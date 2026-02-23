use anyhow::Result;
use log::{error, info};
use std::sync::Arc;
use tokio::sync::mpsc;
use tonic::transport::Channel;

// Import generated proto types
use crate::generated::lure::v1::{
	control_message, lure_message, ControlMessage, HandshakeIdent, LureMessage,
};
use crate::generated::lure::v1::lure_control_client::LureControlClient;

/// RPC Client for bidirectional gRPC communication with Luru
/// Replaces the old SSE EventService system
pub struct LureRpcClient {
	endpoint: String,
	instance_id: String,
	group: String,
}

impl LureRpcClient {
	pub fn new(endpoint: String, instance_id: String, group: String) -> Self {
		Self {
			endpoint,
			instance_id,
			group,
		}
	}

	/// Connect to Luru RPC service and start bidirectional stream
	/// Spawns background tasks for:
	/// - Receiving control messages from Luru
	/// - Sending telemetry to Luru
	pub async fn connect(
		self: Arc<Self>,
	) -> Result<(mpsc::Receiver<ControlMessage>, mpsc::Sender<LureMessage>)> {
		let (tx_control, rx_control) = mpsc::channel(100);
		let (tx_telemetry, mut rx_telemetry) = mpsc::channel(100);

		let client_clone = Arc::clone(&self);
		tokio::spawn(async move {
			if let Err(e) = client_clone.run_stream(tx_control, rx_telemetry).await {
				error!("🔌 RPC stream error: {}", e);
			}
		});

		Ok((rx_control, tx_telemetry))
	}

	/// Main RPC stream loop
	/// - Connect to Luru via tonic
	/// - Send handshake
	/// - Receive control messages and push to tx_control
	/// - Receive telemetry messages from rx_telemetry and send to Luru
	async fn run_stream(
		&self,
		tx_control: mpsc::Sender<ControlMessage>,
		mut rx_telemetry: mpsc::Receiver<LureMessage>,
	) -> Result<()> {
		// Connect to Luru RPC service
		let channel = Channel::from_shared(self.endpoint.clone())?
			.connect()
			.await?;
		let mut client = LureControlClient::new(channel);

		info!("🔌 RPC: Connected to Luru at {}", self.endpoint);

		// Create the bidirectional stream
		let (tx_rpc, rx_rpc) = tokio::sync::mpsc::channel(100);
		let rx_stream = tokio_stream::wrappers::ReceiverStream::new(rx_rpc);

		// Send handshake
		let handshake = LureMessage {
			payload: Some(lure_message::Payload::Handshake(HandshakeIdent {
				instance_id: self.instance_id.clone(),
				group: self.group.clone(),
			})),
		};
		tx_rpc.send(handshake).await?;
		info!(
			"🔌 RPC: Sent handshake - instance: {}, group: {}",
			self.instance_id, self.group
		);

		// Start the bidirectional stream
		let response = client.connect(rx_stream).await?;
		let mut response_stream = response.into_inner();

		// Spawn telemetry sender task
		let tx_rpc_clone = tx_rpc.clone();
		tokio::spawn(async move {
			while let Some(msg) = rx_telemetry.recv().await {
				if let Err(e) = tx_rpc_clone.send(msg).await {
					error!("RPC: Failed to send telemetry: {}", e);
					break;
				}
			}
		});

		// Receive control messages from Luru
		while let Ok(Some(msg)) = response_stream.message().await {
			match &msg.payload {
				Some(control_message::Payload::Hello(_)) => {
					info!("🔌 RPC: Received Hello from Luru");
				}
				Some(control_message::Payload::SetRoute(route)) => {
					info!("🔌 RPC: Received SetRoute: id={}", route.id);
					// Push to control channel for router to process
					if let Err(e) = tx_control.send(msg).await {
						error!("RPC: Failed to push SetRoute to control: {}", e);
						break;
					}
				}
				Some(control_message::Payload::RemoveRoute(remove)) => {
					info!("🔌 RPC: Received RemoveRoute: id={}", remove.id);
					if let Err(e) = tx_control.send(msg).await {
						error!("RPC: Failed to push RemoveRoute to control: {}", e);
						break;
					}
				}
				Some(control_message::Payload::FlushRoutes(_)) => {
					info!("🔌 RPC: Received FlushRoutes");
					if let Err(e) = tx_control.send(msg).await {
						error!("RPC: Failed to push FlushRoutes to control: {}", e);
						break;
					}
				}
				Some(control_message::Payload::SetTunnelToken(token)) => {
					info!("🔌 RPC: Received SetTunnelToken: key_id={}", token.key_id);
					if let Err(e) = tx_control.send(msg).await {
						error!("RPC: Failed to push SetTunnelToken to control: {}", e);
						break;
					}
				}
				Some(control_message::Payload::FlushTunnelTokens(_)) => {
					info!("🔌 RPC: Received FlushTunnelTokens");
					if let Err(e) = tx_control.send(msg).await {
						error!("RPC: Failed to push FlushTunnelTokens to control: {}", e);
						break;
					}
				}
				_ => {
					error!("🔌 RPC: Unknown control message");
				}
			}
		}

		info!("🔌 RPC: Stream closed");
		Ok(())
	}
}
