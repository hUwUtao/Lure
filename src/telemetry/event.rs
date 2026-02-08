use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use futures::StreamExt;
use log::{error, info};
use reqwest::Client;
use serde::{Serialize, de::DeserializeOwned};
use tokio::{sync::RwLock, time::sleep};

#[async_trait]
pub trait EventHook<In, Out>
where
    In: DeserializeOwned + Send + Sync,
    Out: Serialize + Send + Sync,
{
    /// Handshake are called many times within proxy runtime, and only when client disconnected.
    /// In that case, server will either flush the
    async fn on_handshake(&self) -> Option<Out> {
        None
    }

    async fn on_event(
        &self,
        service: &Arc<EventService<In, Out>>,
        event: &'_ In,
    ) -> anyhow::Result<()>;
}

pub struct EventService<In, Out>
where
    In: DeserializeOwned + Send,
    Out: Serialize + Send,
{
    endpoint: String,
    consumer: RwLock<Vec<Box<dyn EventHook<In, Out> + Send + Sync>>>,
    client: Client,
    retry_interval: Duration,
    _in: std::marker::PhantomData<In>,
    _out: std::marker::PhantomData<Out>,
}

impl<In, Out> EventService<In, Out>
where
    In: DeserializeOwned + Send + Sync + 'static,
    Out: Serialize + Send + Sync + 'static,
{
    #[must_use]
    pub fn new(endpoint: String, retry_interval: Duration) -> Self {
        Self {
            endpoint,
            consumer: RwLock::new(Vec::new()),
            client: Client::new(),
            retry_interval,
            _in: std::marker::PhantomData,
            _out: std::marker::PhantomData,
        }
    }

    pub async fn hook<T>(&self, consumer: T)
    where
        T: EventHook<In, Out> + Send + Sync + 'static,
    {
        let boxed = Box::new(consumer);
        self.consumer.write().await.push(boxed);
    }

    pub fn start(self: Arc<Self>) {
        let this = self;
        tokio::spawn(async move {
            loop {
                if let Err(e) = this.clone().consume_events().await {
                    error!("Error consuming events: {e}");
                } else {
                    error!("Event stream stopped. Retrying...");
                }
                sleep(this.retry_interval).await;
            }
        });
    }

    async fn consume_events(self: Arc<Self>) -> anyhow::Result<()> {
        let response = self.client.get(&self.endpoint).send().await?;
        for consumer in self.consumer.read().await.iter() {
            if let Some(event) = consumer.on_handshake().await {
                self.produce_event(event).await?;
            }
        }
        info!("Hi RPC!");
        let mut buffer = Vec::new();
        let mut stream = response.bytes_stream();
        let consumers = self.consumer.read().await;

        while let Some(chunk) = stream.next().await {
            let bytes = chunk?;
            buffer.extend_from_slice(&bytes);

            let mut start = 0;
            while let Some(end) = buffer[start..].iter().position(|&b| b == b'\n') {
                let line_end = start + end;
                let line = &buffer[start..=line_end];
                start = line_end + 1;

                let text = std::str::from_utf8(line)
                    .map_err(|e| anyhow::anyhow!("Received non-UTF8 data: {e}"))?;

                let trimmed_text = text.trim(); // This also handles empty lines from just `\n`
                if trimmed_text.is_empty() || trimmed_text.len() <= 3 {
                    continue;
                }

                let event: In = serde_json::from_str(trimmed_text).map_err(|e| {
                    anyhow::anyhow!("Failed to deserialize event: `{trimmed_text}`. Error: {e}")
                })?;

                for consumer in consumers.iter() {
                    consumer.on_event(&self, &event).await?;
                }
            }
            buffer.drain(..start); // Remove processed data from buffer
        }
        Ok(())
    }

    pub async fn produce_event(&self, event: Out) -> anyhow::Result<()> {
        let buf = serde_json::to_vec(&event)?;
        self.client
            .post(&self.endpoint)
            .header("Content-Type", "application/json")
            .body(buf)
            .send()
            .await?;
        Ok(())
    }
}

#[allow(dead_code)]
mod test {
    use serde::Deserialize;

    use super::{Arc, Duration, EventHook, EventService, Serialize, async_trait};
    // Example consumer implementation
    struct MyHook;

    #[async_trait]
    impl EventHook<MyEvent, MyEvent> for MyHook {
        async fn on_handshake(&self) -> Option<MyEvent> {
            Some(MyEvent {
                id: 0,
                message: "Never gonna give you up never gonna let you down".to_string(),
            })
        }

        async fn on_event(
            &self,
            _: &Arc<EventService<MyEvent, MyEvent>>,
            event: &MyEvent,
        ) -> anyhow::Result<()> {
            println!("Consumed event: {event:?}");
            Ok(())
        }
    }

    #[derive(Serialize, Deserialize, Debug)]
    struct MyEvent {
        id: u64,
        message: String,
    }

    async fn connect_to_test_endpoint() -> anyhow::Result<()> {
        let service = Arc::new(EventService::<MyEvent, MyEvent>::new(
            "http://localhost:8080/events".to_string(),
            Duration::from_secs(1),
        ));

        service.hook(MyHook).await;
        service.clone().start();

        if let Err(e) = service
            .produce_event(MyEvent {
                id: 1,
                message: "Hello World".to_string(),
            })
            .await
        {
            eprintln!("Failed to produce event: {e}");
        }
        Ok(())
    }
}
