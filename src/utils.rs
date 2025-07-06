// use std::{fs, path::PathBuf};
//
// use base64::{engine::general_purpose, Engine};
//
// pub fn read_favicon(path: String) -> Option<String> {
//     let favicon_file = PathBuf::from(path);
//
//     if !favicon_file.exists() {
//         println!("doesnt exist {:?}", favicon_file.as_os_str().to_str());
//         return None;
//     }
//
//     match fs::read(favicon_file) {
//         Ok(favicon) => {
//             let favicon_meta = image_meta::load_from_buf(&favicon).ok()?;
//             if favicon_meta.dimensions.width != 64 || favicon_meta.dimensions.height != 64 {
//                 return None;
//             };
//
//             let mut buf = "data:image/png;base64,".to_string();
//             general_purpose::STANDARD.encode_string(favicon, &mut buf);
//
//             Some(buf)
//         }
//         Err(_) => None,
//     }
// }

use crate::router::RouterInstance;
use crate::telemetry::{EventEnvelope, EventServiceInstance};
use async_trait::async_trait;
use std::sync::Arc;

pub struct OwnedArc<T>(Arc<T>);

impl<T> From<Arc<T>> for OwnedArc<T> {
    fn from(arc: Arc<T>) -> Self {
        OwnedArc(arc)
    }
}

#[async_trait]
impl crate::telemetry::event::EventHook<EventEnvelope, EventEnvelope> for OwnedArc<RouterInstance> {
    async fn on_handshake(&self) -> Option<EventEnvelope> {
        self.0.on_handshake().await
    }

    async fn on_event(
        &self,
        inst: &EventServiceInstance,
        event: &'_ EventEnvelope,
    ) -> anyhow::Result<()> {
        self.0.on_event(inst, event).await?;
        Ok(())
    }
}
