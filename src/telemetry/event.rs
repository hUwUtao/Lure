use async_trait::async_trait;
use futures::StreamExt;
use log::{error, info, log};
use reqwest::Client;
use serde::{de::DeserializeOwned, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::sleep;
use valence::log::tracing_subscriber::Layer;

#[async_trait]
pub trait EventHook<In, Out> {
    /// Handshake are called many times within proxy runtime, and only when client disconnected.
    /// In that case, server will either flush the
    async fn on_handshake(&self) -> Option<Out>;
    async fn on_event(&self, event: &'_ In);
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
        let this = self.clone();
        tokio::spawn(async move {
            loop {
                if let Err(e) = this.consume_events().await {
                    error!("Error consuming events: {}", e);
                    sleep(this.retry_interval).await;
                } else {
                    error!("Event service stopped unexpectedly");
                    sleep(this.retry_interval).await;
                }
            }
        });
    }

    async fn consume_events(&self) -> Result<(), reqwest::Error> {
        let response = self.client.get(&self.endpoint).send().await?;
        for consumer in self.consumer.read().await.iter() {
            if let Some(event) = consumer.on_handshake().await {
                self.produce_event(event).await?;
            }
        }
        info!("Hi RPC!");
        let mut buffer = Vec::new();
        let mut stream = response.bytes_stream();

        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(bytes) => {
                    buffer.extend_from_slice(&bytes);
                    while let Some(pos) = buffer.iter().position(|&b| b == b'\n') {
                        let line = buffer.drain(..=pos).collect::<Vec<u8>>();
                        if let Ok(text) = std::str::from_utf8(&line) {
                            if text.len() < 3 {
                                continue;
                            }
                            if let Ok(event) = serde_json::from_str::<In>(text.trim()) {
                                for consumer in self.consumer.read().await.iter() {
                                    consumer.on_event(&event).await;
                                }
                            } else {
                                error!(
                                    "Failed to deserialize {} byte event: ```{}```",
                                    text.len(),
                                    text
                                );
                            }
                        } else {
                            info!("the fk is this mail")
                        }
                    }
                }
                Err(e) => {
                    error!("Endpoint error: {}", e);
                    break;
                }
            }
        }
        Ok(())
    }

    pub async fn produce_event(&self, event: Out) -> Result<(), reqwest::Error> {
        self.client.post(&self.endpoint).json(&event).send().await?;
        Ok(())
    }
}

mod test {
    use super::*;
    use serde::Deserialize;
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

        async fn on_event(&self, event: &MyEvent) {
            println!("Consumed event: {:?}", event);
        }
    }

    #[derive(Serialize, Deserialize, Debug)]
    struct MyEvent {
        id: u64,
        message: String,
    }

    #[tokio::test]
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
            eprintln!("Failed to produce event: {}", e);
        }
        Ok(())
    }
}
