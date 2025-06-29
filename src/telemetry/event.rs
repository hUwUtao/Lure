use async_trait::async_trait;
use futures::StreamExt;
use log::error;
use reqwest::Client;
use serde::{de::DeserializeOwned, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::sleep;
use valence::log::tracing_subscriber::Layer;

#[async_trait]
pub trait Consume<T> {
    async fn on_event(&self, event: &'_ T);
}

pub struct EventService<In, Out>
where
    In: DeserializeOwned + Send,
    Out: Serialize + Send,
{
    endpoint: String,
    consumer: RwLock<Vec<Box<dyn Consume<In> + Send + Sync>>>,
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
        T: Consume<In> + Send + Sync + 'static,
    {
        let boxed = Box::new(consumer);
        self.consumer.write().await.push(boxed);
    }

    pub async fn start(self: Arc<Self>) {
        let this = self.clone();
        tokio::spawn(async move {
            loop {
                if let Err(e) = this.consume_events().await {
                    eprintln!("Error consuming events: {}", e);
                    sleep(this.retry_interval).await;
                }
            }
        });
    }

    async fn consume_events(&self) -> Result<(), reqwest::Error> {
        let response = self.client.get(&self.endpoint).send().await?;
        let mut buffer = Vec::new();
        let mut stream = response.bytes_stream();

        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(bytes) => {
                    buffer.extend_from_slice(&bytes);
                    while let Some(pos) = buffer.iter().position(|&b| b == b'\n') {
                        let line = buffer.drain(..=pos + 1).collect::<Vec<u8>>();
                        if let Ok(text) = std::str::from_utf8(&line) {
                            if let Ok(event) = serde_json::from_str::<In>(text.trim()) {
                                for consumer in self.consumer.read().await.iter() {
                                    consumer.on_event(&event).await;
                                }
                            } else {
                                error!("Failed to deserialize event: {}", text);
                            }
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
    struct MyConsumer;

    #[async_trait]
    impl Consume<MyEvent> for MyConsumer {
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
            Duration::from_secs(5),
        ));

        service.hook(MyConsumer).await;
        service.clone().start().await;

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
