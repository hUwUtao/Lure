use std::cell::UnsafeCell;

use async_trait::async_trait;

use crate::telemetry::{EventEnvelope, EventServiceInstance, event::EventHook};

#[cfg(feature = "mimalloc")]
mod mimalloc {
    use mimalloc::MiMalloc;

    #[global_allocator]
    static GLOBAL: MiMalloc = MiMalloc;
}

pub struct OwnedStatic<T: 'static>(&'static T);

impl<T> From<&'static T> for OwnedStatic<T> {
    fn from(value: &'static T) -> Self {
        Self(value)
    }
}

#[async_trait]
impl<H: EventHook<EventEnvelope, EventEnvelope> + Send + Sync>
    EventHook<EventEnvelope, EventEnvelope> for OwnedStatic<H>
{
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

pub fn leak<T>(inner: T) -> &'static T {
    Box::leak(Box::new(inner))
}

pub fn spawn_named<F>(
    name: &str,
    future: F,
) -> Result<tokio::task::JoinHandle<F::Output>, std::io::Error>
where
    F: Future + 'static,
    F::Output: 'static,
{
    tokio::task::Builder::new().name(name).spawn_local(future)
}

#[derive(Default, Debug)]
/// Warning: This implementation only assumes that single sync-inc
pub struct UnsafeCounterU64 {
    v: UnsafeCell<u64>,
}

// single-writer, multi-reader-by-convention
unsafe impl Sync for UnsafeCounterU64 {}

impl UnsafeCounterU64 {
    pub fn inc(&self, rhs: u64) {
        unsafe {
            *self.v.get() += rhs;
        }
    }

    pub fn add(&self, rhs: u64) -> u64 {
        unsafe {
            let old = *self.v.get();
            *self.v.get() = old.wrapping_add(rhs);
            old
        }
    }

    pub fn sub(&self, rhs: u64) -> u64 {
        unsafe {
            let old = *self.v.get();
            *self.v.get() = old.wrapping_sub(rhs);
            old
        }
    }

    pub fn store(&self, value: u64) {
        unsafe {
            *self.v.get() = value;
        }
    }

    pub fn swap(&self, value: u64) -> u64 {
        unsafe {
            let old = *self.v.get();
            *self.v.get() = value;
            old
        }
    }

    pub fn load(&self) -> u64 {
        unsafe { *self.v.get() }
    }
}
