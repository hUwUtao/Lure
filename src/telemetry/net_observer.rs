use std::{
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub struct MonitoredStream<T, F>
where
    T: AsyncRead + AsyncWrite,
    F: Fn(u64) + Send + 'static + Unpin,
{
    stream: T,
    callback: F,
}

impl<T, F> MonitoredStream<T, F>
where
    T: AsyncRead + AsyncWrite,
    F: Fn(u64) + Send + 'static + Unpin,
{
    pub fn new(stream: T, callback: F) -> Self {
        Self { stream, callback }
    }
}

impl<T, F> AsyncRead for MonitoredStream<T, F>
where
    T: AsyncRead + AsyncWrite + Unpin,
    F: Fn(u64) + Send + 'static + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.stream).poll_read(cx, buf)
    }
}

impl<T, F> AsyncWrite for MonitoredStream<T, F>
where
    T: AsyncRead + AsyncWrite + Unpin,
    F: Fn(u64) + Send + 'static + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.stream).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => {
                (this.callback)(n as u64);
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.stream).poll_shutdown(cx)
    }
}
