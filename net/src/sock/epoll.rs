use std::{
    io,
    net::SocketAddr,
    os::fd::{AsRawFd, RawFd},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    thread,
};

use crossbeam_channel::Sender;
use dashmap::DashMap;
use libc::{
    O_CLOEXEC, O_NONBLOCK, PRIO_PROCESS, c_int, c_void, close, dup, pipe2, read, setpriority, write,
};
use tokio::net::{TcpListener, TcpStream};

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct EpollStats {
    pub c2s_bytes: u64,
    pub s2c_bytes: u64,
    pub c2s_chunks: u64,
    pub s2c_chunks: u64,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct EpollCmd {
    fd_a: c_int,
    fd_b: c_int,
    id: u64,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct EpollDone {
    pub id: u64,
    pub stats: EpollStats,
    pub result: c_int,
}

#[repr(C)]
struct LureEpollThread {
    _private: [u8; 0],
}

unsafe extern "C" {
    fn lure_epoll_thread_new(
        cmd_fd: c_int,
        done_fd: c_int,
        max_conns: usize,
        buf_cap: usize,
    ) -> *mut LureEpollThread;
    fn lure_epoll_thread_run(thread: *mut LureEpollThread) -> c_int;
    fn lure_epoll_thread_free(thread: *mut LureEpollThread);
    fn lure_epoll_passthrough(fd_a: c_int, fd_b: c_int, stats: *mut EpollStats) -> c_int;
}

#[derive(Debug)]
pub struct Listener {
    inner: TcpListener,
}

impl Listener {
    pub(crate) async fn bind(addr: SocketAddr) -> io::Result<Self> {
        let inner = TcpListener::bind(addr).await?;
        Ok(Self { inner })
    }

    pub(crate) async fn accept(&self) -> io::Result<(Connection, SocketAddr)> {
        let (stream, addr) = self.inner.accept().await?;
        Ok((Connection::new(stream, addr), addr))
    }

    pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

pub struct Connection {
    stream: TcpStream,
    addr: SocketAddr,
}

impl Connection {
    pub(crate) async fn connect(addr: SocketAddr) -> io::Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        let addr = stream.peer_addr()?;
        Ok(Self { stream, addr })
    }

    pub(crate) const fn new(stream: TcpStream, addr: SocketAddr) -> Self {
        Self { stream, addr }
    }

    pub const fn as_ref(&self) -> &TcpStream {
        &self.stream
    }

    pub const fn as_mut(&mut self) -> &mut TcpStream {
        &mut self.stream
    }

    pub const fn addr(&self) -> &SocketAddr {
        &self.addr
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.stream.peer_addr()
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.stream.local_addr()
    }

    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        self.stream.set_nodelay(nodelay)
    }

    pub(crate) async fn read_chunk(&mut self, mut buf: Vec<u8>) -> io::Result<(usize, Vec<u8>)> {
        use tokio::io::AsyncReadExt;
        let n = self.stream.read(buf.as_mut_slice()).await?;
        Ok((n, buf))
    }

    pub(crate) async fn write_all(&mut self, buf: Vec<u8>) -> io::Result<Vec<u8>> {
        use tokio::io::AsyncWriteExt;
        self.stream.write_all(buf.as_slice()).await?;
        Ok(buf)
    }

    pub(crate) async fn flush(&mut self) -> io::Result<()> {
        use tokio::io::AsyncWriteExt;
        self.stream.flush().await
    }

    pub(crate) fn try_read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.try_read(buf)
    }

    pub(crate) async fn shutdown(&mut self) -> io::Result<()> {
        use tokio::io::AsyncWriteExt;
        self.stream.shutdown().await
    }
}

struct WorkerHandle {
    cmd_fd: RawFd,
    join: thread::JoinHandle<()>,
    done_join: thread::JoinHandle<()>,
}

pub struct EpollBackend {
    workers: Vec<WorkerHandle>,
    rr: AtomicUsize,
    next_id: AtomicU64,
    pending: Arc<DashMap<u64, tokio::sync::oneshot::Sender<EpollDone>>>,
    shutdown: AtomicBool,
    done_forward_handle: Option<thread::JoinHandle<()>>,
}

impl EpollBackend {
    pub fn new(worker_threads: usize, max_conns: usize, buf_cap: usize) -> io::Result<Self> {
        let (done_tx, done_rx) = crossbeam_channel::unbounded::<EpollDone>();
        let pending: Arc<DashMap<u64, tokio::sync::oneshot::Sender<EpollDone>>> =
            Arc::new(DashMap::new());
        let pending_forward = Arc::clone(&pending);

        let done_forward_handle = thread::Builder::new()
            .name("lure-epoll-done".to_string())
            .spawn(move || {
                while let Ok(done) = done_rx.recv() {
                    if let Some((_, tx)) = pending_forward.remove(&done.id) {
                        let _ = tx.send(done);
                    }
                }
            })?;

        let mut workers = Vec::with_capacity(worker_threads.max(1));
        for index in 0..worker_threads.max(1) {
            let (cmd_read, cmd_write) = make_pipe()?;
            let (done_read, done_write) = make_pipe()?;

            let done_tx = done_tx.clone();
            let done_join = thread::Builder::new()
                .name(format!("lure-epoll-done-{index}"))
                .spawn(move || forward_done(done_read, done_tx))?;

            let join = thread::Builder::new()
                .name(format!("lure-epoll-{index}"))
                .spawn(move || {
                    // Pin to core only if we have enough cores
                    let core_id = if worker_threads <= num_cpus::get() {
                        Some(index)
                    } else {
                        None
                    };
                    run_c_thread(cmd_read, done_write, max_conns, buf_cap, core_id);
                })?;

            workers.push(WorkerHandle {
                cmd_fd: cmd_write,
                join,
                done_join,
            });
        }

        Ok(Self {
            workers,
            rr: AtomicUsize::new(0),
            next_id: AtomicU64::new(1),
            pending,
            shutdown: AtomicBool::new(false),
            done_forward_handle: Some(done_forward_handle),
        })
    }

    pub fn spawn_pair(
        &self,
        fd_a: RawFd,
        fd_b: RawFd,
    ) -> io::Result<tokio::sync::oneshot::Receiver<EpollDone>> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.pending.insert(id, tx);

        let idx = self.rr.fetch_add(1, Ordering::Relaxed) % self.workers.len();
        let cmd = EpollCmd {
            fd_a: fd_a as c_int,
            fd_b: fd_b as c_int,
            id,
        };

        let cmd_bytes = unsafe {
            std::slice::from_raw_parts(
                (&raw const cmd).cast::<u8>(),
                std::mem::size_of::<EpollCmd>(),
            )
        };
        let mut bytes_written = 0;
        let mut backoff_ms = 1u64;

        loop {
            let rc = unsafe {
                write(
                    self.workers[idx].cmd_fd,
                    cmd_bytes[bytes_written..].as_ptr().cast::<c_void>(),
                    cmd_bytes.len() - bytes_written,
                )
            };

            if rc < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    // Exponential backoff: retry indefinitely with growing sleep duration
                    thread::sleep(std::time::Duration::from_millis(backoff_ms));
                    backoff_ms = (backoff_ms * 2).min(10); // Cap at 10ms instead of 100ms
                    continue;
                }
                let _ = unsafe { close(fd_a) };
                let _ = unsafe { close(fd_b) };
                let _ = self.pending.remove(&id);
                return Err(err);
            }

            bytes_written += rc as usize;
            if bytes_written >= cmd_bytes.len() {
                break;
            }
            backoff_ms = 1; // Reset backoff on successful partial write
        }

        Ok(rx)
    }

    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
        let cmd = EpollCmd {
            fd_a: -1,
            fd_b: -1,
            id: 0,
        };
        let cmd_bytes = unsafe {
            std::slice::from_raw_parts(
                (&raw const cmd).cast::<u8>(),
                std::mem::size_of::<EpollCmd>(),
            )
        };
        for worker in &self.workers {
            let mut bytes_written = 0;
            let mut backoff_ms = 1u64;

            loop {
                let rc = unsafe {
                    write(
                        worker.cmd_fd,
                        cmd_bytes[bytes_written..].as_ptr().cast::<c_void>(),
                        cmd_bytes.len() - bytes_written,
                    )
                };

                if rc < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.kind() == std::io::ErrorKind::WouldBlock {
                        // Exponential backoff: retry indefinitely with growing sleep duration
                        thread::sleep(std::time::Duration::from_millis(backoff_ms));
                        backoff_ms = (backoff_ms * 2).min(10); // Cap at 10ms instead of 100ms
                        continue;
                    }
                    break;
                }

                bytes_written += rc as usize;
                if bytes_written >= cmd_bytes.len() {
                    break;
                }
                backoff_ms = 1; // Reset backoff on successful partial write
            }
        }
    }
}

impl Drop for EpollBackend {
    fn drop(&mut self) {
        self.shutdown();
        for worker in &self.workers {
            unsafe {
                let _ = close(worker.cmd_fd);
            }
        }
        // Give threads time to exit gracefully (1 second timeout per thread)
        for worker in self.workers.drain(..) {
            let _ = worker.join.join();
            let _ = worker.done_join.join();
        }
        // Join the main done_forward handler thread
        if let Some(handle) = self.done_forward_handle.take()
            && let Err(e) = handle.join()
        {
            log::warn!("done_forward_handle join failed: {e:?}");
        }
    }
}

fn pin_to_core(core_id: usize) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    unsafe {
        let mut cpu_set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut cpu_set);
        libc::CPU_SET(core_id, &mut cpu_set);
        let result = libc::sched_setaffinity(
            0,
            std::mem::size_of::<libc::cpu_set_t>(),
            &raw const cpu_set,
        );
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = core_id;
    Ok(())
}

fn run_c_thread(
    cmd_fd: RawFd,
    done_fd: RawFd,
    max_conns: usize,
    buf_cap: usize,
    core_id: Option<usize>,
) {
    // Pin to specific core if requested
    if let Some(core) = core_id {
        if let Err(e) = pin_to_core(core) {
            log::warn!("Failed to pin epoll thread to core {core}: {e}");
        } else {
            log::debug!("Pinned epoll thread to core {core}");
        }
    }

    set_worker_priority();

    let thread =
        unsafe { lure_epoll_thread_new(cmd_fd as c_int, done_fd as c_int, max_conns, buf_cap) };
    if thread.is_null() {
        unsafe {
            let _ = close(cmd_fd);
            let _ = close(done_fd);
        }
        return;
    }

    let _ = unsafe { lure_epoll_thread_run(thread) };

    unsafe {
        lure_epoll_thread_free(thread);
        let _ = close(cmd_fd);
        let _ = close(done_fd);
    }
}

fn forward_done(fd: RawFd, done_tx: Sender<EpollDone>) {
    // Create dedicated epoll instance for done pipe to avoid polling
    let epoll_fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    if epoll_fd < 0 {
        unsafe { libc::close(fd) };
        return;
    }

    // Register done_read fd for EPOLLIN events
    let mut ev = libc::epoll_event {
        events: (libc::EPOLLIN | libc::EPOLLERR | libc::EPOLLHUP) as u32,
        u64: 0,
    };
    if unsafe { libc::epoll_ctl(epoll_fd, libc::EPOLL_CTL_ADD, fd, &raw mut ev) } < 0 {
        unsafe {
            libc::close(epoll_fd);
            libc::close(fd);
        }
        return;
    }

    let mut events = [libc::epoll_event { events: 0, u64: 0 }; 1];
    let frame_size = std::mem::size_of::<EpollDone>();
    let mut frame_buf: Vec<u8> = Vec::with_capacity(frame_size);

    loop {
        // Wait for events with 100ms timeout for clean shutdown
        let n = unsafe { libc::epoll_wait(epoll_fd, events.as_mut_ptr(), 1, 100) };

        if n < 0 {
            if unsafe { *libc::__errno_location() } == libc::EINTR {
                continue;
            }
            break;
        }

        if n == 0 {
            // Timeout - loop back to check for more events
            continue;
        }

        // Data available - read frame-aligned notifications
        loop {
            // Read frame-sized chunks to minimize syscalls
            while frame_buf.len() < frame_size {
                let remaining = frame_size - frame_buf.len();
                let mut read_buf = vec![0u8; remaining];
                let bytes = unsafe { read(fd, read_buf.as_mut_ptr().cast::<c_void>(), remaining) };

                if bytes == 0 {
                    // EOF
                    unsafe {
                        libc::close(epoll_fd);
                        libc::close(fd);
                    }
                    return;
                } else if bytes < 0 {
                    let errno = unsafe { *libc::__errno_location() };
                    if errno == libc::EINTR {
                        continue; // Retry on EINTR
                    }
                    if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
                        // No more data available
                        break;
                    }
                    // Fatal error
                    unsafe {
                        libc::close(epoll_fd);
                        libc::close(fd);
                    }
                    return;
                }
                frame_buf.extend_from_slice(&read_buf[..bytes as usize]);
            }

            // If we have a complete frame, decode and send it
            if frame_buf.len() == frame_size {
                let mut frame_data = [0u8; std::mem::size_of::<EpollDone>()];
                frame_data.copy_from_slice(&frame_buf);
                let done =
                    unsafe { std::ptr::read_unaligned(frame_data.as_ptr().cast::<EpollDone>()) };
                let _ = done_tx.send(done);
                frame_buf.clear();
            } else {
                // Need more data from epoll_wait
                break;
            }
        }
    }

    unsafe {
        libc::close(epoll_fd);
        libc::close(fd);
    }
}

fn make_pipe() -> io::Result<(RawFd, RawFd)> {
    let mut fds = [0; 2];
    let rc = unsafe { pipe2(fds.as_mut_ptr(), O_NONBLOCK | O_CLOEXEC) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((fds[0], fds[1]))
}

fn set_worker_priority() {
    unsafe {
        // Use SCHED_OTHER (normal scheduling) with high nice priority for low-latency
        // This allows the kernel to idle the core when epoll_wait blocks, avoiding
        // CPU saturation while maintaining responsive wakeups
        let _ = setpriority(PRIO_PROCESS, 0, -15);
    }
}

fn set_passthrough_priority() {
    set_worker_priority();
}

pub fn passthrough(fd_a: RawFd, fd_b: RawFd) -> io::Result<EpollStats> {
    set_passthrough_priority();
    let mut stats = EpollStats::default();
    let rc = unsafe { lure_epoll_passthrough(fd_a, fd_b, &raw mut stats) };
    if rc < 0 {
        return Err(io::Error::from_raw_os_error(-rc));
    }
    if rc > 0 {
        return Err(io::Error::other("epoll passthrough failed"));
    }
    Ok(stats)
}

pub fn duplicate_fd(fd: RawFd) -> io::Result<RawFd> {
    let rc = unsafe { dup(fd) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(rc)
}

pub(crate) fn probe() -> io::Result<()> {
    if cfg!(target_os = "linux") {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "epoll backend is linux-only",
        ))
    }
}

pub async fn passthrough_basic(a: &mut Connection, b: &mut Connection) -> io::Result<()> {
    let fd_a = duplicate_fd(a.as_ref().as_raw_fd())?;
    let fd_b = duplicate_fd(b.as_ref().as_raw_fd())?;
    tokio::task::spawn_blocking(move || {
        let res = passthrough(fd_a, fd_b);
        // Close the duplicated FDs after passthrough completes
        let _ = unsafe { close(fd_a) };
        let _ = unsafe { close(fd_b) };
        res
    })
    .await
    .map_err(|err| io::Error::other(err.to_string()))??;
    Ok(())
}
