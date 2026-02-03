use std::{
    collections::HashMap,
    io,
    mem::MaybeUninit,
    net::SocketAddr,
    os::fd::{AsRawFd, RawFd},
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread,
};

use crossbeam_channel::Sender;
use libc::{
    c_int, c_void, close, dup, pipe2, read, sched_param, sched_setscheduler, setpriority, write,
    O_CLOEXEC, O_NONBLOCK, PRIO_PROCESS, SCHED_RR,
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

    pub(crate) fn new(stream: TcpStream, addr: SocketAddr) -> Self {
        Self { stream, addr }
    }

    pub fn as_ref(&self) -> &TcpStream {
        &self.stream
    }

    pub fn as_mut(&mut self) -> &mut TcpStream {
        &mut self.stream
    }

    pub fn addr(&self) -> &SocketAddr {
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
    pending: Arc<Mutex<HashMap<u64, tokio::sync::oneshot::Sender<EpollDone>>>>,
    shutdown: AtomicBool,
}

impl EpollBackend {
    pub fn new(worker_threads: usize, max_conns: usize, buf_cap: usize) -> io::Result<Self> {
        let (done_tx, done_rx) = crossbeam_channel::unbounded::<EpollDone>();
        let pending: Arc<Mutex<HashMap<u64, tokio::sync::oneshot::Sender<EpollDone>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let pending_forward = Arc::clone(&pending);

        thread::Builder::new()
            .name("lure-epoll-done".to_string())
            .spawn(move || {
                while let Ok(done) = done_rx.recv() {
                    if let Some(tx) = pending_forward.lock().unwrap().remove(&done.id) {
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
        })
    }

    pub fn spawn_pair(&self, fd_a: RawFd, fd_b: RawFd) -> io::Result<tokio::sync::oneshot::Receiver<EpollDone>> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.pending.lock().unwrap().insert(id, tx);

        let idx = self.rr.fetch_add(1, Ordering::Relaxed) % self.workers.len();
        let cmd = EpollCmd {
            fd_a: fd_a as c_int,
            fd_b: fd_b as c_int,
            id,
        };

        let rc = unsafe {
            write(
                self.workers[idx].cmd_fd,
                &cmd as *const EpollCmd as *const c_void,
                std::mem::size_of::<EpollCmd>(),
            )
        };

        if rc < 0 {
            let _ = unsafe { close(fd_a) };
            let _ = unsafe { close(fd_b) };
            let _ = self.pending.lock().unwrap().remove(&id);
            return Err(io::Error::last_os_error());
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
        for worker in &self.workers {
            let _ = unsafe {
                write(
                    worker.cmd_fd,
                    &cmd as *const EpollCmd as *const c_void,
                    std::mem::size_of::<EpollCmd>(),
                )
            };
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
            &cpu_set,
        );
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = core_id;
    Ok(())
}

fn run_c_thread(cmd_fd: RawFd, done_fd: RawFd, max_conns: usize, buf_cap: usize, core_id: Option<usize>) {
    // Pin to specific core if requested
    if let Some(core) = core_id {
        if let Err(e) = pin_to_core(core) {
            log::warn!("Failed to pin epoll thread to core {}: {}", core, e);
        } else {
            log::debug!("Pinned epoll thread to core {}", core);
        }
    }

    set_worker_priority();

    let thread = unsafe {
        lure_epoll_thread_new(cmd_fd as c_int, done_fd as c_int, max_conns, buf_cap)
    };
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
    let mut buf: [MaybeUninit<EpollDone>; 32] = unsafe { MaybeUninit::uninit().assume_init() };
    loop {
        let n = unsafe {
            read(
                fd,
                buf.as_mut_ptr() as *mut c_void,
                std::mem::size_of_val(&buf),
            )
        };
        if n <= 0 {
            break;
        }
        let count = n as usize / std::mem::size_of::<EpollDone>();
        for i in 0..count {
            let done = unsafe { buf[i].assume_init() };
            let _ = done_tx.send(done);
        }
    }
    unsafe {
        let _ = close(fd);
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
        let mut param = sched_param { sched_priority: 10 };
        let rc = sched_setscheduler(0, SCHED_RR, &mut param);
        if rc != 0 {
            let _ = setpriority(PRIO_PROCESS, 0, -10);
        }
    }
}

fn set_passthrough_priority() {
    set_worker_priority();
}

pub fn passthrough(fd_a: RawFd, fd_b: RawFd) -> io::Result<EpollStats> {
    set_passthrough_priority();
    let mut stats = EpollStats::default();
    let rc = unsafe { lure_epoll_passthrough(fd_a, fd_b, &mut stats as *mut EpollStats) };
    if rc < 0 {
        return Err(io::Error::from_raw_os_error(-rc));
    }
    if rc > 0 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "epoll passthrough failed",
        ));
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
    tokio::task::spawn_blocking(move || passthrough(fd_a, fd_b))
        .await
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))??;
    Ok(())
}
