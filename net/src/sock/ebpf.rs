use std::{
    ffi::CString,
    io, mem,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    thread,
};

const BPF_MAP_UPDATE_ELEM: libc::c_uint = 2;
const BPF_MAP_DELETE_ELEM: libc::c_uint = 3;
const BPF_OBJ_GET: libc::c_uint = 7;
const BPF_ANY: u64 = 0;
const SO_COOKIE: libc::c_int = 57;
const LOOP_POLL_TIMEOUT_MS: libc::c_int = 100;

#[repr(C)]
struct BpfAttrObj {
    pathname: u64,
    bpf_fd: u32,
    file_flags: u32,
}

#[repr(C)]
struct BpfAttrMapElem {
    map_fd: u32,
    pad: u32,
    key: u64,
    value: u64,
    flags: u64,
}

struct Endpoint {
    map_fd: OwnedFd,
}

impl Endpoint {
    fn from_env() -> io::Result<Self> {
        let path = std::env::var("LURE_EBPF_SOCKHASH")
            .ok()
            .or_else(|| std::env::var("NET_EBPF_SOCKHASH").ok())
            .unwrap_or_else(|| "/sys/fs/bpf/lure/sockhash".to_string());
        let map_fd = open_pinned_map(&path)?;
        Ok(Self { map_fd })
    }

    fn offload_pair_and_wait(
        &self,
        fd_a: RawFd,
        fd_b: RawFd,
        progress: Option<&EbpfProgress>,
    ) -> io::Result<()> {
        let key_a = socket_cookie(fd_a)?;
        let key_b = socket_cookie(fd_b)?;
        let _guard = PairGuard::new(self.map_fd.as_raw_fd(), key_a, key_b, fd_a, fd_b)?;
        wait_for_disconnect_bpf_loop(fd_a, fd_b, progress)
    }
}

struct PairGuard {
    map_fd: RawFd,
    key_a: u64,
    key_b: u64,
}

impl PairGuard {
    fn new(map_fd: RawFd, key_a: u64, key_b: u64, fd_a: RawFd, fd_b: RawFd) -> io::Result<Self> {
        map_update_sockfd(map_fd, &key_a, fd_b)?;
        if let Err(err) = map_update_sockfd(map_fd, &key_b, fd_a) {
            let _ = map_delete(map_fd, &key_a);
            return Err(err);
        }
        Ok(Self {
            map_fd,
            key_a,
            key_b,
        })
    }
}

impl Drop for PairGuard {
    fn drop(&mut self) {
        let _ = map_delete(self.map_fd, &self.key_a);
        let _ = map_delete(self.map_fd, &self.key_b);
    }
}

static ENDPOINT: OnceLock<Result<Endpoint, String>> = OnceLock::new();

#[derive(Debug, Default, Clone, Copy)]
pub struct EbpfStats {
    pub loop_polls: u64,
    pub disconnect_events: u64,
}

#[derive(Default)]
pub struct EbpfProgress {
    loop_polls: AtomicU64,
    disconnect_events: AtomicU64,
}

impl EbpfProgress {
    fn inc_loop_poll(&self) {
        self.loop_polls.fetch_add(1, Ordering::Relaxed);
    }

    fn inc_disconnect_event(&self) {
        self.disconnect_events.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> EbpfStats {
        EbpfStats {
            loop_polls: self.loop_polls.load(Ordering::Relaxed),
            disconnect_events: self.disconnect_events.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct EbpfDone {
    pub result: i32,
    pub stats: EbpfStats,
}

#[must_use]
pub fn ebpf_enabled() -> bool {
    std::env::var("LURE_IO_EBPF")
        .ok()
        .or_else(|| std::env::var("NET_IO_EBPF").ok())
        .is_some_and(|value| value == "1")
}

pub fn offload_pair_and_wait(fd_a: RawFd, fd_b: RawFd) -> io::Result<()> {
    let endpoint = ENDPOINT.get_or_init(|| Endpoint::from_env().map_err(|err| err.to_string()));
    let endpoint = endpoint
        .as_ref()
        .map_err(|err| io::Error::other(err.clone()))?;

    endpoint.offload_pair_and_wait(fd_a, fd_b, None)
}

pub fn spawn_pair_observed(
    fd_a: RawFd,
    fd_b: RawFd,
) -> io::Result<(tokio::sync::oneshot::Receiver<EbpfDone>, Arc<EbpfProgress>)> {
    if !ebpf_enabled() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "eBPF offload is disabled (set LURE_IO_EBPF=1)",
        ));
    }

    let endpoint = ENDPOINT.get_or_init(|| Endpoint::from_env().map_err(|err| err.to_string()));
    let endpoint = endpoint
        .as_ref()
        .map_err(|err| io::Error::other(err.clone()))?;

    let (tx, rx) = tokio::sync::oneshot::channel();
    let progress = Arc::new(EbpfProgress::default());
    let progress_bg = Arc::clone(&progress);
    let map_fd = endpoint.map_fd.as_raw_fd();

    thread::Builder::new()
        .name("lure-ebpf-loop".to_string())
        .spawn(move || {
            let result = run_pair_blocking(map_fd, fd_a, fd_b, &progress_bg);
            let stats = progress_bg.snapshot();
            let _ = tx.send(EbpfDone { result, stats });
            close_fd(fd_a);
            close_fd(fd_b);
        })
        .map_err(io::Error::other)?;
    Ok((rx, progress))
}

fn open_pinned_map(path: &str) -> io::Result<OwnedFd> {
    let path = CString::new(path).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "sockhash path contains interior NUL byte",
        )
    })?;

    let attr = BpfAttrObj {
        pathname: path.as_ptr() as u64,
        bpf_fd: 0,
        file_flags: 0,
    };
    let rc = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_OBJ_GET,
            &raw const attr,
            mem::size_of::<BpfAttrObj>(),
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(rc as RawFd) };
    Ok(fd)
}

fn map_update_sockfd(map_fd: RawFd, key: &u64, sock_fd: RawFd) -> io::Result<()> {
    let mut value = sock_fd as u32;
    let attr = BpfAttrMapElem {
        map_fd: map_fd as u32,
        pad: 0,
        key: key as *const u64 as u64,
        value: (&raw mut value) as u64,
        flags: BPF_ANY,
    };
    bpf_map_elem(BPF_MAP_UPDATE_ELEM, &attr)
}

fn map_delete(map_fd: RawFd, key: &u64) -> io::Result<()> {
    let attr = BpfAttrMapElem {
        map_fd: map_fd as u32,
        pad: 0,
        key: key as *const u64 as u64,
        value: 0,
        flags: 0,
    };
    bpf_map_elem(BPF_MAP_DELETE_ELEM, &attr)
}

fn bpf_map_elem(cmd: libc::c_uint, attr: &BpfAttrMapElem) -> io::Result<()> {
    let rc = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            cmd,
            attr as *const BpfAttrMapElem,
            mem::size_of::<BpfAttrMapElem>(),
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn socket_cookie(fd: RawFd) -> io::Result<u64> {
    let mut cookie: u64 = 0;
    let mut len = mem::size_of::<u64>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            SO_COOKIE,
            (&raw mut cookie).cast::<libc::c_void>(),
            &raw mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(cookie)
}

fn run_pair_blocking(map_fd: RawFd, fd_a: RawFd, fd_b: RawFd, progress: &EbpfProgress) -> i32 {
    match offload_pair_and_wait_with_map(map_fd, fd_a, fd_b, Some(progress)) {
        Ok(()) => 0,
        Err(err) => -errno_from_io_error(&err),
    }
}

fn offload_pair_and_wait_with_map(
    map_fd: RawFd,
    fd_a: RawFd,
    fd_b: RawFd,
    progress: Option<&EbpfProgress>,
) -> io::Result<()> {
    let key_a = socket_cookie(fd_a)?;
    let key_b = socket_cookie(fd_b)?;
    let _guard = PairGuard::new(map_fd, key_a, key_b, fd_a, fd_b)?;
    wait_for_disconnect_bpf_loop(fd_a, fd_b, progress)
}

fn wait_for_disconnect_bpf_loop(
    fd_a: RawFd,
    fd_b: RawFd,
    progress: Option<&EbpfProgress>,
) -> io::Result<()> {
    let mut poll_fds = [
        libc::pollfd {
            fd: fd_a,
            events: libc::POLLERR | libc::POLLHUP | libc::POLLRDHUP,
            revents: 0,
        },
        libc::pollfd {
            fd: fd_b,
            events: libc::POLLERR | libc::POLLHUP | libc::POLLRDHUP,
            revents: 0,
        },
    ];

    loop {
        let rc = unsafe {
            libc::poll(
                poll_fds.as_mut_ptr(),
                poll_fds.len() as libc::nfds_t,
                LOOP_POLL_TIMEOUT_MS,
            )
        };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if let Some(progress) = progress {
            progress.inc_loop_poll();
        }
        if rc == 0 {
            continue;
        }
        for fd in &poll_fds {
            if (fd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLRDHUP)) != 0 {
                if let Some(progress) = progress {
                    progress.inc_disconnect_event();
                }
                return Ok(());
            }
        }
    }
}

fn errno_from_io_error(err: &io::Error) -> i32 {
    err.raw_os_error().unwrap_or(libc::EIO)
}

fn close_fd(fd: RawFd) {
    let _ = unsafe { libc::close(fd) };
}
