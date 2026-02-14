use std::{
    ffi::CString,
    fs, io, mem,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    net::SocketAddr,
    path::{Path, PathBuf},
    process::Command,
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
const LOOP_POLL_TIMEOUT_MS: libc::c_int = 100;
const MAP_UPDATE_RETRIES: usize = 4000;
const MAP_UPDATE_RETRY_DELAY_US: u64 = 1000;
const DEFAULT_PIN_DIR: &str = "/sys/fs/bpf";
const DEFAULT_MAP_NAME: &str = "lure_sockhash";
const DEFAULT_VERDICT_PROG_NAME: &str = "lure_stream_verdict";
const DEFAULT_PARSER_PROG_NAME: &str = "lure_stream_parser";
const LEGACY_MAP_NAME: &str = "sockhash";
const KERNEL_OBJ: &[u8] = include_bytes!(env!("LURE_EBPF_OBJ"));

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

#[repr(C)]
#[derive(Clone, Copy)]
struct SockKeyV4 {
    sip4: u32,
    dip4: u32,
    sport: u32,
    dport: u32,
}

struct Endpoint {
    map_fd: OwnedFd,
}

impl Endpoint {
    fn from_env() -> io::Result<Self> {
        if let Some(path) = std::env::var("LURE_EBPF_SOCKHASH")
            .ok()
            .or_else(|| std::env::var("NET_EBPF_SOCKHASH").ok())
        {
            let map_fd = open_or_bootstrap_map(Path::new(&path))?;
            return Ok(Self { map_fd });
        }

        // Default to the new pinned map name, then fall back to legacy name.
        let preferred = Path::new(DEFAULT_PIN_DIR).join(DEFAULT_MAP_NAME);
        let preferred_err = match open_or_bootstrap_map(&preferred) {
            Ok(map_fd) => return Ok(Self { map_fd }),
            Err(err) => {
                log::warn!("eBPF preferred map path failed ({}): {err}", preferred.display());
                err
            }
        };

        let legacy = Path::new(DEFAULT_PIN_DIR).join(LEGACY_MAP_NAME);
        match open_or_bootstrap_map(&legacy) {
            Ok(map_fd) => Ok(Self { map_fd }),
            Err(err) => {
                log::warn!("eBPF legacy map path failed ({}): {err}", legacy.display());
                Err(preferred_err)
            }
        }
    }

    fn offload_pair_and_wait(
        &self,
        fd_a: RawFd,
        fd_b: RawFd,
        progress: Option<&EbpfProgress>,
    ) -> io::Result<()> {
        let key_a = socket_key_v4(fd_a)?;
        let key_b = socket_key_v4(fd_b)?;
        let _guard = PairGuard::new(self.map_fd.as_raw_fd(), key_a, key_b, fd_a, fd_b)?;
        EbpfLoopContext::new(fd_a, fd_b).run_loop(progress)
    }
}

struct PairGuard {
    map_fd: RawFd,
    key_a: SockKeyV4,
    key_b: SockKeyV4,
}

impl PairGuard {
    fn new(
        map_fd: RawFd,
        key_a: SockKeyV4,
        key_b: SockKeyV4,
        fd_a: RawFd,
        fd_b: RawFd,
    ) -> io::Result<Self> {
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
    pub poll_wakeups: u64,
    pub poll_timeouts: u64,
    pub poll_errors: u64,
    pub disconnect_events: u64,
}

#[derive(Default)]
pub struct EbpfProgress {
    loop_polls: AtomicU64,
    poll_wakeups: AtomicU64,
    poll_timeouts: AtomicU64,
    poll_errors: AtomicU64,
    disconnect_events: AtomicU64,
}

impl EbpfProgress {
    fn inc_loop_poll(&self) {
        self.loop_polls.fetch_add(1, Ordering::Relaxed);
    }

    fn inc_poll_wakeup(&self) {
        self.poll_wakeups.fetch_add(1, Ordering::Relaxed);
    }

    fn inc_poll_timeout(&self) {
        self.poll_timeouts.fetch_add(1, Ordering::Relaxed);
    }

    fn inc_poll_error(&self) {
        self.poll_errors.fetch_add(1, Ordering::Relaxed);
    }

    fn inc_disconnect_event(&self) {
        self.disconnect_events.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> EbpfStats {
        EbpfStats {
            loop_polls: self.loop_polls.load(Ordering::Relaxed),
            poll_wakeups: self.poll_wakeups.load(Ordering::Relaxed),
            poll_timeouts: self.poll_timeouts.load(Ordering::Relaxed),
            poll_errors: self.poll_errors.load(Ordering::Relaxed),
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

fn open_pinned_map(path: &Path) -> io::Result<OwnedFd> {
    let text = path
        .to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "non-utf8 map path"))?;
    open_pinned_map_str(text)
}

fn open_pinned_map_str(path: &str) -> io::Result<OwnedFd> {
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

fn open_or_bootstrap_map(path: &Path) -> io::Result<OwnedFd> {
    match open_pinned_map(path) {
        Ok(fd) => Ok(fd),
        Err(first_err) => {
            if !ebpf_enabled() {
                return Err(first_err);
            }
            bootstrap_kernel_program(path)?;
            open_pinned_map(path)
        }
    }
}

fn bootstrap_kernel_program(map_path: &Path) -> io::Result<()> {
    let pin_dir = map_path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "map path has no parent"))?;
    fs::create_dir_all(pin_dir)?;

    let obj_path = PathBuf::from("/tmp/lure_sockhash_kern.o");
    fs::write(&obj_path, KERNEL_OBJ)?;

    let parser_prog_path = pin_dir.join(DEFAULT_PARSER_PROG_NAME);
    let verdict_prog_path = pin_dir.join(DEFAULT_VERDICT_PROG_NAME);
    let default_map_path = pin_dir.join(DEFAULT_MAP_NAME);
    cleanup_pinned_lure_artifacts(pin_dir)?;
    let load_status = run_bpftool([
        "prog",
        "loadall",
        obj_path.to_str().unwrap_or("/tmp/lure_sockhash_kern.o"),
        pin_dir
            .to_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "non-utf8 pin dir"))?,
        "type",
        "sk_skb",
        "pinmaps",
        pin_dir
            .to_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "non-utf8 pin dir"))?,
    ])?;
    if !load_status.success() {
        // Retry once after cleanup in case stale pinned map/program files raced us.
        cleanup_pinned_lure_artifacts(pin_dir)?;
        let retry = run_bpftool([
            "prog",
            "loadall",
            obj_path.to_str().unwrap_or("/tmp/lure_sockhash_kern.o"),
            pin_dir
                .to_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "non-utf8 pin dir"))?,
            "type",
            "sk_skb",
            "pinmaps",
            pin_dir
                .to_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "non-utf8 pin dir"))?,
        ])?;
        if !retry.success() {
            return Err(io::Error::other("bpftool prog load failed"));
        }
    }

    if map_path != default_map_path.as_path() {
        let pin_map_status = run_bpftool([
            "map",
            "pin",
            "pinned",
            default_map_path.to_str().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "non-utf8 default map path")
            })?,
            map_path
                .to_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "non-utf8 map path"))?,
        ])?;
        if !pin_map_status.success() {
            return Err(io::Error::other("bpftool map pin failed"));
        }
    }

    let attach_status = run_bpftool([
        "prog",
        "attach",
        "pinned",
        verdict_prog_path
            .to_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "non-utf8 prog path"))?,
        "sk_skb_stream_verdict",
        "pinned",
        map_path
            .to_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "non-utf8 map path"))?,
    ])?;
    if !attach_status.success() {
        return Err(io::Error::other("bpftool verdict attach failed"));
    }

    let parser_attach_status = run_bpftool([
        "prog",
        "attach",
        "pinned",
        parser_prog_path
            .to_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "non-utf8 prog path"))?,
        "sk_skb_stream_parser",
        "pinned",
        map_path
            .to_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "non-utf8 map path"))?,
    ])?;
    if !parser_attach_status.success() {
        return Err(io::Error::other("bpftool parser attach failed"));
    }
    Ok(())
}

fn cleanup_pinned_lure_artifacts(pin_dir: &Path) -> io::Result<()> {
    let entries = match fs::read_dir(pin_dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err),
    };

    for entry in entries {
        let entry = entry?;
        let file_name = match entry.file_name().to_str() {
            Some(name) => name.to_string(),
            None => continue,
        };
        if file_name.starts_with("lure_") || file_name == "sockhash" {
            let path = entry.path();
            let _ = fs::remove_file(path);
        }
    }
    Ok(())
}

fn run_bpftool<const N: usize>(args: [&str; N]) -> io::Result<std::process::ExitStatus> {
    match Command::new("bpftool").args(args).status() {
        Ok(status) if status.success() => Ok(status),
        Ok(status) => {
            if status.code() == Some(126) || status.code() == Some(127) || status.code() == Some(1)
            {
                Command::new("sudo")
                    .args(["-n", "bpftool"])
                    .args(args)
                    .status()
            } else {
                Ok(status)
            }
        }
        Err(_) => Command::new("sudo")
            .args(["-n", "bpftool"])
            .args(args)
            .status(),
    }
}

fn map_update_sockfd(map_fd: RawFd, key: &SockKeyV4, sock_fd: RawFd) -> io::Result<()> {
    log::debug!(
        "sockhash update attempt: map_fd={} sock_fd={} key={{sip4={:#x},dip4={:#x},sport={:#x},dport={:#x}}}",
        map_fd,
        sock_fd,
        key.sip4,
        key.dip4,
        key.sport,
        key.dport
    );
    let mut last_err: Option<io::Error> = None;
    for _ in 0..MAP_UPDATE_RETRIES {
        let mut value = sock_fd as u32;
        let attr = BpfAttrMapElem {
            map_fd: map_fd as u32,
            pad: 0,
            key: key as *const SockKeyV4 as u64,
            value: (&raw mut value) as u64,
            flags: BPF_ANY,
        };
        match bpf_map_elem(BPF_MAP_UPDATE_ELEM, &attr) {
            Ok(()) => return Ok(()),
            Err(err) => {
                let retry = matches!(err.raw_os_error(), Some(libc::EAGAIN | libc::EBUSY));
                if !retry {
                    return Err(err);
                }
                last_err = Some(err);
                std::thread::sleep(std::time::Duration::from_micros(MAP_UPDATE_RETRY_DELAY_US));
            }
        }
    }
    let err = last_err.unwrap_or_else(|| io::Error::from_raw_os_error(libc::EAGAIN));
    log::warn!(
        "sockhash map update exhausted retries: map_fd={} sock_fd={} key={{sip4={:#x},dip4={:#x},sport={:#x},dport={:#x}}} err={}",
        map_fd,
        sock_fd,
        key.sip4,
        key.dip4,
        key.sport,
        key.dport,
        err
    );
    Err(err)
}

fn map_delete(map_fd: RawFd, key: &SockKeyV4) -> io::Result<()> {
    let attr = BpfAttrMapElem {
        map_fd: map_fd as u32,
        pad: 0,
        key: key as *const SockKeyV4 as u64,
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

fn socket_key_v4(fd: RawFd) -> io::Result<SockKeyV4> {
    let local = socket_addr(fd, false)?;
    let peer = socket_addr(fd, true)?;
    let (local_ip, local_port, peer_ip, peer_port) = match (local, peer) {
        (SocketAddr::V4(local), SocketAddr::V4(peer)) => (
            u32::from_be_bytes(local.ip().octets()),
            local.port(),
            u32::from_be_bytes(peer.ip().octets()),
            peer.port(),
        ),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "IPv6 sockets are not supported by this eBPF key mode yet",
            ));
        }
    };
    Ok(SockKeyV4 {
        sip4: local_ip,
        dip4: peer_ip,
        sport: (local_port as u32).to_be(),
        dport: (peer_port as u32).to_be(),
    })
}

fn socket_addr(fd: RawFd, peer: bool) -> io::Result<SocketAddr> {
    let mut addr: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let mut len = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let rc = unsafe {
        if peer {
            libc::getpeername(fd, (&raw mut addr).cast(), &raw mut len)
        } else {
            libc::getsockname(fd, (&raw mut addr).cast(), &raw mut len)
        }
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    sockaddr_storage_to_addr(&addr, len)
}

fn sockaddr_storage_to_addr(
    addr: &libc::sockaddr_storage,
    len: libc::socklen_t,
) -> io::Result<SocketAddr> {
    if len < mem::size_of::<libc::sa_family_t>() as libc::socklen_t {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "sockaddr too small",
        ));
    }
    match addr.ss_family as i32 {
        libc::AF_INET => {
            let sin = unsafe { &*(addr as *const _ as *const libc::sockaddr_in) };
            let ip = std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr).to_be_bytes());
            let port = u16::from_be(sin.sin_port);
            Ok(SocketAddr::V4(std::net::SocketAddrV4::new(ip, port)))
        }
        libc::AF_INET6 => {
            let sin6 = unsafe { &*(addr as *const _ as *const libc::sockaddr_in6) };
            let ip = std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            let port = u16::from_be(sin6.sin6_port);
            Ok(SocketAddr::V6(std::net::SocketAddrV6::new(
                ip,
                port,
                sin6.sin6_flowinfo,
                sin6.sin6_scope_id,
            )))
        }
        other => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("unsupported socket family: {other}"),
        )),
    }
}

fn run_pair_blocking(map_fd: RawFd, fd_a: RawFd, fd_b: RawFd, progress: &EbpfProgress) -> i32 {
    let loop_ctx = EbpfLoopContext::new(fd_a, fd_b);
    match offload_pair_and_wait_with_map(map_fd, fd_a, fd_b, Some(progress), &loop_ctx) {
        Ok(()) => 0,
        Err(err) => {
            log::warn!("eBPF pair loop failed: fd_a={fd_a} fd_b={fd_b} err={err}");
            -errno_from_io_error(&err)
        }
    }
}

fn offload_pair_and_wait_with_map(
    map_fd: RawFd,
    fd_a: RawFd,
    fd_b: RawFd,
    progress: Option<&EbpfProgress>,
    loop_ctx: &EbpfLoopContext,
) -> io::Result<()> {
    let key_a = socket_key_v4(fd_a)?;
    let key_b = socket_key_v4(fd_b)?;
    let _guard = PairGuard::new(map_fd, key_a, key_b, fd_a, fd_b)?;
    loop_ctx.run_loop(progress)
}

struct EbpfLoopContext {
    poll_fds: [libc::pollfd; 2],
}

impl EbpfLoopContext {
    fn new(fd_a: RawFd, fd_b: RawFd) -> Self {
        Self {
            poll_fds: [
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
            ],
        }
    }

    fn run_loop(&self, progress: Option<&EbpfProgress>) -> io::Result<()> {
        let mut poll_fds = self.poll_fds;
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
                if let Some(progress) = progress {
                    progress.inc_poll_error();
                }
                return Err(err);
            }
            if let Some(progress) = progress {
                progress.inc_loop_poll();
            }
            if rc == 0 {
                if let Some(progress) = progress {
                    progress.inc_poll_timeout();
                }
                continue;
            }
            if let Some(progress) = progress {
                progress.inc_poll_wakeup();
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
}

fn errno_from_io_error(err: &io::Error) -> i32 {
    err.raw_os_error().unwrap_or(libc::EIO)
}

fn close_fd(fd: RawFd) {
    let _ = unsafe { libc::close(fd) };
}
