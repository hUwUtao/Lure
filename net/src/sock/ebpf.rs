use std::{
    ffi::CString,
    io, mem,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    sync::OnceLock,
};

const BPF_MAP_UPDATE_ELEM: libc::c_uint = 2;
const BPF_MAP_DELETE_ELEM: libc::c_uint = 3;
const BPF_OBJ_GET: libc::c_uint = 7;
const BPF_ANY: u64 = 0;
const SO_COOKIE: libc::c_int = 57;

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

    fn offload_pair_and_wait(&self, fd_a: RawFd, fd_b: RawFd) -> io::Result<()> {
        let key_a = socket_cookie(fd_a)?;
        let key_b = socket_cookie(fd_b)?;
        let _guard = PairGuard::new(self.map_fd.as_raw_fd(), key_a, key_b, fd_a, fd_b)?;
        wait_for_disconnect(fd_a, fd_b)
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

pub fn offload_pair_and_wait(fd_a: RawFd, fd_b: RawFd) -> io::Result<bool> {
    let enabled = std::env::var("LURE_IO_EBPF")
        .ok()
        .or_else(|| std::env::var("NET_IO_EBPF").ok())
        .is_some_and(|value| value == "1");
    if !enabled {
        return Ok(false);
    }

    let endpoint = ENDPOINT.get_or_init(|| Endpoint::from_env().map_err(|err| err.to_string()));
    let endpoint = endpoint
        .as_ref()
        .map_err(|err| io::Error::other(err.clone()))?;

    endpoint.offload_pair_and_wait(fd_a, fd_b)?;
    Ok(true)
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

fn wait_for_disconnect(fd_a: RawFd, fd_b: RawFd) -> io::Result<()> {
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
        let rc = unsafe { libc::poll(poll_fds.as_mut_ptr(), poll_fds.len() as libc::nfds_t, -1) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        for fd in &poll_fds {
            if (fd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLRDHUP)) != 0 {
                return Ok(());
            }
        }
    }
}
