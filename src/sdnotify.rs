//! Minimal sd_notify(3) implementation so the daemon can run as
//! `Type=notify` with watchdog support, without pulling in a crate.

pub fn notify(state: &str) {
    let path = match std::env::var("NOTIFY_SOCKET") {
        Ok(p) if !p.is_empty() => p,
        _ => return,
    };
    unsafe {
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return;
        }
        let mut addr: libc::sockaddr_un = std::mem::zeroed();
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let bytes = path.as_bytes();
        if bytes.is_empty() || bytes.len() >= addr.sun_path.len() {
            libc::close(fd);
            return;
        }
        for (i, b) in bytes.iter().enumerate() {
            addr.sun_path[i] = *b as libc::c_char;
        }
        let family_len = std::mem::size_of::<libc::sa_family_t>();
        let len = if bytes[0] == b'@' {
            // Abstract namespace socket: leading NUL, no trailing NUL.
            addr.sun_path[0] = 0;
            family_len + bytes.len()
        } else {
            family_len + bytes.len() + 1
        };
        libc::sendto(
            fd,
            state.as_ptr() as *const libc::c_void,
            state.len(),
            0,
            &addr as *const _ as *const libc::sockaddr,
            len as libc::socklen_t,
        );
        libc::close(fd);
    }
}
