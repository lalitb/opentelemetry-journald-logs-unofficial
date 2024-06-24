use libc::*;
use std::ffi::CString;
use std::fs::File;
use std::io::{Error, Result};
use std::os::unix::net::UnixDatagram;
use std::os::unix::prelude::{AsRawFd, FromRawFd, RawFd};

pub mod utils {
    use super::*;

/// Creates a sealable memory file descriptor.
pub fn create_sealable() -> Result<File> {
    let name = CString::new("tracing-journald").unwrap();
    let fd = unsafe {
        syscall(
            SYS_memfd_create,
            name.as_ptr(),
            MFD_ALLOW_SEALING | MFD_CLOEXEC,
        )
    };

    if fd < 0 {
        Err(Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd as RawFd) })
    }
}

/// Seals the memory file descriptor to prevent modifications.
pub fn seal_fully(fd: RawFd) -> Result<()> {
    let res = unsafe {
        fcntl(
            fd,
            F_ADD_SEALS,
            F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_SEAL,
        )
    };

    if res < 0 {
        Err(Error::last_os_error())
    } else {
        Ok(())
        }
}

/// Sends a file descriptor to journald using a Unix domain socket.
pub fn send_fd_journald(fd: RawFd, journald_path: &str) -> Result<()> {
    println!("Sending fd to journald at path: {}", journald_path);
    let socket = UnixDatagram::unbound()?;
    let sockaddr = sockaddr_un {
        sun_family: AF_UNIX as sa_family_t,
        sun_path: {
            let mut sun_path = [0; 108];
            for (i, &b) in journald_path.as_bytes().iter().enumerate() {
                sun_path[i] = b as c_char;
            }
            sun_path
        },
    };
    let sockaddr_len = std::mem::size_of_val(&sockaddr);
    let iov = [iovec {
        iov_base: std::ptr::null_mut(),
        iov_len: 0,
    }];
    let fds = [fd];
    let cmsg_space =
        unsafe { CMSG_SPACE((fds.len() * std::mem::size_of::<RawFd>()) as u32) as usize };
    let mut cmsg_buf = vec![0u8; cmsg_space];

    let msghdr = msghdr {
        msg_name: &sockaddr as *const _ as *mut _,
        msg_namelen: sockaddr_len as socklen_t,
        msg_iov: iov.as_ptr() as *mut iovec,
        msg_iovlen: iov.len() as _,
        msg_control: cmsg_buf.as_mut_ptr() as *mut _,
        msg_controllen: cmsg_buf.len() as _,
        msg_flags: 0,
    };

    unsafe {
        let cmsg = CMSG_FIRSTHDR(&msghdr);
        (*cmsg).cmsg_level = SOL_SOCKET;
        (*cmsg).cmsg_type = SCM_RIGHTS;
        (*cmsg).cmsg_len = CMSG_LEN((fds.len() * std::mem::size_of::<RawFd>()) as u32) as _;
        std::ptr::copy_nonoverlapping(
            fds.as_ptr() as *const c_void,
            CMSG_DATA(cmsg) as *mut c_void,
            fds.len() * std::mem::size_of::<RawFd>(),
        );

        println!("Message header: msg_name = {:?}, msg_namelen = {}, msg_iovlen = {}, msg_controllen = {}, msg_flags = {}",
            msghdr.msg_name, msghdr.msg_namelen, msghdr.msg_iovlen, msghdr.msg_controllen, msghdr.msg_flags);
        println!("Control message: level = {}, type = {}, len = {}", (*cmsg).cmsg_level, (*cmsg).cmsg_type, (*cmsg).cmsg_len);
        
        let ret = sendmsg(socket.as_raw_fd(), &msghdr, 0);
        if ret < 0 {
            let err = Error::last_os_error();
            println!("Error sending message: {:?}", err);
            Err(err)
        } else {
            println!("Message sent successfully");
            Ok(())
        }
    }
}
}