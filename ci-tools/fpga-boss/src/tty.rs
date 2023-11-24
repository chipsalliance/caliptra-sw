// Licensed under the Apache-2.0 license

use std::{
    io::{self, ErrorKind, Read},
    mem::MaybeUninit,
    os::fd::AsRawFd,
};

pub struct RawTerminal {
    old_termios: libc::termios,
}
impl RawTerminal {
    pub fn from_stdin() -> io::Result<Self> {
        let stdin = io::stdin().lock();
        unsafe {
            let mut termios = MaybeUninit::<libc::termios>::uninit();
            if libc::tcgetattr(stdin.as_raw_fd(), termios.as_mut_ptr()) != 0 {
                return Err(io::Error::last_os_error());
            }
            let mut termios = termios.assume_init();
            let old_termios = termios;
            termios.c_iflag &= !(libc::IGNBRK
                | libc::BRKINT
                | libc::PARMRK
                | libc::ISTRIP
                | libc::ICRNL
                | libc::INLCR
                | libc::IGNCR
                | libc::IXON);
            termios.c_oflag &= !libc::OPOST;

            // Do we want this?
            termios.c_oflag |= libc::ONLCR | libc::OPOST;

            termios.c_lflag &=
                !(libc::ECHO | libc::ECHONL | libc::ICANON | libc::IEXTEN | libc::ISIG);
            termios.c_cflag &= !(libc::CSIZE | libc::PARENB);
            termios.c_cflag |= libc::CS8;
            termios.c_cc[libc::VMIN] = 1;
            termios.c_cc[libc::VTIME] = 0;
            if libc::tcsetattr(stdin.as_raw_fd(), libc::TCSANOW, &termios as *const _) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(RawTerminal { old_termios })
        }
    }
}
impl Drop for RawTerminal {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(
                io::stdin().as_raw_fd(),
                libc::TCSANOW,
                &self.old_termios as *const _,
            );
        }
    }
}

pub fn read_stdin_nonblock(buf: &mut [u8]) -> io::Result<usize> {
    unsafe {
        let mut stdin = io::stdin().lock();
        let flags = libc::fcntl(stdin.as_raw_fd(), libc::F_GETFL);
        if flags == -1 {
            return Err(io::Error::last_os_error());
        }
        let rv = libc::fcntl(stdin.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
        if rv == -1 {
            return Err(io::Error::last_os_error());
        }
        let bytes_read = match stdin.read(buf) {
            Ok(bytes_read) => Ok(bytes_read),
            Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(0),
            Err(e) => Err(e),
        }?;
        let rv = libc::fcntl(stdin.as_raw_fd(), libc::F_SETFL, flags);
        if rv == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(bytes_read)
    }
}

pub struct EscapeSeqStateMachine {
    escaped: bool,
}
impl EscapeSeqStateMachine {
    pub fn new() -> Self {
        Self { escaped: false }
    }
    pub fn process(&mut self, buf: &mut [u8], len: &mut usize, mut cb: impl FnMut(u8)) {
        let mut copy_offset = 0;
        for i in 0..*len {
            let ch = buf[i];
            if self.escaped {
                self.escaped = false;
                if ch != 0x14 {
                    cb(ch);
                    copy_offset += 1;
                    *len -= 1;
                    continue;
                }
            } else if ch == 0x14 {
                // Ctrl-T was pressed
                self.escaped = true;
                copy_offset += 1;
                *len -= 1;
                continue;
            }
            buf[i - copy_offset] = ch;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::EscapeSeqStateMachine;

    #[test]
    fn test_escape_sequence() {
        let mut callback_invocations = Vec::new();
        let mut sm = EscapeSeqStateMachine::new();
        let mut buf = [b'H', b'i', 0x14, 0x00];
        let mut len = 3;
        sm.process(&mut buf, &mut len, |ch| callback_invocations.push(ch));
        assert_eq!(&buf[..len], [b'H', b'i']);
        assert_eq!(callback_invocations, vec![]);

        len = 2;
        buf = [b'q', b'W', 0x00, 0x00];
        sm.process(&mut buf, &mut len, |ch| callback_invocations.push(ch));
        assert_eq!(&buf[..len], [b'W']);
        assert_eq!(callback_invocations, vec![b'q']);

        callback_invocations.clear();
        len = 9;
        let mut buf = [b'h', 0x14, b'w', b'j', 0x14, 0x14, 0x14, b'd', b'x'];
        sm.process(&mut buf, &mut len, |ch| callback_invocations.push(ch));
        assert_eq!(&buf[..len], [b'h', b'j', 0x14, b'x']);
        assert_eq!(callback_invocations, vec![b'w', b'd']);
    }
}
