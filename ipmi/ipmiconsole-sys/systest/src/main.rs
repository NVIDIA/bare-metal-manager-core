extern crate errno;
extern crate getopts;
extern crate ipmiconsole_sys;
extern crate libc;
extern crate termios;

use errno::errno;
use ipmiconsole_sys::{
    ipmi_console::*, AuthenticationType, CipherSuite, CipherSuite::*, IpmiConsoleError,
    PrivilegeLevel, PrivilegeLevel::*,
};
use libc::{c_int, c_void, fcntl, size_t, ssize_t, EAGAIN, F_GETFL, F_SETFL, O_NONBLOCK};

use std::io;
use std::io::Write;
use std::os::unix::io::{AsRawFd, RawFd};
use std::{thread, time};
use termios::Termios;
use termios::*;

fn setup_raw_tty(fd: RawFd, saved_tty: &mut Termios) -> io::Result<()> {
    tcgetattr(fd, saved_tty)?;
    let mut set_tty: Termios = *saved_tty;

    set_tty.c_iflag = 0;
    set_tty.c_oflag = 0;
    set_tty.c_cflag &= !CSIZE;
    set_tty.c_cflag |= CS8;
    set_tty.c_cflag &= !PARENB;
    set_tty.c_cflag |= CLOCAL;
    set_tty.c_lflag &= !(ECHO | ICANON | IEXTEN | ISIG);
    set_tty.c_cc[VMIN] = 1;
    set_tty.c_cc[VTIME] = 0;

    tcsetattr(fd, TCSADRAIN, &set_tty)?;
    Ok(())
}

fn restore_tty(fd: RawFd, saved_tty: &mut Termios) -> io::Result<()> {
    tcsetattr(fd, TCSAFLUSH, saved_tty).unwrap();
    Ok(())
}

/// read all available output in sol fd and dump to stdout
fn read_sol_and_print(ctx: &mut IpmiConsoleContext, fd: RawFd) -> Result<(), IpmiConsoleError> {
    let mut buf: Vec<u8> = vec![0; 4096];
    let readlen = ctx.read(&mut buf)?;

    if readlen < 0 {
        return Err(IpmiConsoleError::ReadFd(errno().0));
    }
    if readlen == 0 {
        return Ok(());
    }

    let mut writelen = readlen as size_t;
    buf.truncate(writelen);
    while writelen > 0 {
        let wrote: ssize_t;
        unsafe {
            wrote = libc::write(fd, buf.as_ptr() as *const c_void, writelen);
        }
        match wrote {
            n if n > 0 => {
                writelen -= wrote as size_t;
                buf.drain(0..wrote as usize);
            }
            e if e < 0 => {
                return Err(IpmiConsoleError::WriteFd(errno().0));
            }
            _ => {}
        }
    }

    Ok(())
}

fn read_stdin_and_send(ctx: &mut IpmiConsoleContext, fd: RawFd) -> Result<(), IpmiConsoleError> {
    let readlen: ssize_t;
    let mut buf: Vec<u8> = vec![0; 4096];

    unsafe {
        readlen = libc::read(fd, buf.as_mut_ptr() as *mut c_void, buf.len());
    }
    if readlen < 0 {
        if errno().0 == EAGAIN {
            return Ok(());
        }
        return Err(IpmiConsoleError::ReadFd(errno().0));
    }

    if readlen == 0 {
        return Ok(());
    }
    // write entire buffer to sol
    let mut writelen = readlen as size_t;
    buf.truncate(writelen);
    while writelen > 0 {
        let wrote = ctx.write(&buf)?;
        match wrote {
            n if n > 0 => {
                writelen -= wrote as size_t;
                buf.drain(0..wrote as usize);
            }
            e if e < 0 => {
                return Err(IpmiConsoleError::WriteFd(errno().0));
            }
            _ => {}
        }
    }

    Ok(())
}

fn main() -> Result<(), String> {
    let mut hostname: String = "".to_string();
    let mut username: String = "".to_string();
    let mut password: String = "".to_string();
    let mut cipher: CipherSuite = HmacSha1AesCbc128;
    let mut auth: AuthenticationType = AuthenticationType::None;
    let mode: PrivilegeLevel = Admin;
    let args: Vec<String> = std::env::args().collect();
    let mut opts = getopts::Options::new();
    let mut error_msg: String = "".to_string();
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let mut saved_stdin: Termios = Termios::from_fd(stdin.as_raw_fd()).unwrap();
    let mut saved_stdout: Termios = Termios::from_fd(stdout.as_raw_fd()).unwrap();

    opts.optopt("H", "hostname", "specify hostname or IP address", "HOST");
    opts.optopt("U", "username", "specify authentication username", "USER");
    opts.optopt("P", "password", "specify authentication password", "PASS");
    opts.optopt(
        "C",
        "cipher",
        "specify cipher suite value to use (only for lanplus)",
        "CIPHER",
    );
    opts.optopt(
        "A",
        "auth",
        "specify auth type NONE/PASSWORD/MD2/MD5/OEM to use (only for lan)",
        "AUTH",
    );

    let args_given = opts.parse(&args[1..]).unwrap();
    if args_given.opt_present("H") {
        hostname = args_given.opt_str("H").unwrap();
    }
    if args_given.opt_present("U") {
        username = args_given.opt_str("U").unwrap();
    }
    if args_given.opt_present("P") {
        password = args_given.opt_str("P").unwrap();
    }
    if !error_msg.is_empty() {
        return Err(error_msg);
    }

    if args_given.opt_present("A") {
        match args_given.opt_str("A").unwrap().as_str() {
            "NONE" => {
                auth = AuthenticationType::None;
            }
            "PASSWORD" => {
                auth = AuthenticationType::StraightPasswordKey;
            }
            "MD2" => {
                auth = AuthenticationType::Md2;
            }
            "MD5" => {
                auth = AuthenticationType::Md5;
            }
            "OEM" => {
                auth = AuthenticationType::OemProp;
            }
            _ => {
                error_msg = format!(
                    "Invalid auth argument given {}",
                    args_given.opt_str("A").unwrap()
                );
            }
        }
    }
    if !error_msg.is_empty() {
        return Err(error_msg);
    }

    if args_given.opt_present("C") {
        match args_given.opt_str("C").unwrap().as_str() {
            "3" => {
                cipher = CipherSuite::HmacSha1AesCbc128;
            }
            "8" => {
                cipher = CipherSuite::HmacMd5AesCbc128;
            }
            "17" => {
                cipher = CipherSuite::HmacSha256AesCbc128;
            }
            _ => {
                error_msg = format!(
                    "Unsupported cipher specified {}",
                    args_given.opt_str("C").unwrap()
                );
            }
        }
    }
    if !error_msg.is_empty() {
        return Err(error_msg);
    }

    ipmiconsole_threads_init(1).unwrap();

    let mut ctx = IpmiConsoleContext::new(
        hostname,
        username,
        password,
        Option::from(cipher),
        Option::from(mode),
        Option::from(auth),
    );

    match ctx.connect() {
        Ok(()) => {
            // this is a simple test so run it for a fixed amount of time.
            let mut ctr: usize = 1000;
            let sleeptime = time::Duration::from_millis(10);

            // set raw on stdin and stdout
            setup_raw_tty(stdin.as_raw_fd(), &mut saved_stdin).unwrap();
            setup_raw_tty(stdout.as_raw_fd(), &mut saved_stdout).unwrap();

            // loop
            //   read from sol and write to stdout
            //   read from stdin and write to sol
            // todo: handle ~~. escape sequence to stop similar to ipmitool behavior
            loop {
                unsafe {
                    let flags: c_int = fcntl(stdin.as_raw_fd(), F_GETFL, 0);
                    fcntl(stdin.as_raw_fd(), F_SETFL, flags | O_NONBLOCK);
                }
                read_stdin_and_send(&mut ctx, stdin.as_raw_fd()).unwrap();
                read_sol_and_print(&mut ctx, stdout.as_raw_fd()).unwrap();
                stdout.flush().unwrap();

                thread::sleep(sleeptime);
                ctr -= 1;
                if ctr == 0 {
                    break;
                }
            }

            restore_tty(stdin.as_raw_fd(), &mut saved_stdin).unwrap();
            restore_tty(stdout.as_raw_fd(), &mut saved_stdout).unwrap();
        }
        Err(e) => {
            let error_msg = format!("Failed to connect {}", e);
            println!("{}", error_msg);
        }
    }

    if ctx.disconnect().is_err() {
        println!("Error disconnecting");
    }

    ipmiconsole_threads_exit();

    Ok(())
}
