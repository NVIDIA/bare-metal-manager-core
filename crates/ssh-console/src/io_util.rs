/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::os::fd::{AsFd, OwnedFd, RawFd};

use nix::errno::Errno;
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::pty::{OpenptyResult, openpty};
use nix::sys::termios::{Termios, cfmakeraw};
use nix::unistd;
use tokio::io::unix::AsyncFd;

/// Allocate a pty with `nix::pty::openpty`, ensuring its file descriptors are set with O_NONBLOCK,
/// and return it.
pub fn alloc_pty(cols: u16, rows: u16) -> Result<OpenptyResult, PtyAllocError> {
    // set up raw mode so the child sees a “dumb” terminal
    let libc_termios = libc::termios {
        c_iflag: 0,
        c_oflag: 0,
        c_cflag: 0,
        c_lflag: 0,
        c_line: 0,
        c_cc: [0; 32],
        c_ispeed: 0,
        c_ospeed: 0,
    };
    let mut termios = Termios::from(libc_termios);
    cfmakeraw(&mut termios);

    // set initial window-size
    let winsz = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };

    let pty = openpty(Some(&winsz), Some(&termios)).map_err(|error| PtyAllocError::Io {
        what: "opening PTY",
        error: std::io::Error::from_raw_os_error(error as _),
    })?;

    set_nonblocking(&pty.master).map_err(|error| PtyAllocError::Io {
        what: "making PTY master fd non-blocking",
        error: std::io::Error::from_raw_os_error(error as _),
    })?;
    set_nonblocking(&pty.slave).map_err(|error| PtyAllocError::Io {
        what: "making PTY slave fd non-blocking",
        error: std::io::Error::from_raw_os_error(error as _),
    })?;

    Ok(pty)
}

#[derive(thiserror::Error, Debug)]
pub enum PtyAllocError {
    #[error("error {what}: {error}")]
    Io {
        error: std::io::Error,
        what: &'static str,
    },
}

/// Make `pty_slave` the controlling terminal for the given command when it is executed.
pub fn set_controlling_terminal_on_exec(command: &mut tokio::process::Command, pty_slave: RawFd) {
    // SAFETY: the pre_exec closure runs in the forked process before exec, where setsid() and
    // setting TIOCSCTTY are commonly allowed things.
    unsafe {
        command.pre_exec(move || {
            unistd::setsid()?;
            // https://man7.org/linux/man-pages/man2/TIOCSCTTY.2const.html
            if libc::ioctl(pty_slave, libc::TIOCSCTTY, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// Set the O_NONBLOCK flag on a file descriptor.
///
/// This is essential to allow reading/writing to the fd from a tokio context, otherwise it will
/// block the runtime.
fn set_nonblocking<F: AsFd>(fd: &F) -> nix::Result<()> {
    let current_flags = fcntl(fd, FcntlArg::F_GETFL)?;
    let flags_with_nonblock = OFlag::from_bits_truncate(current_flags) | OFlag::O_NONBLOCK;
    fcntl(fd, FcntlArg::F_SETFL(flags_with_nonblock))?;
    Ok(())
}

/// Waits for the fd to be ready for writing, and writes the data to it, looping repeatedly until
/// all data is written.
pub async fn write_data_to_async_fd(data: &[u8], fd: &AsyncFd<OwnedFd>) -> std::io::Result<usize> {
    let mut written = 0;
    loop {
        let mut guard = fd.writable().await?;
        match unistd::write(fd, &data[written..]) {
            Ok(0) => {
                // EOF
                break;
            }
            Ok(n) => {
                written += n;
                if written >= data.len() {
                    break;
                }
            }
            Err(e) if e == Errno::EWOULDBLOCK => {
                // no data, await writable() again
                guard.clear_ready();
            }
            Err(e) => return Err(std::io::Error::from_raw_os_error(e as _)),
        }
    }
    Ok(written)
}
