use crate::bmc_vendor::IPMITOOL_ESCAPE_SEQUENCE;
use crate::config::Config;
use crate::io_util::{self, set_controlling_terminal_on_exec, write_data_to_async_fd};
use crate::ssh_server::backend::IpmiConnectionDetails;
use eyre::Context;
use forge_uuid::machine::MachineId;
use nix::errno::Errno;
use nix::pty::OpenptyResult;
use nix::unistd;
use russh::ChannelMsg;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::Arc;
use tokio::io::unix::AsyncFd;
use tokio::sync::{broadcast, mpsc};

/// Spawn ipmitool in the background to connect to the given BMC specified by `connection_details`,
/// and proxy data between it and the SSH frontend.
///
/// A PTY is opened to control ipmitool, since it's designed to work with one, and having a
/// persistent PTY allows multiple connections to work without worrying about how to interpret
/// multiple client PTY requests.
///
/// `to_frontend_tx` is a [`russh::Channel`] to send data from ipmitool to the SSH frontend.
///
/// Returns a [`mpsc::Sender<ChannelMsg>`] that the frontend can use to send data to ipmitool.
pub async fn spawn(
    connection_details: &IpmiConnectionDetails,
    to_frontend_tx: broadcast::Sender<Arc<ChannelMsg>>,
    config: &Config,
) -> eyre::Result<mpsc::Sender<ChannelMsg>> {
    let machine_id = connection_details.machine_id;
    // Open a PTY to control ipmitool
    let OpenptyResult {
        master: pty_master,
        slave: pty_slave,
    } = io_util::alloc_pty(80, 24).context("error spawning a PTY for ipmitool")?;
    let pty_master = AsyncFd::new(pty_master).expect("BUG: not in tokio runtime?");

    // Run `ipmitool sol activate` with the appropriate args
    let mut command = tokio::process::Command::new("ipmitool");
    command
        .arg("-I")
        .arg("lanplus")
        .arg("-H")
        .arg(connection_details.addr.ip().to_string())
        .arg("-p")
        .arg(connection_details.addr.port().to_string())
        .arg("-U")
        .arg(&connection_details.user)
        .arg("-P")
        .arg(&connection_details.password)
        // connect stdin/stdout/stderr to the pty
        .stdin(
            pty_slave
                .try_clone()
                .context("error cloning pty fd for stdin")?,
        )
        .stdout(
            pty_slave
                .try_clone()
                .context("error cloning pty fd for stdout")?,
        )
        .stderr(
            pty_slave
                .try_clone()
                .context("error cloning pty fd for stderr")?,
        )
        // Set the xterm env var as a reasonable default.
        .env("TERM", "xterm");

    if config.insecure_ipmi_ciphers {
        command.arg("-C").arg("3"); // use SHA1 ciphers, useful for ipmi_sim
    }
    command.arg("sol").arg("activate");

    // Spawn ipmitool in the controlling pty
    set_controlling_terminal_on_exec(&mut command, pty_slave.as_raw_fd());
    let mut process = command.spawn().context("error spawning ipmitool")?;

    // Make a channel the frontend can use to send messages to us
    let (from_frontend_tx, from_frontend_rx) = mpsc::channel(1);

    // Send messages to/from ipmitool in the background. We have to print our own errors here,
    // because nothing is polling the exit status.
    tokio::spawn(async move {
        match ipmitool_process_loop(machine_id, pty_master, from_frontend_rx, &to_frontend_tx).await
        {
            Ok(()) => tracing::debug!(%machine_id, "ipmitool task finished successfully"),
            Err(e) => tracing::error!(%machine_id, "ipmitool task error: {e:?}"),
        }
        match process.try_wait() {
            Ok(Some(exit_status)) if exit_status.success() => {}
            Ok(Some(exit_failure_status)) => {
                tracing::warn!(%machine_id, "ipmitool exit status: {exit_failure_status:?}");
            }
            Ok(None) => {
                process.kill().await.ok();
            }
            Err(e) => {
                tracing::error!(%machine_id, "error checking ipmitool exit status: {e:?}");
                process.kill().await.ok();
            }
        }
    });

    Ok(from_frontend_tx)
}

/// Poll from the SSH frontend and the ipmitool PTY in the foreground, pumping messages between
/// them, until either the frontend closes or ipmitool exits.
///
/// This function is tricky because we're dealing with "normal" UNIX file descriptors (set with
/// O_NONBLOCK), but we want to poll them in a tokio::select loop.  So we have to do the typical
/// UNIX pattern of reading/writing data until we get EWOULDBLOCK, returning to the main loop, etc.
async fn ipmitool_process_loop(
    machine_id: MachineId,
    pty_master: AsyncFd<OwnedFd>,
    mut from_frontend_rx: mpsc::Receiver<ChannelMsg>,
    to_frontend_tx: &broadcast::Sender<Arc<ChannelMsg>>,
) -> eyre::Result<()> {
    // Keep track of whether the last byte sent from the client was the first byte of an escape sequence.
    let mut escape_was_pending = false;
    // Read up to a few kilobytes of stdout from ipmitool at a time
    let mut stdout_buf = [0u8; 4096];
    loop {
        tokio::select! {
            // Poll for any data to be available in pty_master
            guard = pty_master.readable() => {
                let mut guard = guard.context("error polling from pty master fd")?;
                // Read the available data
                match unistd::read(guard.get_inner(), &mut stdout_buf) {
                    Ok(n) => {
                        if n == 0 {
                            tracing::debug!(%machine_id, "eof from pty fd");
                            break;
                        }
                        to_frontend_tx.send(Arc::new(ChannelMsg::Data { data: stdout_buf[0..n].to_vec().into() }))
                            .context("error writing data from ipmitool to frontend channel")?;
                        // Note, we're not clearing the ready state, so the fd will stay readable.
                        // The next time through the loop we'll get EWOULDBLOCK and clear the
                        // status. This lets us handle cases where there's more data to read than
                        // the buf size.
                    }
                    Err(e) if e == Errno::EWOULDBLOCK => {
                        // clear the readiness so we go back to polling
                        guard.clear_ready();
                    }
                    Err(e) => {
                        return Err(eyre::Report::new(std::io::Error::from_raw_os_error(e as _))
                            .wrap_err("error reading from async fd"));
                    }
                };
            }
            // Poll for any messages from the SSH frontend
            res = from_frontend_rx.recv() => match res {
                Some(msg) => {
                    escape_was_pending = send_frontend_message_to_ipmi_console(machine_id, msg, &pty_master, escape_was_pending).await.context(
                        "error sending frontend message to ipmi console"
                    )?;
                }
                None => {
                    tracing::info!(%machine_id, "ssh connection closed, stopping ipmitool");
                    break;
                }
            },
        }
    }

    Ok(())
}

async fn send_frontend_message_to_ipmi_console(
    machine_id: MachineId,
    msg: ChannelMsg,
    ipmitool_pty: &AsyncFd<OwnedFd>,
    escape_was_pending: bool,
) -> eyre::Result<bool> {
    let (msg, escape_pending) = match msg {
        // Filter out escape sequences
        ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, ext: _ } => {
            let (data, escape_pending) =
                IPMITOOL_ESCAPE_SEQUENCE.filter_escape_sequences(data.as_ref(), escape_was_pending);
            (
                ChannelMsg::Data {
                    data: data.as_ref().into(),
                },
                escape_pending,
            )
        }
        msg => (msg, escape_was_pending),
    };

    // TODO: parse an escape sequence to trigger a reboot (legacy ssh-console used ^U, but that was awful.)

    match msg {
        ChannelMsg::Eof | ChannelMsg::Close => {
            // multiple clients can come and go, we don't close just because one of them disconnected.
        }
        ChannelMsg::Data { data } => {
            write_data_to_async_fd(&data, ipmitool_pty)
                .await
                .context("error writing to ipmitool pty")?;
        }
        ChannelMsg::WindowChange {
            col_width,
            row_height,
            pix_width,
            pix_height,
        } => {
            // update the kernel pty size
            let winsz = libc::winsize {
                ws_row: row_height.try_into().unwrap_or(80),
                ws_col: col_width.try_into().unwrap_or(24),
                ws_xpixel: pix_width.try_into().unwrap_or(0),
                ws_ypixel: pix_height.try_into().unwrap_or(0),
            };
            // SAFETY: ioctl on master FD
            unsafe {
                libc::ioctl(ipmitool_pty.as_raw_fd(), libc::TIOCSWINSZ, &winsz);
            }
        }
        other => {
            tracing::debug!(%machine_id, "Not handling unknown SSH frontend message in ipmitool: {other:?}");
        }
    };
    Ok(escape_pending)
}
