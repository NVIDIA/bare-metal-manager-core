/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::net::{IpAddr, SocketAddr};
use std::result::Result as StdResult;
use std::sync::Arc;

use bmc_mock::HostnameQuerying;
use eyre::Context;
use russh::keys::PublicKeyBase64;
use russh::keys::signature::rand_core::OsRng;
use russh::server::{Auth, Config, Msg, Server as _, Session, run_stream};
use russh::{Channel, ChannelId, MethodKind, MethodSet, Pty, server};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

#[derive(Debug)]
pub struct MockSshServerHandle {
    pub host_pubkey: String,
    pub port: u16,
    _shutdown_handle: Option<oneshot::Sender<()>>,
}

#[derive(Debug, Clone)]
pub struct Credentials {
    pub user: String,
    pub password: String,
}

#[derive(Copy, Clone)]
pub enum PromptBehavior {
    Dell,
    Dpu,
}

pub async fn spawn(
    ip: IpAddr,
    port: Option<u16>,
    prompt_hostname: Arc<dyn HostnameQuerying>,
    require_credentials: Option<Credentials>,
    prompt_behavior: PromptBehavior,
) -> eyre::Result<MockSshServerHandle> {
    let mut rng = OsRng;
    let host_key = russh::keys::PrivateKey::random(&mut rng, russh::keys::Algorithm::Ed25519)?;
    let host_pubkey = host_key.public_key_base64();
    let server = Server {
        prompt_hostname,
        prompt_behavior,
        require_credentials,
    };
    let listener = if let Some(port) = port {
        let socket_addr = SocketAddr::new(ip, port);
        TcpListener::bind(socket_addr)
            .await
            .context(format!("error listening on {socket_addr}"))?
    } else {
        TcpListener::bind("0.0.0.0:0")
            .await
            .context("error listening on 0.0.0.0:0")?
    };

    let port = listener.local_addr()?.port();

    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(server.run(
        Arc::new(russh::server::Config {
            keys: vec![host_key],
            ..Default::default()
        }),
        listener,
        rx,
    ));

    Ok(MockSshServerHandle {
        _shutdown_handle: Some(tx),
        port,
        host_pubkey,
    })
}

#[derive(Clone)]
struct Server {
    prompt_hostname: Arc<dyn HostnameQuerying>,
    prompt_behavior: PromptBehavior,
    require_credentials: Option<Credentials>,
}

impl Server {
    async fn run(
        mut self,
        config: Arc<Config>,
        socket: TcpListener,
        mut shutdown: oneshot::Receiver<()>,
    ) -> eyre::Result<()> {
        loop {
            tokio::select! {
                accept_result = socket.accept() => {
                    match accept_result {
                        Ok((socket, _)) => {
                            let config = config.clone();
                            let handler = self.new_client(socket.peer_addr().ok());

                            tokio::spawn(async move {
                                if config.nodelay
                                    && let Err(e) = socket.set_nodelay(true) {
                                        tracing::warn!("set_nodelay() failed: {e:?}");
                                    }

                                let session = match run_stream(config, socket, handler).await {
                                    Ok(s) => s,
                                    Err(error) => {
                                        if !matches!(error, russh::Error::Disconnect) {
                                            tracing::warn!(?error, "Connection setup failed");
                                        }
                                        return
                                    }
                                };

                                match session.await {
                                    Ok(_) => tracing::debug!("Connection closed"),
                                    Err(russh::Error::Disconnect) => {},
                                    Err(error) => {
                                        tracing::warn!(?error, "Connection closed with error");
                                    }
                                }
                            });
                        }

                        Err(error) => {
                            tracing::error!(?error, "Error accepting SSH connection from socket");
                            break;
                        },
                    }
                },

                _ = &mut shutdown => break,
            }
        }

        Ok(())
    }
}

impl server::Server for Server {
    type Handler = MockSshHandler;
    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self::Handler {
        MockSshHandler::new(
            self.prompt_hostname.clone(),
            self.prompt_behavior,
            self.require_credentials.clone(),
        )
    }
}

struct MockSshHandler {
    prompt_hostname: Arc<dyn HostnameQuerying>,
    prompt_behavior: PromptBehavior,
    console_state: ConsoleState,
    buffer: Vec<u8>,
    require_credentials: Option<Credentials>,
}

impl MockSshHandler {
    fn new(
        prompt_hostname: Arc<dyn HostnameQuerying>,
        prompt_behavior: PromptBehavior,
        require_credentials: Option<Credentials>,
    ) -> Self {
        Self {
            prompt_hostname,
            prompt_behavior,
            console_state: ConsoleState::default(),
            buffer: Vec::default(),
            require_credentials,
        }
    }

    fn print_prompt(
        &self,
        session: &mut Session,
        channel: ChannelId,
    ) -> StdResult<(), russh::Error> {
        match self.console_state {
            ConsoleState::SystemConsole => {
                session.data(
                    channel,
                    format!("\r\nroot@{} # ", self.prompt_hostname.get_hostname()).into(),
                )?;
            }
            ConsoleState::Bmc => {
                session.data(channel, "\nracadm>>".into())?;
            }
            ConsoleState::NoShell => {
                // Do nothing
            }
        }
        Ok(())
    }
}

#[derive(Debug, Default, Copy, Clone)]
enum ConsoleState {
    #[default]
    NoShell,
    Bmc,
    SystemConsole,
}

impl server::Handler for MockSshHandler {
    type Error = russh::Error;

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        _session: &mut Session,
    ) -> StdResult<bool, Self::Error> {
        tracing::debug!("channel_open_session");
        Ok(true)
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> StdResult<(), Self::Error> {
        tracing::debug!("pty_request");
        session.channel_success(channel)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> StdResult<(), Self::Error> {
        tracing::debug!("shell_request");
        match self.prompt_behavior {
            PromptBehavior::Dell => {
                self.console_state = ConsoleState::Bmc;
            }
            PromptBehavior::Dpu => {
                self.console_state = ConsoleState::SystemConsole;
            }
        }
        session.channel_success(channel)?;
        Ok(())
    }

    async fn auth_none(&mut self, _user: &str) -> StdResult<Auth, Self::Error> {
        Ok(server::Auth::Reject {
            proceed_with_methods: Some(MethodSet::from([MethodKind::Password].as_slice())),
            partial_success: false,
        })
    }

    async fn auth_password(&mut self, user: &str, password: &str) -> StdResult<Auth, Self::Error> {
        if let Some(require_credentials) = &self.require_credentials {
            if user == require_credentials.user && password == require_credentials.password {
                tracing::info!("got correct auth_password, accepting");
                Ok(server::Auth::Accept)
            } else {
                tracing::info!(
                    "got incorrect auth_password, rejecting. user={user}, password={password}"
                );
                Ok(server::Auth::Reject {
                    proceed_with_methods: None,
                    partial_success: false,
                })
            }
        } else {
            tracing::info!(
                "configured to accept any credentials, accepting user={user}, password={password}"
            );
            Ok(server::Auth::Accept)
        }
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> StdResult<(), Self::Error> {
        // Sending Ctrl+C ends the session and disconnects the client
        if data == [3] {
            return Err(russh::Error::Disconnect);
        }

        match self.console_state {
            ConsoleState::NoShell => {
                tracing::warn!("data sent without shell request");
            }
            ConsoleState::Bmc => {
                if data == b"\n" || data == b"\r\n" || data == b"\r" {
                    let command = std::mem::take(&mut self.buffer);
                    if command.starts_with(b"connect com2") {
                        tracing::info!(
                            "Got `connect com2` in bmc propmt, simulating system console"
                        );
                        self.console_state = ConsoleState::SystemConsole;
                    }
                    self.print_prompt(session, channel)?;
                } else {
                    self.buffer = [&self.buffer, data].concat();
                    session.data(channel, data.into())?;
                }
            }
            ConsoleState::SystemConsole => {
                if data == b"\n" || data == b"\r\n" || data == b"\r" {
                    let command = std::mem::take(&mut self.buffer);
                    if matches!(self.prompt_behavior, PromptBehavior::Dell)
                        && command.starts_with(b"backdoor_escape_console")
                    {
                        tracing::info!(
                            "Got backdoor command to simulate escaping console, dropping to BMC prompt"
                        );
                        self.console_state = ConsoleState::Bmc;
                    }
                    self.print_prompt(session, channel)?;
                } else {
                    match (data, self.prompt_behavior) {
                        (b"\x1c", PromptBehavior::Dell) => {
                            // ssh-console should have prevented this, make it a warning.
                            tracing::warn!(
                                "Got ctrl+\\ in system console, dropping to BMC prompt {:?}",
                                self.console_state
                            );
                            // ctrl+\
                            self.console_state = ConsoleState::Bmc;
                        }
                        (data, _) => {
                            self.buffer = [&self.buffer, data].concat();
                            session.data(channel, data.into())?;
                        }
                    }
                }
            }
        }

        Ok(())
    }
}
