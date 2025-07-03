use bmc_mock::HostnameQuerying;
use eyre::Context;
use rand_core::OsRng;
use russh::keys::PublicKeyBase64;
use russh::server::{Auth, Config, Msg, Server as _, Session, run_stream};
use russh::{Channel, ChannelId, MethodKind, MethodSet, Pty, server};
use std::net::{IpAddr, SocketAddr};
use std::result::Result as StdResult;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

#[derive(Debug)]
pub struct MockSshServerHandle {
    pub host_pubkey: String,
    pub port: u16,
    _shutdown_handle: Option<oneshot::Sender<()>>,
}

pub async fn spawn(
    ip: IpAddr,
    port: Option<u16>,
    prompt_hostname: Arc<dyn HostnameQuerying>,
    accept_user: String,
    accept_password: String,
) -> eyre::Result<MockSshServerHandle> {
    let mut rng = OsRng;
    let host_key = russh::keys::PrivateKey::random(&mut rng, russh::keys::Algorithm::Ed25519)?;
    let host_pubkey = host_key.public_key_base64();
    let server = Server {
        prompt_hostname,
        accept_user,
        accept_password,
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
    accept_user: String,
    accept_password: String,
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
                                if config.nodelay {
                                    if let Err(e) = socket.set_nodelay(true) {
                                        tracing::warn!("set_nodelay() failed: {e:?}");
                                    }
                                }

                                let session = match run_stream(config, socket, handler).await {
                                    Ok(s) => s,
                                    Err(error) => {
                                        tracing::warn!(?error, "Connection setup failed");
                                        return
                                    }
                                };

                                match session.await {
                                    Ok(_) => tracing::debug!("Connection closed"),
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
            self.accept_user.clone(),
            self.accept_password.clone(),
        )
    }
}

#[derive(Debug)]
struct MockSshHandler {
    prompt_hostname: Arc<dyn HostnameQuerying>,
    console_state: ConsoleState,
    buffer: Vec<u8>,
    accept_user: String,
    accept_password: String,
}

impl MockSshHandler {
    fn new(
        prompt_hostname: Arc<dyn HostnameQuerying>,
        accept_user: String,
        accept_password: String,
    ) -> Self {
        Self {
            prompt_hostname,
            console_state: ConsoleState::default(),
            buffer: Vec::default(),
            accept_user,
            accept_password,
        }
    }

    fn print_prompt(
        &self,
        session: &mut Session,
        channel: ChannelId,
    ) -> StdResult<(), russh::Error> {
        match self.console_state {
            ConsoleState::System => {
                session.data(
                    channel,
                    format!("\r\nroot@{} # ", self.prompt_hostname.get_hostname()).into(),
                )?;
            }
            ConsoleState::Bmc => {
                session.data(channel, "\nracadm>>".into())?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
enum ConsoleState {
    #[default]
    Bmc,
    System,
}

impl server::Handler for MockSshHandler {
    type Error = russh::Error;

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        _session: &mut Session,
    ) -> StdResult<bool, Self::Error> {
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
        session.channel_success(channel)?;
        self.print_prompt(session, channel)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> StdResult<(), Self::Error> {
        session.channel_success(channel)?;
        Ok(())
    }

    async fn auth_none(&mut self, user: &str) -> StdResult<Auth, Self::Error> {
        if user == self.accept_user {
            Ok(server::Auth::Reject {
                proceed_with_methods: Some(MethodSet::from([MethodKind::Password].as_slice())),
                partial_success: false,
            })
        } else {
            Ok(server::Auth::Reject {
                proceed_with_methods: None,
                partial_success: false,
            })
        }
    }

    async fn auth_password(&mut self, user: &str, password: &str) -> StdResult<Auth, Self::Error> {
        if user == self.accept_user && password == self.accept_password {
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

        if data == b"\n" || data == b"\r\n" || data == b"\r" {
            let command = std::mem::take(&mut self.buffer);
            if command.starts_with(b"connect com2") {
                tracing::info!("Got `connect com2` in state {:?}", self.console_state);
                if matches!(self.console_state, ConsoleState::Bmc) {
                    self.console_state = ConsoleState::System;
                }
            } else if command.starts_with(b"backdoor_escape_console") {
                tracing::info!(
                    "Got command to simulate escaping console in state {:?}: {}",
                    self.console_state,
                    String::from_utf8_lossy(&command),
                );
                self.console_state = ConsoleState::Bmc;
            } else {
                tracing::info!("Got command in state {:?}: {command:?}", self.console_state,);
            }

            self.print_prompt(session, channel)?;
        } else {
            match data {
                b"\x1c" => {
                    tracing::info!("Got ctrl+\\ in state {:?}", self.console_state);
                    // ctrl+\
                    if matches!(self.console_state, ConsoleState::System) {
                        self.console_state = ConsoleState::Bmc;
                        session.data(channel, "\r\nracadm>>".into())?;
                    }
                }
                data => {
                    self.buffer = [&self.buffer, data].concat();
                    session.data(channel, data.into())?;
                }
            }
        }

        Ok(())
    }
}
