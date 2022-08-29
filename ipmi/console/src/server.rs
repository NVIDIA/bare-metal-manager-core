use std::collections::HashMap;
use std::net::SocketAddr;
use std::str;
use std::sync::{Arc, Mutex};

use sqlx::PgPool;
use thrussh::server::{self, Auth, Session};
use thrussh::{ChannelId, CryptoVec};
use thrussh_keys::*;
use uuid::Uuid;

use rpc::forge::v0::UserRoles;

use crate::auth;
use crate::commands::command_handler;
use crate::ipmi::HostInfo;

const PROMPT: &str = "$ ";

mod ascii {
    pub const CTRL_C: u8 = 3;
    pub const CTRL_D: u8 = 4;
    pub const CR: u8 = 13;
    pub const BS: u8 = 127;
}

#[derive(Clone, Copy, Debug)]
pub enum TaskState {
    Init,
    Running,
    Cancelled,
}

#[derive(Clone, Debug)]
pub struct UserInfo {
    pub name: String,
    pub role: UserRoles,
}

// Create a server
#[derive(Clone)]
pub struct Server {
    _client_pubkey: Arc<thrussh_keys::key::PublicKey>,
    pub clients: Arc<Mutex<HashMap<(Uuid, ChannelId), thrussh::server::Handle>>>,
    pub id: Uuid,
    prompt: String,
    command: Vec<u8>,
    pub user: Option<UserInfo>,
    pub pool: PgPool,
    pub current_command: Option<String>,
    pub host_info: Option<HostInfo>,
    pub task_state: Arc<Mutex<TaskState>>,
    pub exec_mode: bool,
    pub under_test: bool,
}

impl Server {
    fn new_line(mut self, channel: ChannelId, mut session: Session) -> (Self, Session) {
        if self.exec_mode {
            return (self, session);
        }
        self.command.clear();
        session.data(channel, CryptoVec::from_slice(b"\r\n"));
        if let TaskState::Init = *self.task_state.lock().unwrap() {
            session.data(channel, CryptoVec::from(self.get_prompt()));
        }
        (self, session)
    }

    pub fn get_prompt(&self) -> String {
        if let Some(h) = &self.host_info {
            return format!("{}$ ", h.id.clone());
        }

        self.prompt.clone()
    }
}

impl server::Server for Server {
    type Handler = Self;
    fn new(&mut self, _: Option<std::net::SocketAddr>) -> Self {
        let s = self.clone();
        self.id = Uuid::new_v4();
        s
    }
}

// Create a handler
impl server::Handler for Server {
    type Error = anyhow::Error;
    type FutureAuth = futures::future::Ready<Result<(Self, Auth), anyhow::Error>>;
    type FutureUnit = futures::future::Ready<Result<(Self, Session), anyhow::Error>>;
    type FutureBool = futures::future::Ready<Result<(Self, Session, bool), anyhow::Error>>;

    fn finished_auth(self, auth: Auth) -> Self::FutureAuth {
        futures::future::ready(Ok((self, auth)))
    }

    fn finished_bool(self, b: bool, s: Session) -> Self::FutureBool {
        futures::future::ready(Ok((self, s, b)))
    }

    fn finished(self, s: Session) -> Self::FutureUnit {
        futures::future::ready(Ok((self, s)))
    }

    fn auth_publickey(mut self, user: &str, pubkey: &key::PublicKey) -> Self::FutureAuth {
        let validate_fn = if self.under_test {
            auth::validate_user_test
        } else {
            auth::validate_user
        };

        match validate_fn(user, pubkey) {
            Ok(role) => {
                self.user = Some(UserInfo {
                    name: user.to_string(),
                    role,
                })
            }
            Err(x) => {
                log::error!("Authentication failed for user {}: Error: {}", user, x);
                return self.finished_auth(server::Auth::Reject);
            }
        };
        self.finished_auth(server::Auth::Accept)
    }

    fn channel_open_session(
        mut self,
        channel: ChannelId,
        mut session: Session,
    ) -> Self::FutureUnit {
        {
            let mut clients = self.clients.lock().unwrap();
            clients.insert((self.id, channel), session.handle());
        }
        session.data(channel, CryptoVec::from(self.get_prompt()));
        self.task_state = Arc::new(Mutex::new(TaskState::Init));
        self.finished(session)
    }
    fn data(mut self, channel: ChannelId, data: &[u8], mut session: Session) -> Self::FutureUnit {
        for d in data {
            match *d {
                ascii::CR => {
                    let command = String::from_utf8(self.command.clone())
                        .unwrap()
                        .trim()
                        .to_string();

                    if !command.is_empty() && !self.exec_mode {
                        if command == "exit" {
                            session.close(channel);
                            break;
                        }

                        session.data(channel, CryptoVec::from_slice(b"\r\n"));
                        self.current_command = Some(command);
                        (self, session) = command_handler(self, channel, session);
                        self.current_command = None;
                    }
                    (self, session) = self.new_line(channel, session);
                }
                ascii::CTRL_C => {
                    {
                        let mut val = self.task_state.lock().unwrap();
                        if let TaskState::Running = *val {
                            *val = TaskState::Cancelled;
                        }
                    }
                    session.data(channel, CryptoVec::from("^C".to_string()));
                    (self, session) = self.new_line(channel, session);
                    break;
                }
                ascii::CTRL_D => {
                    session.close(channel);
                    break;
                }
                ascii::BS => {
                    if !self.command.is_empty() {
                        self.command.pop();
                        session.data(channel, CryptoVec::from_slice(b"\x08 \x08"));
                    }
                    break;
                }
                _ => {
                    if let TaskState::Init = *self.task_state.lock().unwrap() {
                        self.command.push(*d);
                        session.data(channel, CryptoVec::from((*d as char).to_string()));
                    }
                }
            }
        }
        self.finished(session)
    }

    // following handler is called if some one passes command with ssh command.
    // e.g. ssh user@forge "<machine-id>;sol
    // This is good for automation.
    fn exec_request(
        mut self,
        channel: ChannelId,
        data: &[u8],
        mut session: Session,
    ) -> Self::FutureUnit {
        let help = r#"Uses: ssh <user>@<server> "<machine-id>;<command>"
          e.g. ssh <user>@forge "uuid;power status""#;
        let commands = String::from(str::from_utf8(data).unwrap())
            .trim()
            .to_string();
        self.exec_mode = true;
        let commands = commands.split(';').collect::<Vec<&str>>();
        if commands.len() != 2 && Uuid::parse_str(commands[0]).is_err() {
            session.data(channel, CryptoVec::from(String::from(help)));
            session.close(channel);
            return self.finished(session);
        }

        // Connect to host.
        self.current_command = Some(format!("connect {}", commands[0]));
        (self, session) = command_handler(self, channel, session);

        if self.host_info.is_none() {
            session.close(channel);
        }

        // Execute command
        session.data(channel, CryptoVec::from(String::from("\r\n")));
        self.current_command = Some(String::from(commands[1]));
        (self, session) = command_handler(self, channel, session);
        self.current_command = None;

        self.finished(session)
    }
}

pub async fn run(pool: PgPool, address: SocketAddr) {
    let client_key = key::KeyPair::generate_ed25519().unwrap();
    let client_pubkey = Arc::new(client_key.clone_public_key());
    let config = server::Config {
        connection_timeout: None,
        auth_rejection_time: std::time::Duration::from_secs(10),
        keys: vec![key::KeyPair::generate_ed25519().unwrap()],
        ..Default::default()
    };

    let config = Arc::new(config);
    let sh = Server {
        _client_pubkey: client_pubkey,
        clients: Arc::new(Mutex::new(HashMap::new())),
        id: Uuid::new_v4(),
        user: None,
        prompt: PROMPT.to_string(),
        command: Vec::new(),
        pool,
        current_command: None,
        host_info: None,
        task_state: Arc::new(Mutex::new(TaskState::Init)),
        exec_mode: false,
        under_test: cfg!(test),
    };

    server::run(config, &address.to_string(), sh).await.unwrap();
}
