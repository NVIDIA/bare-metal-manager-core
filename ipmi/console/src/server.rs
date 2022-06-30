use crate::commands::command_handler;
use crate::ipmi::HostInfo;
use anyhow;
use futures;
use sqlx::PgPool;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use thrussh::server::{self, Auth, Session};
use thrussh::{ChannelId, CryptoVec};
use thrussh_keys::*;
use uuid::Uuid;

const PROMPT: &str = "$ ";

mod ascii {
    pub const CTRL_C: u8 = 3;
    pub const CTRL_D: u8 = 4;
    pub const CR: u8 = 13;
    pub const BS: u8 = 127;
}

#[derive(Clone, Copy)]
pub enum TaskState {
    INIT,
    RUNNING,
    CANCELLED,
}

// Create a server
#[derive(Clone)]
pub struct Server {
    _client_pubkey: Arc<thrussh_keys::key::PublicKey>,
    pub clients: Arc<Mutex<HashMap<(Uuid, ChannelId), thrussh::server::Handle>>>,
    pub id: Uuid,
    prompt: String,
    command: Vec<u8>,
    pub user: Option<String>,
    pub pool: PgPool,
    pub current_command: Option<String>,
    pub host_info: Option<HostInfo>,
    pub task_state: Arc<Mutex<TaskState>>,
}

impl Server {
    fn new_line(mut self, channel: ChannelId, mut session: Session) -> (Self, Session) {
        self.command.clear();
        session.data(channel, CryptoVec::from_slice(b"\r\n"));
        match *self.task_state.lock().unwrap() {
            TaskState::INIT => {
                session.data(channel, CryptoVec::from(self.get_prompt()));
            }
            _ => {}
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
    type FutureAuth = futures::future::Ready<Result<(Self, server::Auth), anyhow::Error>>;
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
        self.task_state = Arc::new(Mutex::new(TaskState::INIT));
        self.finished(session)
    }
    fn auth_publickey(mut self, user: &str, _: &key::PublicKey) -> Self::FutureAuth {
        //TODO: Create a list of whitelisted public keyss and validate.
        //TODO: ACL for user, what hosts he can manage.
        self.user = Some(user.to_string());
        self.finished_auth(server::Auth::Accept)
    }
    fn data(mut self, channel: ChannelId, data: &[u8], mut session: Session) -> Self::FutureUnit {
        for d in data {
            match *d {
                ascii::CR => {
                    let command = String::from_utf8(self.command.clone())
                        .unwrap()
                        .trim()
                        .to_string();

                    if command.len() > 0 {
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
                        match *val {
                            TaskState::RUNNING => {
                                *val = TaskState::CANCELLED;
                            }
                            _ => {}
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
                _ => match *self.task_state.lock().unwrap() {
                    TaskState::INIT => {
                        self.command.push(d.clone());
                        session.data(channel, CryptoVec::from((*d as char).to_string()));
                    }
                    _ => {}
                },
            }
        }
        self.finished(session)
    }
}

pub async fn run(pool: PgPool, address: SocketAddr) {
    let client_key = thrussh_keys::key::KeyPair::generate_ed25519().unwrap();
    let client_pubkey = Arc::new(client_key.clone_public_key());
    let mut config = thrussh::server::Config::default();
    config.connection_timeout = None;
    config.auth_rejection_time = std::time::Duration::from_secs(10);
    config
        .keys
        .push(thrussh_keys::key::KeyPair::generate_ed25519().unwrap());

    let config = Arc::new(config);
    let sh = Server {
        _client_pubkey: client_pubkey,
        clients: Arc::new(Mutex::new(HashMap::new())),
        id: Uuid::new_v4(),
        user: None,
        prompt: PROMPT.to_string().clone(),
        command: Vec::new(),
        pool: pool,
        current_command: None,
        host_info: None,
        task_state: Arc::new(Mutex::new(TaskState::INIT)),
    };

    thrussh::server::run(config, &address.to_string(), sh)
        .await
        .unwrap();
}
