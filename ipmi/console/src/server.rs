use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::str;
use std::sync::Arc;

use sqlx::PgPool;
use thrussh::server::{self, Auth, Session};
use thrussh::{ChannelId, CryptoVec};
use thrussh_keys::key::PublicKey;
use thrussh_keys::*;
use tokio::sync::Mutex;
use uuid::Uuid;

use rpc::forge::UserRoles;

use crate::auth::UserValidator;
use crate::commands::{
    command_handler, CommandHandler, ConnectHandler, DisconnectHandler, PowerHandler, SolHandler,
    StatusHandler,
};
use crate::ipmi::HostInfo;
use crate::ConsoleContext;

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

#[derive(Clone)]
pub struct ServerInfo {
    _client_pubkey: Arc<key::PublicKey>,
    pub clients: Arc<Mutex<HashMap<(Uuid, ChannelId), server::Handle>>>,
    pub id: Uuid,
    prompt: String,
    command: Vec<u8>,
    pub user: Option<UserInfo>,
    pub pool: PgPool,
    pub current_command: Option<String>,
    pub host_info: Option<HostInfo>,
    pub task_state: Arc<Mutex<TaskState>>,
    pub exec_mode: bool,
    pub(crate) console_context: ConsoleContext,
}

impl ServerInfo {
    async fn new_line(mut self, channel: ChannelId, mut session: Session) -> (Self, Session) {
        if self.exec_mode {
            return (self, session);
        }
        self.command.clear();
        session.data(channel, CryptoVec::from_slice(b"\r\n"));
        if let TaskState::Init = *self.task_state.lock().await {
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

#[derive(Clone)]
pub struct Server<V>
where
    V: UserValidator + Send + Sync,
{
    pub(crate) server_info: ServerInfo,
    user_validator: V,
    pub handlers: HashMap<String, Arc<dyn CommandHandler>>,
}

impl<V> Server<V>
where
    V: UserValidator + Send + Sync,
{
    async fn new_line(mut self, channel: ChannelId, session: Session) -> (Self, Session) {
        let (server_info, session) = self.server_info.new_line(channel, session).await;
        self.server_info = server_info;
        (self, session)
    }

    pub fn get_prompt(&self) -> String {
        self.server_info.get_prompt()
    }

    async fn channel_open_session(
        mut self,
        channel: ChannelId,
        mut session: Session,
    ) -> Result<(Self, Session), anyhow::Error> {
        {
            let mut clients = self.server_info.clients.lock().await;
            clients.insert((self.server_info.id, channel), session.handle());
        }
        session.data(channel, CryptoVec::from(self.get_prompt()));
        self.server_info.task_state = Arc::new(Mutex::new(TaskState::Init));
        Ok((self, session))
    }

    async fn data(
        mut self,
        channel: ChannelId,
        data: Vec<u8>,
        mut session: Session,
    ) -> Result<(Self, Session), anyhow::Error> {
        for d in data {
            match d {
                ascii::CR => {
                    let command = String::from_utf8(self.server_info.command.clone())
                        .unwrap()
                        .trim()
                        .to_string();

                    if !command.is_empty() && !self.server_info.exec_mode {
                        if command == "exit" {
                            session.close(channel);
                            break;
                        }

                        session.data(channel, CryptoVec::from_slice(b"\r\n"));
                        self.server_info.current_command = Some(command);
                        (self, session) = command_handler(self, channel, session).await;
                        self.server_info.current_command = None;
                    }
                    (self, session) = self.new_line(channel, session).await;
                }
                ascii::CTRL_C => {
                    {
                        let mut val = self.server_info.task_state.lock().await;
                        if let TaskState::Running = *val {
                            *val = TaskState::Cancelled;
                        }
                    }
                    session.data(channel, CryptoVec::from("^C".to_string()));
                    (self, session) = self.new_line(channel, session).await;
                    break;
                }
                ascii::CTRL_D => {
                    session.close(channel);
                    break;
                }
                ascii::BS => {
                    if !self.server_info.command.is_empty() {
                        self.server_info.command.pop();
                        session.data(channel, CryptoVec::from_slice(b"\x08 \x08"));
                    }
                    break;
                }
                _ => {
                    if let TaskState::Init = *self.server_info.task_state.lock().await {
                        self.server_info.command.push(d);
                        session.data(channel, CryptoVec::from((d as char).to_string()));
                    }
                }
            }
        }

        Ok((self, session))
    }

    async fn exec_request(
        mut self,
        channel: ChannelId,
        commands: String,
        mut session: Session,
    ) -> Result<(Self, Session), anyhow::Error> {
        let help = r#"Uses: ssh <user>@<server> "<machine-id>;<command>"
          e.g. ssh <user>@forge "uuid;power status""#;
        self.server_info.exec_mode = true;
        let commands = commands.split(';').collect::<Vec<&str>>();
        if commands.len() != 2 && Uuid::parse_str(commands[0]).is_err() {
            session.data(channel, CryptoVec::from(String::from(help)));
            session.close(channel);
            return Ok((self, session));
        }

        // Connect to host.
        self.server_info.current_command = Some(format!("connect {}", commands[0]));
        (self, session) = command_handler(self, channel, session).await;

        if self.server_info.host_info.is_none() {
            session.close(channel);
        }

        // Execute command
        session.data(channel, CryptoVec::from(String::from("\r\n")));
        self.server_info.current_command = Some(String::from(commands[1]));
        (self, session) = command_handler(self, channel, session).await;
        self.server_info.current_command = None;

        Ok((self, session))
    }

    async fn auth_publickey(
        mut self,
        user: String,
        pubkey: PublicKey,
    ) -> Result<(Self, Auth), anyhow::Error> {
        let auth = match self
            .user_validator
            .validate_user(user.as_str(), &pubkey, &self.server_info.console_context)
            .await
        {
            Ok(role) => {
                self.server_info.user = Some(UserInfo {
                    name: user.clone(),
                    role,
                });
                Auth::Accept
            }
            Err(console_err) => {
                log::error!(
                    "Authentication failed for user {}: Error: {}",
                    user,
                    console_err
                );
                Auth::Reject
            }
        };

        Ok((self, auth))
    }
}

impl<V> server::Server for Server<V>
where
    V: Send + Sync + UserValidator + Clone + 'static,
{
    type Handler = Self;
    fn new(&mut self, _peer_addr: Option<SocketAddr>) -> Self {
        let s = self.clone();
        self.server_info.id = Uuid::new_v4();
        s
    }
}

impl<V> server::Handler for Server<V>
where
    V: Send + Sync + UserValidator + Clone + 'static,
{
    type Error = anyhow::Error;
    type FutureAuth = Pin<Box<dyn Future<Output = Result<(Self, Auth), Self::Error>> + Send>>;
    type FutureUnit = Pin<Box<dyn Future<Output = Result<(Self, Session), Self::Error>> + Send>>;
    type FutureBool =
        Pin<Box<dyn Future<Output = Result<(Self, Session, bool), Self::Error>> + Send>>;

    fn finished_auth(self, auth: Auth) -> Self::FutureAuth {
        Box::pin(futures::future::ready(Ok((self, auth))))
    }

    fn finished_bool(self, b: bool, s: Session) -> Self::FutureBool {
        Box::pin(futures::future::ready(Ok((self, s, b))))
    }

    fn finished(self, s: Session) -> Self::FutureUnit {
        Box::pin(futures::future::ready(Ok((self, s))))
    }

    fn auth_publickey(self, user: &str, pubkey: &PublicKey) -> Self::FutureAuth {
        //lifetime shenanigans because pubkey doesn't implement Clone...
        let pubkey = parse_public_key_base64(pubkey.public_key_base64().as_str()).unwrap();
        Box::pin(self.auth_publickey(user.to_string(), pubkey))
    }

    fn channel_open_session(self, channel: ChannelId, session: Session) -> Self::FutureUnit {
        Box::pin(self.channel_open_session(channel, session))
    }

    fn data(self, channel: ChannelId, data: &[u8], session: Session) -> Self::FutureUnit {
        Box::pin(self.data(channel, data.to_vec(), session))
    }

    // following handler is called if some one passes command with ssh command.
    // e.g. ssh user@forge "<machine-id>;sol
    // This is good for automation.
    fn exec_request(self, channel: ChannelId, data: &[u8], session: Session) -> Self::FutureUnit {
        let data = data.to_vec();
        Box::pin(async move {
            let string_data = String::from_utf8(data)?;
            let commands = string_data.trim().to_string();
            self.exec_request(channel, commands, session).await
        })
    }
}

pub async fn run<V>(
    pool: PgPool,
    address: SocketAddr,
    console_context: ConsoleContext,
    user_validator: V,
) where
    V: Send + Sync + UserValidator + 'static + Clone,
{
    let client_key = key::KeyPair::generate_ed25519().unwrap();
    let client_pubkey = Arc::new(client_key.clone_public_key());
    let config = server::Config {
        connection_timeout: None,
        auth_rejection_time: std::time::Duration::from_secs(10),
        keys: vec![key::KeyPair::generate_ed25519().unwrap()],
        ..Default::default()
    };

    let config = Arc::new(config);
    let handlers = HashMap::from([
        (
            "connect".to_string(),
            Arc::new(ConnectHandler {}) as Arc<dyn CommandHandler>,
        ),
        (
            "disconnect".to_string(),
            Arc::new(DisconnectHandler {}) as Arc<dyn CommandHandler>,
        ),
        (
            "power".to_string(),
            Arc::new(PowerHandler {}) as Arc<dyn CommandHandler>,
        ),
        (
            "status".to_string(),
            Arc::new(StatusHandler {}) as Arc<dyn CommandHandler>,
        ),
        (
            "sol".to_string(),
            Arc::new(SolHandler {}) as Arc<dyn CommandHandler>,
        ),
    ]);
    let sh = Server {
        server_info: ServerInfo {
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
            console_context,
        },
        user_validator,
        handlers,
    };

    server::run(config, &address.to_string(), sh).await.unwrap();
}
