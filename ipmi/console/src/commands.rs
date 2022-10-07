use std::io::{Error, ErrorKind};
use std::sync::Arc;

use sqlx::PgPool;
use thrussh::server::{Handle, Session};
use thrussh::{ChannelId, CryptoVec};
use tokio::sync::Mutex;
use tokio::time;
use tonic::async_trait;
use uuid::Uuid;

use carbide::{bg::Status, ipmi, CarbideError, CarbideResult};

use crate::auth::UserValidator;
use crate::ipmi::{HostInfo, IpmiInfo};
use crate::server::{Server, ServerInfo, TaskState};

#[async_trait]
pub trait CommandHandler: Send + Sync {
    async fn handle_command(
        &self,
        server_info: ServerInfo,
        channel: ChannelId,
        session: Session,
    ) -> (ServerInfo, Session);
}

#[derive(Clone)]
pub struct DisconnectHandler {}

#[async_trait]
impl CommandHandler for DisconnectHandler {
    async fn handle_command(
        &self,
        mut server_info: ServerInfo,
        channel: ChannelId,
        mut session: Session,
    ) -> (ServerInfo, Session) {
        let help = "Syntax: disconnect".to_string();
        let command = server_info.current_command.clone().unwrap();
        let command_count = command.split(' ').count();
        if command_count != 1 {
            session.data(channel, CryptoVec::from(help));
            return (server_info, session);
        }

        match server_info.host_info {
            Some(_) => {
                server_info.host_info = None;
                session.data(
                    channel,
                    CryptoVec::from(String::from("Host is disconnected successfully.")),
                );
            }
            None => {
                session.data(
                    channel,
                    CryptoVec::from(String::from("No host is connected.")),
                );
            }
        }

        (server_info, session)
    }
}

#[derive(Clone)]
pub struct ConnectHandler {}

#[async_trait]
impl CommandHandler for ConnectHandler {
    async fn handle_command(
        &self,
        mut server_info: ServerInfo,
        channel: ChannelId,
        mut session: Session,
    ) -> (ServerInfo, Session) {
        let help = "Syntax: connect <machine_id>".to_string();
        let command = server_info.current_command.clone().unwrap();
        let command = command.split(' ').collect::<Vec<&str>>();
        if command.len() != 2 {
            session.data(channel, CryptoVec::from(help));
            return (server_info, session);
        }
        let role = server_info.user.clone().unwrap().role;

        if server_info.host_info.is_some() {
            server_info.host_info = None;
        }

        let api_endpoint = server_info.console_context.api_endpoint.clone();

        match HostInfo::new(command[1].to_string(), role, api_endpoint).await {
            Ok(x) => {
                session.data(
                    channel,
                    CryptoVec::from(format!("Connected to host: {}", command[1])),
                );
                server_info.host_info = Some(x);
            }
            Err(x) => {
                session.data(
                    channel,
                    CryptoVec::from(format!("Connect failed. Error: {}", x)),
                );
            }
        };

        (server_info, session)
    }
}

#[derive(Clone)]
pub struct PowerHandler {}

#[async_trait]
impl CommandHandler for PowerHandler {
    async fn handle_command(
        &self,
        mut server_info: ServerInfo,
        channel: ChannelId,
        mut session: Session,
    ) -> (ServerInfo, Session) {
        let possible_commands: [&str; 5] = ["up", "down", "reset", "cycle", "status"];
        let help = format!("Syntax: power <{}>", possible_commands.join("/"));
        let command = server_info.current_command.clone().unwrap();
        let command = command.split(' ').collect::<Vec<&str>>();
        if command.len() != 2 || !possible_commands.contains(&command[1]) {
            session.data(channel, CryptoVec::from(help));
            return (server_info, session);
        }

        if let Err(err) = validate_host_info(&server_info) {
            session.data(channel, CryptoVec::from(err.to_string()));
            return (server_info, session);
        }

        server_info = handle_power_command(server_info, channel, command[1].to_string()).await;
        (server_info, session)
    }
}

#[derive(Clone)]
pub struct StatusHandler {}

#[async_trait]
impl CommandHandler for StatusHandler {
    async fn handle_command(
        &self,
        mut server_info: ServerInfo,
        channel: ChannelId,
        mut session: Session,
    ) -> (ServerInfo, Session) {
        if let Err(err) = validate_host_info(&server_info) {
            session.data(channel, CryptoVec::from(err.to_string()));
            return (server_info, session);
        }
        server_info = handle_power_command(server_info, channel, "status".to_string()).await;
        (server_info, session)
    }
}

#[derive(Clone)]
pub struct SolHandler {}

#[async_trait]
impl CommandHandler for SolHandler {
    async fn handle_command(
        &self,
        server_info: ServerInfo,
        channel: ChannelId,
        mut session: Session,
    ) -> (ServerInfo, Session) {
        let command = server_info.current_command.clone().unwrap();
        let command = command.split(' ').collect::<Vec<&str>>();

        //TODO: either implement something that uses this or remove it
        let _force = command.len() == 2 && command[1] == "force";

        if let Err(err) = validate_host_info(&server_info) {
            session.data(channel, CryptoVec::from(err.to_string()));
            return (server_info, session);
        }

        let task_state = server_info.task_state.clone();
        let prompt = server_info.get_prompt();
        let exec_mode = server_info.exec_mode;
        let clients = server_info.clients.clone();
        {
            *task_state.lock().await = TaskState::Running;
        }
        tokio::spawn(async move {
            let mut handle: Handle;
            {
                let mut clients = clients.lock().await;
                handle = clients.get_mut(&(server_info.id, channel)).unwrap().clone();
            }

            loop {
                // Ipmi sol read logic comes here.
                // It should be non blocking based on some timeout.
                // if ipmi.read(buf, timeout) != error {
                //   handle.data(buf);
                // } else {
                //   handle.data("connect closed by host: error:");
                //   break
                // }
                time::sleep(time::Duration::from_millis(500)).await;
                let _ = handle
                    .data(
                        channel,
                        CryptoVec::from("Here is sol text.\r\n".to_string()),
                    )
                    .await;
                if let TaskState::Cancelled = *task_state.lock().await {
                    break;
                }
            }

            util::end_task(task_state, prompt, channel, handle, exec_mode).await;
        });

        (server_info, session)
    }
}

fn validate_host_info(server_info: &ServerInfo) -> Result<(), Error> {
    if server_info.host_info.is_none() {
        return Err(Error::new(
            ErrorKind::Other,
            "Host info is not available. Execute 'connect <machine_id>' first.",
        ));
    }

    let ipmi_info = server_info.host_info.clone().unwrap().ipmi_info;

    if ipmi_info.is_none() {
        return Err(Error::new(
            ErrorKind::Other,
            "IPMI info is not available. Contact administrator for updating IPMI details.",
        ));
    }

    Ok(())
}

async fn call_ipmi_api(ipmi_info: IpmiInfo, data: String, pool: PgPool) -> CarbideResult<Uuid> {
    let ipmi_command =
        ipmi::IpmiCommand::new(ipmi_info.ip.to_string(), ipmi_info.user, ipmi_info.password);

    match data.trim() {
        "up" => ipmi_command.power_up(&pool).await,
        "down" => ipmi_command.power_down(&pool).await,
        "reset" => ipmi_command.power_reset(&pool).await,
        "cycle" => ipmi_command.power_cycle(&pool).await,
        "status" => ipmi_command.ipmi_status(&pool).await,
        _ => Err(CarbideError::GenericError("Unknown Command.".to_string())),
    }
}

async fn handle_power_command(
    server_info: ServerInfo,
    channel: ChannelId,
    data: String,
) -> ServerInfo {
    let task_state = server_info.task_state.clone();
    let ipmi_info = server_info.host_info.clone().unwrap().ipmi_info.unwrap();
    let pool = server_info.pool.clone();
    let clients = server_info.clients.clone();
    let prompt = server_info.get_prompt();
    let exec_mode = server_info.exec_mode;
    {
        *task_state.lock().await = TaskState::Running;
    }
    tokio::spawn(async move {
        let mut handle: Handle;
        {
            let mut clients = clients.lock().await;
            handle = clients.get_mut(&(server_info.id, channel)).unwrap().clone();
        }

        if let Ok(job_id) = call_ipmi_api(ipmi_info, data, pool.clone()).await {
            let mut task_cancelled: bool = false;
            loop {
                if Status::is_finished(&pool, job_id).await.unwrap() {
                    break;
                }
                if let TaskState::Cancelled = *task_state.lock().await {
                    task_cancelled = true;
                    break;
                }
                time::sleep(time::Duration::from_millis(500)).await;
            }

            match Status::poll(&pool, job_id).await {
                Ok(fs) => {
                    let _ = handle
                        .data(channel, CryptoVec::from(fs.msg.trim().to_string()))
                        .await;
                }
                Err(x) => {
                    if !task_cancelled {
                        let _ = handle.data(channel, CryptoVec::from(x.to_string())).await;
                    }
                }
            };
        }
        util::end_task(task_state, prompt, channel, handle, exec_mode).await;
    });
    server_info
}

// TODO: the next pattern to clean up is the one where we pass objects and then return them.
// we should just be passing &mut objects as arguments.
// The *entire* return value here is unnecessary.
pub async fn command_handler<V>(
    mut server: Server<V>,
    channel: ChannelId,
    mut session: Session,
) -> (Server<V>, Session)
where
    V: Send + Sync + UserValidator,
{
    let help = format!(
        "Possible commands: {}",
        server
            .handlers
            .keys()
            .map(|s| &**s)
            .collect::<Vec<&str>>()
            .join(", ")
    );

    // Add audit data here.
    if server.server_info.current_command.is_none() {
        log::error!("No idea how got a empty current_command.");
        return (server, session);
    }

    let command = server.server_info.current_command.clone().unwrap();
    let command = command.split(' ').collect::<Vec<&str>>()[0];

    if command == "?" || command == "help" {
        session.data(channel, CryptoVec::from(help));
        return (server, session);
    }

    match server.handlers.get(command.to_string().as_str()) {
        Some(handler) => {
            let (server_info, session) = handler
                .handle_command(server.server_info, channel, session)
                .await;
            server.server_info = server_info;
            (server, session)
        }
        None => {
            session.data(
                channel,
                CryptoVec::from(format!("Unknown Command: {}\r\n", command)),
            );
            session.data(channel, CryptoVec::from(help));
            (server, session)
        }
    }
}

mod util {
    use super::*;

    async fn new_line(prompt: String, channel: ChannelId, mut handle: Handle) -> Handle {
        let _ = handle.data(channel, CryptoVec::from_slice(b"\r\n")).await;
        let _ = handle.data(channel, CryptoVec::from(prompt)).await;
        handle
    }

    pub async fn end_task(
        task_state: Arc<Mutex<TaskState>>,
        prompt: String,
        channel: ChannelId,
        mut handle: Handle,
        exec_mode: bool,
    ) -> Handle {
        *task_state.lock().await = TaskState::Init;
        if exec_mode {
            let _ = handle.close(channel);
            return handle;
        }
        new_line(prompt, channel, handle).await
    }
}
