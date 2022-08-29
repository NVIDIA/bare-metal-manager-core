use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::sync::{Arc, Mutex};

use futures::executor::block_on;
use lazy_static::lazy_static;
use sqlx::PgPool;
use thrussh::server::{Handle, Session};
use thrussh::{ChannelId, CryptoVec};
use tokio::sync::mpsc::channel;
use tokio::time;
use uuid::Uuid;

use carbide::{bg::Status, ipmi, CarbideError, CarbideResult};
use console::ConsoleError;
use rpc::forge::v0::UserRoles;

use crate::ipmi::{HostInfo, IpmiInfo};
use crate::server::{Server, TaskState};

struct AsyncWrapper {}

type CHandler = fn(server: Server, channel: ChannelId, session: Session) -> (Server, Session);

lazy_static! {
    static ref COMMAND_HANDLER: HashMap<&'static str, CHandler> = {
        let mut map = HashMap::new();
        map.insert("connect", connect_handler as CHandler);
        map.insert("disconnect", disconnect_handler as CHandler);
        map.insert("power", power_handler as CHandler);
        map.insert("status", status_handler as CHandler);
        map.insert("sol", sol_handler as CHandler);

        map
    };
}

//TODO: remove this when clippy isn't stupid about this
#[allow(clippy::needless_collect)]
fn disconnect_handler(
    mut server: Server,
    channel: ChannelId,
    mut session: Session,
) -> (Server, Session) {
    let help = "Syntax: disconnect".to_string();
    let command = server.current_command.clone().unwrap();
    //TODO: would split_whitespace work here?
    let command = command.split(' ').collect::<Vec<&str>>();
    if command.len() != 1 {
        session.data(channel, CryptoVec::from(help));
        return (server, session);
    }

    match server.host_info {
        Some(_) => {
            server.host_info = None;
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

    (server, session)
}

fn connect_handler(
    mut server: Server,
    channel: ChannelId,
    mut session: Session,
) -> (Server, Session) {
    let help = "Syntax: connect <machine_id>".to_string();
    let command = server.current_command.clone().unwrap();
    let command = command.split(' ').collect::<Vec<&str>>();
    if command.len() != 2 {
        session.data(channel, CryptoVec::from(help));
        return (server, session);
    }
    let role = server.user.clone().unwrap().role;

    if server.host_info.is_some() {
        server.host_info = None;
    }

    match AsyncWrapper::get_host_details(role, command[1].to_string()) {
        Ok(x) => {
            session.data(
                channel,
                CryptoVec::from(format!("Connected to host: {}", command[1])),
            );
            server.host_info = Some(x);
        }
        Err(x) => {
            session.data(
                channel,
                CryptoVec::from(format!("Connect failed. Error: {}", x)),
            );
        }
    };

    (server, session)
}

fn power_handler(
    mut server: Server,
    channel: ChannelId,
    mut session: Session,
) -> (Server, Session) {
    let possible_commands: [&str; 5] = ["up", "down", "reset", "cycle", "status"];
    let help = format!("Syntax: power <{}>", possible_commands.join("/"));
    let command = server.current_command.clone().unwrap();
    let command = command.split(' ').collect::<Vec<&str>>();
    if command.len() != 2 || !possible_commands.contains(&command[1]) {
        session.data(channel, CryptoVec::from(help));
        return (server, session);
    }

    if let Err(err) = validate_host_info(&server) {
        session.data(channel, CryptoVec::from(err.to_string()));
        return (server, session);
    }
    server = AsyncWrapper::handle_power_command(server, channel, command[1].to_string());
    (server, session)
}

fn status_handler(
    mut server: Server,
    channel: ChannelId,
    mut session: Session,
) -> (Server, Session) {
    if let Err(err) = validate_host_info(&server) {
        session.data(channel, CryptoVec::from(err.to_string()));
        return (server, session);
    }
    server = AsyncWrapper::handle_power_command(server, channel, "status".to_string());
    (server, session)
}

fn sol_handler(mut server: Server, channel: ChannelId, mut session: Session) -> (Server, Session) {
    let command = server.current_command.clone().unwrap();
    let command = command.split(' ').collect::<Vec<&str>>();
    let force = command.len() == 2 && command[1] == "force";

    if let Err(err) = validate_host_info(&server) {
        session.data(channel, CryptoVec::from(err.to_string()));
        return (server, session);
    }
    server = AsyncWrapper::handle_sol_command(server, channel, force);
    (server, session)
}

fn validate_host_info(server: &Server) -> Result<(), Error> {
    if server.host_info.is_none() {
        return Err(Error::new(
            ErrorKind::Other,
            "Host info is not available. Execute 'connect <machine_id>' first.",
        ));
    }

    let ipmi_info = server.host_info.clone().unwrap().ipmi_info;

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

// AsyncWrapper is using tokio::task::spawn_blocking to process command in separate thread.
// Tokio has limitation of 500 blocking thread only.
// Please note that this is parallel running commands, not parallel user sessions.
// In case 500 limit is not enough, we can replace spawn_blocking with standard thread.
// Before doing so, just think about load on server.
impl AsyncWrapper {
    fn get_host_details(role: UserRoles, data: String) -> Result<HostInfo, ConsoleError> {
        let (tx, mut rx) = channel(10);
        tokio::task::spawn_blocking(move || {
            tokio::spawn(async move {
                let host_info = HostInfo::new(data, role).await;
                let _ = tx.send(host_info).await;
            });
        });

        block_on(async {
            match rx.recv().await {
                Some(x) => x,
                None => Err(ConsoleError::GenericError(
                    "Error in getting data.".to_string(),
                )),
            }
        })
    }

    fn handle_power_command(server: Server, channel: ChannelId, data: String) -> Server {
        let clients = server.clients.clone();
        let task_state = server.task_state.clone();
        let ipmi_info = server.host_info.clone().unwrap().ipmi_info.unwrap();
        let pool = server.pool.clone();
        let prompt = server.get_prompt();
        let exec_mode = server.exec_mode;
        *task_state.lock().unwrap() = TaskState::Running;
        tokio::task::spawn_blocking(move || {
            tokio::spawn(async move {
                let mut handle: Handle;
                {
                    let mut clients = clients.lock().unwrap();
                    handle = clients.get_mut(&(server.id, channel)).unwrap().clone();
                }

                let job_id = call_ipmi_api(ipmi_info, data, pool.clone()).await;
                if job_id.is_err() {
                    util::end_task(task_state, prompt, channel, handle, exec_mode).await;
                    return;
                }

                let job_id = job_id.unwrap();
                let mut task_cancelled: bool = false;

                loop {
                    if Status::is_finished(&pool, job_id).await.unwrap() {
                        break;
                    }
                    //TODO: it is likely an error to be using a synchronous lock in an async fn.
                    if let TaskState::Cancelled = *task_state.lock().unwrap() {
                        task_cancelled = true;
                        break;
                    }
                    time::sleep(time::Duration::from_millis(200)).await;
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
                util::end_task(task_state, prompt, channel, handle, exec_mode).await;
            });
        });

        server
    }

    fn handle_sol_command(server: Server, channel: ChannelId, _force: bool) -> Server {
        let clients = server.clients.clone();
        let task_state = server.task_state.clone();
        let _ipmi_info = server.host_info.clone().unwrap().ipmi_info.unwrap();
        let prompt = server.get_prompt();
        let exec_mode = server.exec_mode;
        *task_state.lock().unwrap() = TaskState::Running;
        tokio::task::spawn_blocking(move || {
            tokio::spawn(async move {
                let mut handle: Handle;
                {
                    let mut clients = clients.lock().unwrap();
                    handle = clients.get_mut(&(server.id, channel)).unwrap().clone();
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
                    if let TaskState::Cancelled = *task_state.lock().unwrap() {
                        break;
                    }
                }

                util::end_task(task_state, prompt, channel, handle, exec_mode).await;
            });
        });

        server
    }
}

pub fn command_handler(
    server: Server,
    channel: ChannelId,
    mut session: Session,
) -> (Server, Session) {
    let help = format!(
        "Possible commands: {}",
        COMMAND_HANDLER
            .keys()
            .map(|s| &**s)
            .collect::<Vec<&str>>()
            .join(", ")
    );

    // Add audit data here.
    if server.current_command.is_none() {
        log::error!("No idea how got a empty current_command.");
        return (server, session);
    }

    let command = server.current_command.clone().unwrap();
    let command = command.split(' ').collect::<Vec<&str>>()[0];

    if command == "?" || command == "help" {
        session.data(channel, CryptoVec::from(help));
        return (server, session);
    }

    if !COMMAND_HANDLER.contains_key(command) {
        session.data(
            channel,
            CryptoVec::from(format!("Unknown Command: {}\r\n", command)),
        );
        session.data(channel, CryptoVec::from(help));
        return (server, session);
    }

    COMMAND_HANDLER[&command](server, channel, session)
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
        *task_state.lock().unwrap() = TaskState::Init;
        if exec_mode {
            let _ = handle.close(channel);
            return handle;
        }
        new_line(prompt, channel, handle).await
    }
}
