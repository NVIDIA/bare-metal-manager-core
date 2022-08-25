use crate::IN_QEMU_VM;
use cli::CarbideClientError;
use cli::CarbideClientResult;
#[cfg(not(test))]
use log::{debug, error, info};

#[cfg(test)]
use std::{println as error, println as debug, println as info};

use rand::Rng;
use regex::Regex;
use rpc::forge::v0 as rpc;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fmt;
use std::process::Command;
use uuid::Uuid;

static PASSWORD_LEN: usize = 16;

//TODO: Remove the leading underscores from the variants once they're actually being referenced.
#[derive(Clone, Debug, Copy)]
enum IpmitoolRoles {
    _Callback = 0x1,
    User = 0x2,
    Operator = 0x3,
    Administrator = 0x4,
    _OEMProprietary = 0x5,
    _NoAccess = 0xF,
}

impl fmt::Display for IpmitoolRoles {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let str_val = match self {
            IpmitoolRoles::User => "user",
            IpmitoolRoles::Administrator => "administrator",
            IpmitoolRoles::Operator => "operator",
            _ => "noaccess",
        };

        write!(f, "{}", str_val)
    }
}

impl IpmitoolRoles {
    fn convert(&self) -> Result<rpc::UserRoles, CarbideClientError> {
        match self {
            IpmitoolRoles::User => Ok(rpc::UserRoles::User),
            IpmitoolRoles::Administrator => Ok(rpc::UserRoles::Administrator),
            IpmitoolRoles::Operator => Ok(rpc::UserRoles::Operator),
            _ => Err(CarbideClientError::GenericError(
                "Not implemented".to_string(),
            )),
        }
    }
}

#[derive(Clone, Debug)]
struct UsersList {
    user: &'static str,
    role: IpmitoolRoles,
}

static USERS: [UsersList; 3] = [
    UsersList {
        user: "forge_admin",
        role: IpmitoolRoles::Administrator,
    },
    UsersList {
        user: "forge_user",
        role: IpmitoolRoles::User,
    },
    UsersList {
        user: "forge_operator",
        role: IpmitoolRoles::Operator,
    },
];

#[derive(Debug)]
struct IpmiInfo {
    user: String,
    role: IpmitoolRoles,
    password: String,
}

impl IpmiInfo {
    fn convert(
        value: Vec<IpmiInfo>,
        uuid: &str,
        ip: String,
    ) -> Result<rpc::BmcMetaData, CarbideClientError> {
        let machine_id: rpc::Uuid = Uuid::parse_str(uuid)
            .map(|m| m.into())
            .map_err(|e| CarbideClientError::GenericError(e.to_string()))?;

        let mut bmc_meta_data = rpc::BmcMetaData {
            machine_id: Some(machine_id),
            ip,
            data: Vec::new(),
            request_type: rpc::BmcRequestType::Ipmi as i32,
        };

        for v in value {
            bmc_meta_data.data.push(rpc::bmc_meta_data::DataItem {
                user: v.user.clone(),
                password: v.password.clone(),
                role: v.role.convert()? as i32,
            });
        }

        Ok(bmc_meta_data)
    }
}

struct CMD {
    command: Command,
}

impl Default for CMD {
    fn default() -> Self {
        CMD {
            command: Command::new("ipmitool"),
        }
    }
}

impl CMD {
    fn args(mut self, args: Vec<&str>) -> Self {
        self.command.args(args);
        self
    }

    fn output(mut self) -> CarbideClientResult<String> {
        if cfg!(test) {
            return Ok("test string".to_string());
        }

        let output = self
            .command
            .output()
            .map_err(|x| CarbideClientError::GenericError(x.to_string()))?;

        if !output.status.success() {
            return Err(CarbideClientError::GenericError(format!(
                "Command {:?} with {:?} failed.",
                self.command.get_program(),
                self.command.get_args().collect::<Vec<&OsStr>>()
            )));
        }

        Ok(String::from_utf8(output.stdout)?)
    }
}

fn get_lan_print() -> CarbideClientResult<String> {
    if cfg!(test) {
        use std::fs;
        fs::read_to_string("test/lan_print.txt")
            .map_err(|x| cli::CarbideClientError::GenericError(x.to_string()))
    } else {
        CMD::default().args(vec!["lan", "print"]).output()
    }
}

fn fetch_ipmi_ip() -> CarbideClientResult<String> {
    let pattern = Regex::new("IP Address *: (.*?)$")?;
    info!("Fetching BMC IP Address.");
    let output = get_lan_print()?;
    let ip = output
        .lines()
        .filter_map(|line| pattern.captures(line))
        .map(|x| x[1].trim().to_string())
        .take(1)
        .collect::<Vec<String>>();

    if ip.is_empty() {
        error!("Could not find IP address. Output: {}", output);
        return Err(CarbideClientError::GenericError(
            "Could not find IP address.".to_string(),
        ));
    }
    Ok(ip[0].clone())
}

fn get_user_list() -> CarbideClientResult<String> {
    info!("Fetching current configured users list.");
    if cfg!(test) {
        use std::fs;
        Ok(fs::read_to_string("test/user_list.csv").unwrap())
    } else {
        CMD::default()
            .args(vec!["user", "list", "1", "-c"])
            .output()
    }
}

fn fetch_ipmi_users_and_free_ids() -> CarbideClientResult<(Vec<String>, HashMap<String, String>)> {
    let output = get_user_list()?;

    let free_ids = output
        .lines()
        .map(|x| x.split(",").collect::<Vec<&str>>())
        .filter(|x| x[1].to_string().is_empty())
        .map(|x| x[0].to_string())
        .collect::<Vec<String>>();

    // username: user_id mapping
    let user_to_id: HashMap<String, String> = output
        .lines()
        .map(|x| x.split(",").collect::<Vec<&str>>())
        .filter(|x| !x[1].to_string().is_empty())
        .map(|x| (x[1].to_string(), x[0].to_string()))
        .collect();

    Ok((free_ids, user_to_id))
}

fn create_ipmi_user(id: &String, user: &String) -> CarbideClientResult<()> {
    let _ = CMD::default()
        .args(vec!["user", "set", "name", id, user])
        .output()?;
    Ok(())
}

fn generate_password() -> String {
    const UPPERCHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const LOWERCHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
    const NUMCHARS: &[u8] = b"0123456789";
    const EXTRACHARS: &[u8] = b"^%$@!~_";
    const CHARSET: [&[u8]; 4] = [UPPERCHARS, LOWERCHARS, NUMCHARS, EXTRACHARS];

    let mut rng = rand::thread_rng();

    let password: String = (0..PASSWORD_LEN)
        .map(|_| {
            let chid = rng.gen_range(0..CHARSET.len());
            let idx = rng.gen_range(0..CHARSET[chid].len());
            CHARSET[chid][idx] as char
        })
        .collect();

    password
}

fn set_ipmi_password(id: &String) -> CarbideClientResult<String> {
    let password = generate_password();
    info!("Updating password for id {}", id);
    let _ = CMD::default()
        .args(vec!["user", "set", "password", id, &password])
        .output()?;
    debug!("Updated password {} for id {}", password, id);
    Ok(password)
}

fn set_ipmi_props(id: &String, role: IpmitoolRoles) -> CarbideClientResult<()> {
    info!("Setting privileges for id {}", id);
    let role = format!("privilege={}", role as u8);

    // Enable user
    let _ = CMD::default().args(vec!["user", "enable", id]).output()?;

    // Set user privilege and channel access
    let _ = CMD::default()
        .args(vec![
            "channel",
            "setaccess",
            "1",
            id,
            "callin=on",
            "ipmi=on",
            "link=on",
            &role,
        ])
        .output()?;

    // Enable TCP/LAN access
    let _ = CMD::default()
        .args(vec!["lan", "set", "1", "access", "on"])
        .output()?;

    Ok(())
}

fn set_ipmi_creds() -> CarbideClientResult<(Vec<IpmiInfo>, String)> {
    let ip = fetch_ipmi_ip()?;
    let (free_ids, user_to_id) = fetch_ipmi_users_and_free_ids()?;
    let mut user_lists: Vec<IpmiInfo> = Vec::new();

    for (pos, user_info) in USERS.iter().enumerate() {
        let user_name = user_info.user.to_string();
        let id = if let Some(user_id) = user_to_id.get(&user_name) {
            // User already exists.
            // Get Id
            info!(
                "User {} already exists. Only setting password and privileges.",
                user_name
            );
            user_id.clone()
        } else {
            // Create user and get id.
            if pos >= free_ids.len() {
                return Err(CarbideClientError::GenericError(format!(
                    "Not sufficient free ids to create user. Failed at pos: {} for user: {}",
                    pos, user_name
                )));
            }
            info!("Creating user {}", user_name);
            let free_id = free_ids[pos].clone();
            create_ipmi_user(&free_id, &user_name)?;
            free_id
        };

        let password = set_ipmi_password(&id)?;
        set_ipmi_props(&id, user_info.role)?;

        user_lists.push(IpmiInfo {
            user: user_name.clone(),
            role: user_info.role,
            password,
        })
    }

    Ok((user_lists, ip))
}

pub async fn update_ipmi_creds(listen: String, uuid: &str) -> CarbideClientResult<()> {
    if IN_QEMU_VM.read().unwrap().in_qemu {
        return Ok(());
    }

    let (ipmi_info, ip) = set_ipmi_creds()?;
    let bmc_metadata: rpc::BmcMetaData = IpmiInfo::convert(ipmi_info, uuid, ip)?;

    let mut client = rpc::forge_client::ForgeClient::connect(listen).await?;
    let request = tonic::Request::new(bmc_metadata);
    client.update_bmc_meta_data(request).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    static EXPECTED_IP: &str = "127.0.0.2";

    #[tokio::test]
    async fn test_ipmi_ip() {
        assert_eq!(&fetch_ipmi_ip().unwrap(), EXPECTED_IP)
    }

    #[tokio::test]
    async fn test_ipmi_cred() {
        let (responses, ip) = set_ipmi_creds().unwrap();
        assert_eq!(&ip, EXPECTED_IP);
        for response in responses {
            assert_eq!(response.password.len(), PASSWORD_LEN);
        }
    }
}
