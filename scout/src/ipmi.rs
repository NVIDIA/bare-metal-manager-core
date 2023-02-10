/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::collections::{HashMap, VecDeque};
use std::ffi::OsStr;
use std::fmt;
use std::process::Command;
use std::time::Instant;

use ::rpc::forge as rpc;
use rand::Rng;
use regex::Regex;
use tokio::time::{sleep, Duration};

use crate::CarbideClientError;
use crate::CarbideClientResult;
use crate::IN_QEMU_VM;

const PASSWORD_LEN: usize = 16;

//TODO: Remove the leading underscores from the variants once they're actually being referenced.
#[derive(Clone, Debug, Copy)]
enum IpmitoolRoles {
    _Callback = 0x1,
    _User = 0x2,
    _Operator = 0x3,
    Administrator = 0x4,
    _OEMProprietary = 0x5,
    _NoAccess = 0xF,
}

impl fmt::Display for IpmitoolRoles {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let str_val = match self {
            IpmitoolRoles::_User => "user",
            IpmitoolRoles::Administrator => "administrator",
            IpmitoolRoles::_Operator => "operator",
            _ => "noaccess",
        };

        write!(f, "{}", str_val)
    }
}

impl IpmitoolRoles {
    fn convert(&self) -> Result<rpc::UserRoles, CarbideClientError> {
        match self {
            IpmitoolRoles::_User => Ok(rpc::UserRoles::User),
            IpmitoolRoles::Administrator => Ok(rpc::UserRoles::Administrator),
            IpmitoolRoles::_Operator => Ok(rpc::UserRoles::Operator),
            _ => Err(CarbideClientError::GenericError(
                "Not implemented".to_string(),
            )),
        }
    }
}

const FORGE_ADMIN_USER_NAME: &str = "forge_admin";

#[derive(Debug)]
struct IpmiInfo {
    user: String,
    role: IpmitoolRoles,
    password: String,
}

impl IpmiInfo {
    fn convert(
        value: Vec<IpmiInfo>,
        machine_id: uuid::Uuid,
        ip: String,
    ) -> Result<rpc::BmcMetaDataUpdateRequest, CarbideClientError> {
        let mut bmc_meta_data = rpc::BmcMetaDataUpdateRequest {
            machine_id: Some(machine_id.into()),
            ip,
            data: Vec::new(),
            request_type: rpc::BmcRequestType::Ipmi as i32,
        };

        for v in value {
            bmc_meta_data
                .data
                .push(rpc::bmc_meta_data_update_request::DataItem {
                    user: v.user.clone(),
                    password: v.password.clone(),
                    role: v.role.convert()? as i32,
                });
        }

        Ok(bmc_meta_data)
    }
}

struct Cmd {
    command: Command,
}

impl Default for Cmd {
    fn default() -> Self {
        Cmd {
            command: Command::new("ipmitool"),
        }
    }
}

impl Cmd {
    pub fn new<S: AsRef<OsStr>>(program: S) -> Self {
        Self {
            command: Command::new(program),
        }
    }

    fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
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
            return Err(CarbideClientError::subprocess_error(&self.command, &output));
        }

        String::from_utf8(output.stdout).map_err(|_| {
            CarbideClientError::GenericError(format!(
                "Result of IPMI command {:?} with args {:?} is invalid UTF8",
                self.command.get_program(),
                self.command.get_args().collect::<Vec<&OsStr>>()
            ))
        })
    }
}

fn get_lan_print() -> CarbideClientResult<String> {
    if cfg!(test) {
        std::fs::read_to_string("test/lan_print.txt")
            .map_err(|x| CarbideClientError::GenericError(x.to_string()))
    } else {
        Cmd::default().args(vec!["lan", "print"]).output()
    }
}

fn fetch_ipmi_ip() -> CarbideClientResult<String> {
    let pattern = Regex::new("IP Address *: (.*?)$")?;
    log::info!("Fetching BMC IP Address.");
    let output = get_lan_print()?;
    let ip = output
        .lines()
        .filter_map(|line| pattern.captures(line))
        .map(|x| x[1].trim().to_string())
        .take(1)
        .collect::<Vec<String>>();

    if ip.is_empty() {
        log::error!("Could not find IP address. Output: {}", output);
        return Err(CarbideClientError::GenericError(
            "Could not find IP address.".to_string(),
        ));
    }
    Ok(ip[0].clone())
}

fn get_user_list(test_list: Option<&str>) -> CarbideClientResult<String> {
    log::info!("Fetching current configured users list.");
    if let Some(test_list) = test_list {
        use std::fs;
        Ok(fs::read_to_string(test_list).unwrap())
    } else {
        Cmd::default()
            .args(vec!["user", "list", "1", "-c"])
            .output()
    }
}

#[derive(Clone, Debug, PartialEq)]
struct IpmiUserRecord {
    pub id: String,
    pub name: String,
    pub _callin: bool,
    pub _link_auth: bool,
    pub _ipmi_msg: bool,
    pub _privilege_level: String,
}

impl IpmiUserRecord {
    pub fn from_row(row: Vec<&str>) -> Self {
        assert_eq!(row.len(), 6);

        let id = row[0].to_string();
        let name = row[1].to_string();
        let callin = as_bool(row[2]);
        let link_auth = as_bool(row[3]);
        let ipmi_msg = as_bool(row[4]);
        let privilege_level = row[5].to_string();

        Self {
            id,
            name,
            _callin: callin,
            _link_auth: link_auth,
            _ipmi_msg: ipmi_msg,
            _privilege_level: privilege_level,
        }
    }

    pub fn is_free(&self) -> bool {
        self.name.is_empty()
    }
}

fn fetch_ipmi_users_and_free_ids(
    test_list: Option<&str>,
) -> CarbideClientResult<(VecDeque<IpmiUserRecord>, HashMap<String, IpmiUserRecord>)> {
    let output = get_user_list(test_list)?;

    let (free_users, existing_users): (VecDeque<IpmiUserRecord>, VecDeque<IpmiUserRecord>) = output
        .lines()
        .map(|x| x.split(',').collect::<Vec<&str>>())
        .map(IpmiUserRecord::from_row)
        // some machines do not allow user with ID "1" to be used, so we don't report it as free OR existing in this case.
        .filter(|user| !(user.is_free() && user.id.as_str() == "1"))
        .partition(|user| user.is_free());

    let existing_users = existing_users
        .into_iter()
        .map(|user| (user.name.clone(), user))
        .collect::<HashMap<String, IpmiUserRecord>>();

    Ok((free_users, existing_users))
}

fn create_ipmi_user(id: &str, user: &str) -> CarbideClientResult<()> {
    let _ = Cmd::default()
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
    log::info!("Updating password for id {}", id);
    let _ = Cmd::default()
        .args(vec!["user", "set", "password", id, &password])
        .output()?;
    log::debug!("Updated password {} for id {}", password, id);
    Ok(password)
}

fn set_ipmi_props(id: &String, role: IpmitoolRoles) -> CarbideClientResult<()> {
    log::info!("Setting privileges for id {}", id);
    let role = format!("privilege={}", role as u8);

    // Enable user
    let _ = Cmd::default().args(vec!["user", "enable", id]).output()?;

    // Set user privilege and channel access
    let _ = Cmd::default()
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
    let _ = Cmd::default()
        .args(vec!["lan", "set", "1", "access", "on"])
        .output(); // Ignore it as this command might fail in some cards.

    // enable redfish access
    let idrac_user_str = format!("iDRAC.Users.{id}.Privilege");
    let _ = Cmd::new("racadm")
        .args(["set", idrac_user_str.as_str(), "0x1ff"])
        .output()?;

    Ok(())
}

fn set_ipmi_creds() -> CarbideClientResult<(IpmiInfo, String)> {
    let ip = fetch_ipmi_ip()?;
    let (mut free_users, existing_users) = fetch_ipmi_users_and_free_ids(None)?;

    // first, we create users, if we need to.
    let forge_admin_user =
        if let Some(existing_user) = existing_users.get(&FORGE_ADMIN_USER_NAME.to_string()) {
            // User already exists.
            // Get Id
            log::info!(
                "User {} already exists. Only setting password and privileges.",
                existing_user.name
            );
            existing_user.clone()
        } else {
            // Create user and get id.
            if let Some(free_user) = free_users.pop_front() {
                log::info!("Creating user {}", FORGE_ADMIN_USER_NAME);
                create_ipmi_user(free_user.id.as_str(), FORGE_ADMIN_USER_NAME)?;
                free_user
            } else {
                return Err(CarbideClientError::GenericError(format!(
                    "Insufficient free ids to create user. Failed for user: {}",
                    FORGE_ADMIN_USER_NAME
                )));
            }
        };

    // once we have the user, we set the password and privileges.
    let password = set_ipmi_password(&forge_admin_user.id)?;

    // The password set sometimes takes a few seconds before the user can be modified
    // This ensures that if a failure occurs during the set, it will be tried again.
    for attempt in 0..3 {
        match set_ipmi_props(&forge_admin_user.id, IpmitoolRoles::Administrator) {
            Ok(_) => break,
            Err(x) => {
                if attempt == 2 {
                    return Err(x);
                } else {
                    log::error!("retrying ipmi calls due to: {:?}", x);
                    std::thread::sleep(Duration::from_secs(1));
                }
            }
        }
    }

    Ok((
        IpmiInfo {
            user: FORGE_ADMIN_USER_NAME.to_string(),
            role: IpmitoolRoles::Administrator,
            password,
        },
        ip,
    ))
}

pub async fn update_ipmi_creds(
    forge_api: String,
    machine_id: uuid::Uuid,
) -> CarbideClientResult<()> {
    if IN_QEMU_VM.read().await.in_qemu {
        return Ok(());
    }

    wait_until_ipmi_is_ready().await?;

    let (ipmi_info, ip) = set_ipmi_creds()?;
    let bmc_metadata: rpc::BmcMetaDataUpdateRequest =
        IpmiInfo::convert(vec![ipmi_info], machine_id, ip)?;

    let mut client = rpc::forge_client::ForgeClient::connect(forge_api).await?;
    let request = tonic::Request::new(bmc_metadata);
    client.update_bmc_meta_data(request).await?;

    Ok(())
}

async fn wait_until_ipmi_is_ready() -> CarbideClientResult<()> {
    let now = Instant::now();
    const MAX_TIMEOUT: Duration = Duration::from_secs(60 * 12);
    const RETRY_TIME: Duration = Duration::from_secs(5);

    while now.elapsed() <= MAX_TIMEOUT {
        if Cmd::default().args(vec!["lan", "print"]).output().is_ok() {
            log::info!("ipmitool ready after {} seconds", now.elapsed().as_secs());
            return Ok(());
        } else {
            log::debug!(
                "still waiting for ipmitool after {} seconds",
                now.elapsed().as_secs()
            );
            sleep(RETRY_TIME).await;
        }
    }

    // Reached here, means MAX_TIMEOUT passed and yet ipmitool command is still failing.
    Err(CarbideClientError::GenericError(format!(
        "Max timout ({} seconds) is elapsed and still ipmitool is failed.",
        MAX_TIMEOUT.as_secs(),
    )))
}

fn as_bool(s: &str) -> bool {
    match s {
        "1" | "y" | "yes" | "on" | "t" | "true" => true,
        "0" | "n" | "no" | "off" | "f" | "false" => false,
        _ => false,
    }
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
    async fn test_fetch_list() {
        let (free_users, _existing_users) =
            fetch_ipmi_users_and_free_ids(Some("test/user_list.csv")).unwrap();
        assert!(free_users.iter().any(|user| user.id.as_str() == "4"));
        assert!(!free_users.iter().any(|user| user.id.as_str() == "1"));

        let (free_users, _existing_users) =
            fetch_ipmi_users_and_free_ids(Some("test/test_user_list_2.csv")).unwrap();
        assert!(free_users.iter().any(|user| user.id.as_str() == "5"));
        assert!(!free_users.iter().any(|user| user.id.as_str() == "3"));
    }
}
