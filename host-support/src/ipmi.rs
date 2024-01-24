/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
use std::fmt;

use ::rpc::forge::{self as rpc, BmcInfo, BmcMetaDataUpdateRequest};
use ::rpc::forge_tls_client::ForgeClientT;
use forge_secrets::credentials::Credentials;
use regex::Regex;
use tokio::time::Duration;
use tracing::{debug, error};
use utils::cmd::Cmd;

use crate::hardware_enumeration::{HardwareEnumerationError, HardwareEnumerationResult};

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
    fn convert(&self) -> eyre::Result<rpc::UserRoles> {
        match self {
            IpmitoolRoles::_User => Ok(rpc::UserRoles::User),
            IpmitoolRoles::Administrator => Ok(rpc::UserRoles::Administrator),
            IpmitoolRoles::_Operator => Ok(rpc::UserRoles::Operator),
            _ => Err(eyre::eyre!("Not implemented")),
        }
    }
}

const FORGE_ADMIN_USER_NAME: &str = "forge_admin";

#[derive(Debug)]
pub struct IpmiUser {
    user: String,
    role: IpmitoolRoles,
    password: String,
}

fn get_lan_print() -> eyre::Result<String> {
    if cfg!(test) {
        std::fs::read_to_string("test/lan_print.txt").map_err(|x| eyre::eyre!(x))
    } else {
        Ok(Cmd::new("ipmitool")
            .attempts(5)
            .ignore_return(true)
            .args(vec!["lan", "print"])
            .output()?)
    }
}

pub async fn send_bmc_metadata_update(
    forge_client: &mut ForgeClientT,
    machine_id: &str,
    ipmi_users: Vec<IpmiUser>,
) -> eyre::Result<()> {
    let (bmc_ip, bmc_mac) = fetch_bmc_network_config()?;
    let (bmc_version, bmc_firmware_version) = fetch_bmc_info()?;

    let data = ipmi_users
        .into_iter()
        .map(|u| {
            let role = u.role.convert()?;
            Ok(rpc::bmc_meta_data_update_request::DataItem {
                user: u.user,
                password: u.password,
                role: role as i32,
            })
        })
        .collect::<eyre::Result<Vec<_>>>()?;

    let bmc_metadata_request = BmcMetaDataUpdateRequest {
        machine_id: Some(machine_id.to_owned().into()),
        data,
        request_type: rpc::BmcRequestType::Ipmi as i32,
        bmc_info: Some(BmcInfo {
            ip: bmc_ip,
            mac: bmc_mac,
            version: bmc_version,
            firmware_version: bmc_firmware_version,
        }),
    };

    let request = tonic::Request::new(bmc_metadata_request);
    forge_client.update_bmc_meta_data(request).await?;

    Ok(())
}

fn get_bmc_info() -> eyre::Result<String> {
    if cfg!(test) {
        std::fs::read_to_string("test/bmc_info.txt").map_err(|x| eyre::eyre!(x.to_string()))
    } else {
        Ok(Cmd::new("ipmitool")
            .attempts(5)
            .args(vec!["bmc", "info"])
            .output()?)
    }
}

fn fetch_bmc_network_config() -> eyre::Result<(Option<String>, Option<String>)> {
    let versions_pattern = Regex::new("(?s)IP Address *: (.*?)\n.*MAC Address *: (.*?)\n")?;
    debug!("Fetching BMC Network Information.");
    let output = get_lan_print()?;
    let captures = versions_pattern.captures(&output).ok_or(eyre::eyre!(
        "Could not find BMC network information.".to_string(),
    ))?;

    let bmc_ip = captures.get(1).and_then(|m| {
        let match_str = m.as_str();
        if match_str.trim().is_empty() {
            None
        } else {
            Some(match_str.to_owned())
        }
    });

    let bmc_mac = captures.get(2).and_then(|m| {
        let match_str = m.as_str();
        if match_str.trim().is_empty() {
            None
        } else {
            Some(match_str.to_owned())
        }
    });

    debug!("BMC IP: {:?} BMC MAC: {:?}", bmc_ip, bmc_mac);

    Ok((bmc_ip, bmc_mac))
}

fn fetch_bmc_info() -> eyre::Result<(Option<String>, Option<String>)> {
    let versions_pattern = Regex::new("Device Revision *: (.*?)\n.*Firmware Revision *: (.*?)\n")?;
    debug!("Fetching BMC Version Information.");
    let output = get_bmc_info()?;
    let captures = versions_pattern
        .captures(&output)
        .ok_or(eyre::eyre!("Could not find BMC information."))?;

    let device_version = captures.get(1).and_then(|m| {
        let match_str = m.as_str();
        if match_str.trim().is_empty() {
            None
        } else {
            Some(match_str.to_owned())
        }
    });

    let firmware_version = captures.get(2).and_then(|m| {
        let match_str = m.as_str();
        if match_str.trim().is_empty() {
            None
        } else {
            Some(match_str.to_owned())
        }
    });

    debug!(
        "BMC device version: {:?} firmware version: {:?}",
        device_version, firmware_version
    );

    Ok((device_version, firmware_version))
}

fn get_user_list(test_list: Option<&str>) -> eyre::Result<String> {
    tracing::info!("Fetching current configured users list.");
    if let Some(test_list) = test_list {
        use std::fs;
        Ok(fs::read_to_string(test_list).unwrap())
    } else {
        Ok(Cmd::new("ipmitool")
            .attempts(5)
            .args(vec!["user", "list", "1", "-c"])
            .output()?)
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
        self.name.is_empty() || self.name.as_str() == "(Empty User)"
    }
}

fn fetch_ipmi_users_and_free_ids(
    test_list: Option<&str>,
) -> eyre::Result<(VecDeque<IpmiUserRecord>, HashMap<String, IpmiUserRecord>)> {
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

fn create_ipmi_user(id: &str, user: &str, sys_vendor: &str) -> HardwareEnumerationResult<()> {
    match sys_vendor {
        "Lenovo" => {
            let onecli_id: i32 = match id
                .parse::<i32>()
                .map(|x| x - 1)
                .map_err(|e| HardwareEnumerationError::GenericError(e.to_string()))?
            {
                valid_id if valid_id > 1 => Ok(valid_id),
                invalid_id => {
                    Err(HardwareEnumerationError::GenericError(format!(
                        "The value for the login user {invalid_id} was not greater than 1, which is the root user"
                    )))
                }
            }?;

            let onecli_user_str = format!("IMM.Loginid.{onecli_id}");
            let _ = Cmd::new("/opt/forge/xclarity/onecli")
                .args(["config", "set", onecli_user_str.as_str(), user])
                .output()?;
        }
        _other => {
            let _ = Cmd::new("ipmitool")
                .attempts(5)
                .args(vec!["user", "set", "name", id, user])
                .output()
                .map_err(HardwareEnumerationError::from)?;
        }
    }

    Ok(())
}

fn set_ipmi_password(id: &String, sys_vendor: &str) -> eyre::Result<String> {
    let password = Credentials::generate_password();
    tracing::info!("Updating password for id {}", id);
    match sys_vendor {
        "Lenovo" => {
            let onecli_id: i32 = match id
                .parse::<i32>()
                .map(|x| x - 1)?
            {
                valid_id if valid_id > 1 => Ok(valid_id),
                invalid_id => {
                    Err(eyre::eyre!(
                        "The value for the login user {invalid_id} was not greater than 1, which is the root user"
                    ))
                }
            }?;

            let onecli_user_str = format!("IMM.Password.{onecli_id}");
            let _ = Cmd::new("/opt/forge/xclarity/onecli")
                .args(["config", "set", onecli_user_str.as_str(), password.as_str()])
                .output()?;
        }
        _other => {
            let _ = Cmd::new("ipmitool")
                .attempts(5)
                .args(vec!["user", "set", "password", id, &password])
                .output()?;
        }
    }
    tracing::debug!("Updated password {} for id {}", password, id);
    Ok(password)
}

fn set_ipmi_props(id: &String, role: IpmitoolRoles, sys_vendor: &str) -> eyre::Result<()> {
    tracing::info!("Setting privileges for id {}", id);
    let role = format!("privilege={}", role as u8);

    // Enable user
    let _ = Cmd::new("ipmitool")
        .attempts(5)
        .args(vec!["user", "enable", id])
        .output()?;

    // Set user privilege and channel access
    let _ = Cmd::new("ipmitool")
        .attempts(5)
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
    let _ = Cmd::new("ipmitool")
        .attempts(5)
        .args(vec!["lan", "set", "1", "access", "on"])
        .output(); // Ignore it as this command might fail in some cards.

    // enable redfish access
    match sys_vendor {
        "Lenovo" => issue_onecli_user_commands(id),
        "Dell Inc." => issue_racadm_user_commands(id),
        "https://www.mellanox.com" => Ok(()),
        "Supermicro" => Ok(()),
        "NVIDIA" => Ok(()),
        "HPE" => Ok(()),
        other => {
            return Err(eyre::eyre!(
                "The chassis vendor was an unexpected result - {other}"
            ))
        }
    }?;

    Ok(())
}

fn issue_onecli_user_commands(id: &str) -> eyre::Result<()> {
    // The onecli tool identifies users starting at 1 and ipmi has 1 as a reserved number
    // so the onecli needs to have the ipmi user id minus one to set the LoginRole.
    let onecli_id: i32 = match id
        .parse::<i32>()
        .map(|x| x - 1)?
    {
        valid_id if valid_id > 1 => Ok(valid_id),
        invalid_id => {
            Err(eyre::eyre!(
                "The value for the login user {invalid_id} was not greater than 1, which is the root user"
            ))
        }
    }?;

    let onecli_user_str = format!("IMM.LoginRole.{onecli_id}");
    let _ = Cmd::new("/opt/forge/xclarity/onecli")
        .args(["config", "set", onecli_user_str.as_str(), "Administrator"])
        .output()?;
    Ok(())
}

fn issue_racadm_user_commands(id: &String) -> eyre::Result<()> {
    let idrac_user_str = format!("iDRAC.Users.{id}.Privilege");
    let _ = Cmd::new("racadm")
        .args(["set", idrac_user_str.as_str(), "0x1ff"])
        .output()?;
    // set idrac forge_admin user sol related privileges
    let idrac_ipmilan_str = format!("iDRAC.Users.{id}.IpmiLanPrivilege");
    let _ = Cmd::new("racadm")
        .args(["set", idrac_ipmilan_str.as_str(), "4"])
        .output()?;
    let idrac_ipmisol_str = format!("iDRAC.Users.{id}.IpmiSerialPrivilege");
    let _ = Cmd::new("racadm")
        .args(["set", idrac_ipmisol_str.as_str(), "4"])
        .output()?;
    let idrac_solenable_str = format!("iDRAC.Users.{id}.SolEnable");
    let _ = Cmd::new("racadm")
        .args(["set", idrac_solenable_str.as_str(), "1"])
        .output()?;
    Ok(())
}

fn set_ipmi_sol(id: &String) -> eyre::Result<()> {
    // failures for these 3 commands are okay to ignore, some BMCs may not handle them correctly.
    let _ = Cmd::new("ipmitool")
        .attempts(5)
        .args(vec!["sol", "set", "set-in-progress", "set-complete", "1"])
        .output()?;

    let _ = Cmd::new("ipmitool")
        .attempts(5)
        .args(vec!["sol", "set", "enabled", "true", "1"])
        .output()?;

    let _ = Cmd::new("ipmitool")
        .attempts(5)
        .args(vec!["sol", "payload", "enable", "1", id])
        .output()?;

    Ok(())
}

pub fn set_ipmi_creds() -> eyre::Result<IpmiUser> {
    let (mut free_users, existing_users) = fetch_ipmi_users_and_free_ids(None)?;

    let ven = std::fs::read_to_string("/sys/class/dmi/id/chassis_vendor")?;
    let sys_vendor = ven.trim();

    // first, we create users, if we need to.
    let forge_admin_user =
        if let Some(existing_user) = existing_users.get(&FORGE_ADMIN_USER_NAME.to_string()) {
            // User already exists.
            // Get Id
            tracing::info!(
                "User {} already exists. Only setting password and privileges.",
                existing_user.name
            );
            existing_user.clone()
        } else {
            // Create user and get id.
            if let Some(free_user) = free_users.pop_front() {
                tracing::info!("Creating user {}", FORGE_ADMIN_USER_NAME);
                create_ipmi_user(free_user.id.as_str(), FORGE_ADMIN_USER_NAME, sys_vendor)?;
                free_user
            } else {
                return Err(eyre::eyre!(
                "Insufficient free ids to create user. Failed for user: {FORGE_ADMIN_USER_NAME}",
            ));
            }
        };

    // once we have the user, we set the password and privileges.
    let password = set_ipmi_password(&forge_admin_user.id, sys_vendor)?;

    // The password set sometimes takes a few seconds before the user can be modified
    // This ensures that if a failure occurs during the set, it will be tried again.
    for attempt in 0..3 {
        match set_ipmi_props(
            &forge_admin_user.id,
            IpmitoolRoles::Administrator,
            sys_vendor,
        ) {
            Ok(_) => break,
            Err(x) => {
                if attempt == 2 {
                    return Err(x);
                } else {
                    tracing::error!("retrying ipmi calls due to: {:?}", x);
                    std::thread::sleep(Duration::from_secs(1));
                }
            }
        }
    }

    // set ipmi sol parameters
    if let Err(e) = set_ipmi_sol(&forge_admin_user.id) {
        error!("Failed to enable SOL: {}", e);
    }

    Ok(IpmiUser {
        user: FORGE_ADMIN_USER_NAME.to_string(),
        role: IpmitoolRoles::Administrator,
        password,
    })
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
    static EXPECTED_MAC: &str = "10:70:fd:18:0f:be";
    static EXPECTED_BMC_VERSION: &str = "1";
    static EXPECTED_BMC_FIRMWARE_VERSION: &str = "5.10";

    #[tokio::test]
    async fn test_ipmi_ip() {
        let (ip, mac) = fetch_bmc_network_config().unwrap();

        assert_eq!(ip, Some(EXPECTED_IP.to_owned()));
        assert_eq!(mac, Some(EXPECTED_MAC.to_owned()));
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

    #[tokio::test]
    async fn test_generate_password() {
        const UPPERCHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        const LOWERCHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
        const NUMCHARS: &[u8] = b"0123456789";
        const EXTRACHARS: &[u8] = b"^%$@!~_";
        const CHARSET: [&[u8]; 4] = [UPPERCHARS, LOWERCHARS, NUMCHARS, EXTRACHARS];
        for _ in 0..500 {
            let password = Credentials::generate_password();
            for charset in CHARSET {
                let mut found = false;
                for ch in charset {
                    if password.contains(*ch as char) {
                        found = true;
                        break;
                    }
                }

                assert!(
                    found,
                    "Charset {:?} is missing in password: {}",
                    charset, password
                );
            }
        }
    }

    #[tokio::test]
    async fn test_bmc_info() {
        let (bmc_device_version, bmc_firmware_version) = fetch_bmc_info().unwrap();

        assert_eq!(bmc_device_version, Some(EXPECTED_BMC_VERSION.to_owned()));
        assert_eq!(
            bmc_firmware_version,
            Some(EXPECTED_BMC_FIRMWARE_VERSION.to_owned())
        );
    }
}
