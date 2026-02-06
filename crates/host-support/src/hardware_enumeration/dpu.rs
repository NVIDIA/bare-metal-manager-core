/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use std::collections::HashMap;
use std::thread::sleep;
use std::time::{Duration, Instant};

use regex::Regex;
use rpc::machine_discovery::{DpuData, LldpSwitchData};
use serde::{Deserialize, Serialize};
use serde_with::{OneOrMany, serde_as};
use tracing::{debug, warn};
use utils::cmd::{Cmd, CmdError};

const LLDP_PORTS: &[&str] = &["p0", "p1", "oob_net0"];

#[derive(thiserror::Error, Debug)]
pub enum DpuEnumerationError {
    #[error("Failed reading basic DPU info: {0}")]
    BasicInfo(String),
    #[error("Regex error {0}")]
    Regex(#[from] regex::Error),
    #[error("Command error {0}")]
    Cmd(#[from] CmdError),
    #[error("DPU enumeration failed reading '{0}': {1}")]
    Read(&'static str, String),
    #[error("LLDP error: {0}")]
    Lldp(String),
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LldpCapabilityData {
    #[serde(rename = "type")]
    pub capability_type: String,
    pub enabled: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LldpIdData {
    #[serde(rename = "type")]
    pub id_type: String,
    pub value: String,
}

#[serde_as]
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LldpChassisData {
    pub id: LldpIdData,
    pub descr: String,
    #[serde(rename = "mgmt-ip", default)]
    #[serde_as(as = "OneOrMany<_>")]
    pub management_ip_address: Vec<String>, // we get an array with ipv4 and ipv6 addresses
    #[serde(default)]
    pub capability: Vec<LldpCapabilityData>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LldpPortData {
    pub id: LldpIdData,
    pub descr: Option<String>,
    pub ttl: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LldpQueryData {
    pub age: String,
    pub chassis: HashMap<String, LldpChassisData>, // the key in this hash is the tor name
    pub port: LldpPortData,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LldpInterface {
    pub interface: HashMap<String, LldpQueryData>, // the key in this hash is the port #, eg. p0
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LldpResponse {
    pub lldp: LldpInterface,
}

/// Get LLDP port info.
pub fn get_lldp_port_info(port: &str) -> Result<String, DpuEnumerationError> {
    if cfg!(test) {
        const TEST_DATA: &str = "test/lldp_query.json";
        std::fs::read_to_string(TEST_DATA).map_err(|e| {
            warn!("Could not read LLDP json: {e}");
            DpuEnumerationError::Read(TEST_DATA, e.to_string())
        })
    } else {
        let lldp_cmd = format!("lldpcli -f json show neighbors ports {port}");
        Cmd::new("bash")
            .args(vec!["-c", lldp_cmd.as_str()])
            .output()
            .map_err(|e| {
                warn!("Could not discover LLDP peer for {port}, {e}");
                DpuEnumerationError::Lldp(e.to_string())
            })
    }
}

pub fn wait_until_all_ports_available() {
    const MAX_TIMEOUT: Duration = Duration::from_secs(60 * 5);
    const RETRY_TIME: Duration = Duration::from_secs(5);
    let now = Instant::now();
    let mut ports_read = vec![];

    for port in LLDP_PORTS.iter() {
        while now.elapsed() <= MAX_TIMEOUT {
            match get_port_lldp_info(port) {
                Ok(_) => {
                    ports_read.push(port);
                    break;
                }
                Err(_e) => {
                    warn!(port, "Port is not available yet.");
                    sleep(RETRY_TIME);
                }
            }
        }
    }

    debug!("lldp: Ports {:?} are read succesfully.", ports_read);
}

// LLDP was broken in multiple forge versions. It was fixed in HBN 2.1/ doca 2.6, as per
// https://redmine.mellanox.com/issues/3753899
// 2.1 aligns with XX.40.1000 firmwware, so if the middle section of firmware is equal or greater
// than 40, then LLDP should work.

// LLDP is not fully configured on sites and causes issues. It makes the dpu agent hang at startup.
// For now this will return false until a better fix is worked out.
pub fn is_lldp_working(_fw_version: &str) -> bool {
    /*
    fw_version
        .split('.')
        .nth(1) // second chunk is what we care about
        .and_then(|m| m.parse::<u8>().ok()) // turn it into a number
        .is_some_and(|n| n >= 40) // ensure its greater than or equal to 2.1 (40)
     */
    false
}

/// query lldp info for high speed ports p0..1, oob_net0 (some ports may not exist, warn on errors)
/// translate to simpler tor struct for discovery info
pub fn get_port_lldp_info(port: &str) -> Result<LldpSwitchData, DpuEnumerationError> {
    let lldp_json: String = get_lldp_port_info(port)?;

    // deserialize
    let lldp_resp: LldpResponse = match serde_json::from_str(lldp_json.as_str()) {
        Ok(x) => x,
        Err(e) => {
            warn!("Could not deserialize LLDP response {lldp_json}, {e}");
            return Err(DpuEnumerationError::Lldp(e.to_string()));
        }
    };

    let mut lldp_info: LldpSwitchData = Default::default();
    // copy over useful fields
    if let Some(lldp_data) = lldp_resp.lldp.interface.get(port) {
        for (tor, tor_data) in lldp_data.chassis.iter() {
            lldp_info.name = tor.to_string();
            lldp_info.id = format!("{}={}", tor_data.id.id_type, tor_data.id.value);
            lldp_info.description = tor_data.descr.to_string();
            lldp_info.local_port = port.to_string();

            // management_ip_address if missing we just replace it with empty list.
            lldp_info.ip_address = tor_data.management_ip_address.clone();
        }
        lldp_info.remote_port =
            format!("{}={}", lldp_data.port.id.id_type, lldp_data.port.id.value);
    } else {
        warn!("Malformed LLDP JSON response, port not found");
        return Err(DpuEnumerationError::Lldp(
            "LLDP: port not found".to_string(),
        ));
    }

    Ok(lldp_info)
}

fn get_flint_query() -> Result<String, DpuEnumerationError> {
    if cfg!(test) {
        const TEST_DATA: &str = "test/flint_query.txt";
        std::fs::read_to_string(TEST_DATA)
            .map_err(|x| DpuEnumerationError::Read(TEST_DATA, x.to_string()))
    } else {
        Cmd::new("bash")
            .args(vec!["-c", "flint -d /dev/mst/mt*_pciconf0 q full"])
            .output()
            .map_err(DpuEnumerationError::from)
    }
}

pub fn get_dpu_info() -> Result<DpuData, DpuEnumerationError> {
    let fw_ver_pattern = Regex::new("FW Version:\\s*(.*?)$")?;
    let fw_date_pattern = Regex::new("FW Release Date:\\s*(.*?)$")?;
    let part_num_pattern = Regex::new("Part Number:\\s*(.*?)$")?;
    let desc_pattern = Regex::new("Description:\\s*(.*?)$")?;
    let prod_ver_pattern = Regex::new("Product Version:\\s*(.*?)$")?;
    let base_mac_pattern = Regex::new("Base MAC:\\s+([[:alnum:]]+?)\\s+(.*?)$")?;

    let output = get_flint_query()?;
    let fw_ver = output
        .lines()
        .filter_map(|line| fw_ver_pattern.captures(line))
        .map(|x| x[1].trim().to_string())
        .take(1)
        .collect::<Vec<String>>();

    if fw_ver.is_empty() {
        return Err(DpuEnumerationError::BasicInfo(
            "Could not find firmware version.".to_string(),
        ));
    }
    let fw_date = output
        .lines()
        .filter_map(|line| fw_date_pattern.captures(line))
        .map(|x| x[1].trim().to_string())
        .take(1)
        .collect::<Vec<String>>();

    if fw_date.is_empty() {
        return Err(DpuEnumerationError::BasicInfo(
            "Could not find firmware date.".to_string(),
        ));
    }

    let part_number = output
        .lines()
        .filter_map(|line| part_num_pattern.captures(line))
        .map(|x| x[1].trim().to_string())
        .take(1)
        .collect::<Vec<String>>();

    if part_number.is_empty() {
        return Err(DpuEnumerationError::BasicInfo(
            "Could not find part number.".to_string(),
        ));
    }

    let device_description = output
        .lines()
        .filter_map(|line| desc_pattern.captures(line))
        .map(|x| x[1].trim().to_string())
        .take(1)
        .collect::<Vec<String>>();

    if device_description.is_empty() {
        return Err(DpuEnumerationError::BasicInfo(
            "Could not find device description.".to_string(),
        ));
    }

    let product_version = output
        .lines()
        .filter_map(|line| prod_ver_pattern.captures(line))
        .map(|x| x[1].trim().to_string())
        .take(1)
        .collect::<Vec<String>>();

    if product_version.is_empty() {
        return Err(DpuEnumerationError::BasicInfo(
            "Could not find product version.".to_string(),
        ));
    }

    let factory_mac_address = output
        .lines()
        .filter_map(|line| base_mac_pattern.captures(line))
        .map(|x| x[1].trim().to_string())
        .take(1)
        .collect::<Vec<String>>();

    if factory_mac_address.is_empty() {
        return Err(DpuEnumerationError::BasicInfo(
            "Could not find factory mac address.".to_string(),
        ));
    }
    // flint produces mac address without : separators
    let mut factory_mac = String::with_capacity(18);
    factory_mac.insert_str(0, &factory_mac_address[0]);
    if factory_mac.find(':').is_none() {
        factory_mac.insert(2, ':');
        factory_mac.insert(5, ':');
        factory_mac.insert(8, ':');
        factory_mac.insert(11, ':');
        factory_mac.insert(14, ':');
    }

    let mut switches: Vec<LldpSwitchData> = vec![];

    if is_lldp_working(&fw_ver[0]) {
        wait_until_all_ports_available();
        for port in LLDP_PORTS.iter() {
            match get_port_lldp_info(port) {
                Ok(lldp_info) => {
                    switches.push(lldp_info);
                }
                Err(_e) => {}
            }
        }
    }

    let dpu_info = DpuData {
        part_number: part_number[0].clone(),
        part_description: device_description[0].clone(),
        product_version: product_version[0].clone(),
        factory_mac_address: factory_mac,
        firmware_version: fw_ver[0].clone(),
        firmware_date: fw_date[0].clone(),
        switches,
    };
    Ok(dpu_info)
}

#[cfg(test)]
mod tests {
    use crate::hardware_enumeration::dpu;

    #[test]
    fn check_fw_versions_for_lldp() {
        assert!(!dpu::is_lldp_working("xx.39.yyyy"));
        assert!(!dpu::is_lldp_working("xx.40.yyyy"));
        assert!(!dpu::is_lldp_working("xx.41.yyyy"));

        //broken data should return false
        assert!(!dpu::is_lldp_working("xx.zz.yyyy"));
        assert!(!dpu::is_lldp_working("junk"));
    }

    #[test]
    fn validate_mgmt_ip_lldp_with_mixed_mgmt_ip_results() {
        let oob_lldp = dpu::get_port_lldp_info("oob_net0").unwrap();
        let p0_lldp = dpu::get_port_lldp_info("p0").unwrap();

        assert_eq!(oob_lldp.ip_address[0], "10.180.253.66");
        assert_eq!(oob_lldp.ip_address.len(), 1);

        assert_eq!(p0_lldp.ip_address[0], "10.180.253.67");
        assert_eq!(p0_lldp.ip_address.len(), 2);
    }
}
