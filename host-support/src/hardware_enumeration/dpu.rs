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

use crate::cmd::{Cmd, CmdError};
use regex::Regex;
use rpc::machine_discovery::{DpuData, TorLldpData};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{error, warn};

#[derive(thiserror::Error, Debug)]
pub enum DpuEnumerationError {
    #[error("DPU enumeration error: {0}")]
    Generic(String),
    #[error("Regex error {0}")]
    Regex(#[from] regex::Error),
    #[error("Command error {0}")]
    Cmd(#[from] CmdError),
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

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LldpChassisData {
    pub id: LldpIdData,
    pub descr: String,
    #[serde(rename = "mgmt-ip")]
    pub management_ip_address: Vec<String>, // we get an array with ipv4 and ipv6 addresses
    pub capability: Vec<LldpCapabilityData>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LldpPortData {
    pub id: LldpIdData,
    pub descr: String,
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

/// query lldp info for high speed ports p0..4, oob_net0 (some ports may not exist, warn on errors)
/// translate to simpler tor struct for discovery info
pub fn get_port_lldp_info(port: &str) -> Result<TorLldpData, DpuEnumerationError> {
    let lldp_json: String = if cfg!(test) {
        match std::fs::read_to_string("test/lldp_query.json") {
            Ok(s) => s,
            Err(e) => {
                warn!("Could not read LLDP json: {e}");
                return Err(DpuEnumerationError::Generic(e.to_string()));
            }
        }
    } else {
        let lldp_cmd = format!("lldpcli -f json show neighbors ports {}", port);
        match Cmd::new("bash")
            .args(vec!["-c", lldp_cmd.as_str()])
            .output()
        {
            Ok(s) => s,
            Err(e) => {
                warn!("Could not discover LLDP peer for {port}, {e}");
                return Err(DpuEnumerationError::Generic(e.to_string()));
            }
        }
    };

    // deserialize
    let lldp_resp: LldpResponse = match serde_json::from_str(lldp_json.as_str()) {
        Ok(x) => x,
        Err(e) => {
            warn!("Could not deserialize LLDP response {lldp_json}, {e}");
            return Err(DpuEnumerationError::Generic(e.to_string()));
        }
    };

    let mut lldp_info: TorLldpData = Default::default();
    // copy over useful fields
    if let Some(lldp_data) = lldp_resp.lldp.interface.get(port) {
        for (tor, tor_data) in lldp_data.chassis.iter() {
            lldp_info.name = tor.to_string();
            lldp_info.id = format!("{}={}", tor_data.id.id_type, tor_data.id.value);
            lldp_info.description = tor_data.descr.to_string();
            lldp_info.local_port = port.to_string();
            for ip_address in tor_data.management_ip_address.iter() {
                lldp_info.ip_address.push(ip_address.to_string());
            }
        }
    } else {
        warn!("Malformed LLDP JSON response, port not found");
        return Err(DpuEnumerationError::Generic(
            "LLDP: port not found".to_string(),
        ));
    }

    Ok(lldp_info)
}

fn get_flint_query() -> Result<String, DpuEnumerationError> {
    if cfg!(test) {
        std::fs::read_to_string("test/flint_query.txt")
            .map_err(|x| DpuEnumerationError::Generic(x.to_string()))
    } else {
        Cmd::new("bash")
            .args(vec!["-c", "flint -d /dev/mst/mt*_pciconf0 q full"])
            .output()
            .map_err(DpuEnumerationError::from)
    }
}

pub fn get_dpu_info() -> Result<DpuData, DpuEnumerationError> {
    const LLDP_PORTS: &[&str] = &["p0", "p1", "oob_net0"];
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
        return Err(DpuEnumerationError::Generic(
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
        return Err(DpuEnumerationError::Generic(
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
        return Err(DpuEnumerationError::Generic(
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
        return Err(DpuEnumerationError::Generic(
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
        return Err(DpuEnumerationError::Generic(
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
        return Err(DpuEnumerationError::Generic(
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

    let mut tors: Vec<TorLldpData> = vec![];
    for port in LLDP_PORTS.iter() {
        match get_port_lldp_info(port) {
            Ok(lldp_info) => {
                tors.push(lldp_info);
            }
            Err(_e) => {}
        }
    }

    let dpu_info = DpuData {
        part_number: part_number[0].clone(),
        part_description: device_description[0].clone(),
        product_version: product_version[0].clone(),
        factory_mac_address: factory_mac,
        firmware_version: fw_ver[0].clone(),
        firmware_date: fw_date[0].clone(),
        tors: tors.clone(),
    };
    Ok(dpu_info)
}
