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

use std::thread::sleep;
use std::time::{Duration, Instant};

use carbide_utils::cmd::{Cmd, CmdError};
use regex::Regex;
use rpc::machine_discovery::{DpuData, LldpSwitchData};
use tracing::{debug, warn};

use crate::lldp_collector::get_port_lldp_info;

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

    debug!("lldp: Ports {:?} are read successfully.", ports_read);
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
                Ok(Some(lldp_info)) => {
                    switches.push(lldp_info);
                }
                Ok(None) => {}
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
    use carbide_test_support::value_scenarios;

    use crate::hardware_enumeration::dpu;

    // `is_lldp_working` is currently stubbed to always return `false` (the
    // firmware-version parse is commented out pending a real LLDP fix). Every
    // input -- valid versions, boundary `40`, and garbage -- must yield `false`.
    #[test]
    fn is_lldp_working_always_false() {
        value_scenarios!(
            run = dpu::is_lldp_working;
            "below the 40 boundary" {
                "xx.39.yyyy" => false,
            }

            "at the 40 boundary" {
                "xx.40.yyyy" => false,
            }

            "above the 40 boundary" {
                "xx.41.yyyy" => false,
            }

            "non-numeric middle chunk" {
                "xx.zz.yyyy" => false,
            }

            "no dots at all" {
                "junk" => false,
            }

            "empty string" {
                "" => false,
            }

            "well-formed high version" {
                "22.99.1000" => false,
            }

            "single leading dot" {
                ".40." => false,
            }
        );
    }
}
