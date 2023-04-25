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
use std::ffi::OsStr;
use std::process::Command;

use log::error;
use regex::Regex;
use rpc::machine_discovery::DpuData;

#[derive(thiserror::Error, Debug)]
pub enum DpuEnumerationError {
    #[error("DPU enumeration error: {0}")]
    GenericError(String),
    #[error("Mellanox Firmware Tools {0} {1:?} failed with error: {2}")]
    MftErr(String, Vec<String>, String),
    #[error("Regex error {0}")]
    RegexError(#[from] regex::Error),
}

struct Cmd {
    command: Command,
}

impl Default for Cmd {
    fn default() -> Self {
        Cmd {
            command: Command::new("bash"),
        }
    }
}

impl Cmd {
    fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.command.args(args);
        self
    }

    fn output(mut self) -> Result<String, DpuEnumerationError> {
        if cfg!(test) {
            return Ok("test string".to_string());
        }

        let output = self
            .command
            .output()
            .map_err(|x| DpuEnumerationError::GenericError(x.to_string()))?;

        if !output.status.success() {
            return Err(DpuEnumerationError::MftErr(
                self.command.get_program().to_string_lossy().to_string(),
                self.command
                    .get_args()
                    .map(|arg| arg.to_string_lossy().to_string())
                    .collect::<Vec<String>>(),
                String::from_utf8_lossy(&output.stderr).to_string(),
            ));
        }

        String::from_utf8(output.stdout).map_err(|_| {
            DpuEnumerationError::GenericError(format!(
                "Result of command {:?} with args {:?} is invalid UTF8",
                self.command.get_program(),
                self.command.get_args().collect::<Vec<&OsStr>>()
            ))
        })
    }
}

fn get_flint_query() -> Result<String, DpuEnumerationError> {
    if cfg!(test) {
        std::fs::read_to_string("test/flint_query.txt")
            .map_err(|x| DpuEnumerationError::GenericError(x.to_string()))
    } else {
        Cmd::default()
            .args(vec![
                "-c",
                "flint",
                "-d",
                "/dev/mst/mt*_pciconf0",
                "q",
                "full",
            ])
            .output()
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
        return Err(DpuEnumerationError::GenericError(
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
        return Err(DpuEnumerationError::GenericError(
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
        return Err(DpuEnumerationError::GenericError(
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
        return Err(DpuEnumerationError::GenericError(
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
        return Err(DpuEnumerationError::GenericError(
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
        return Err(DpuEnumerationError::GenericError(
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

    let dpu_info = DpuData {
        part_number: part_number[0].clone(),
        part_description: device_description[0].clone(),
        product_version: product_version[0].clone(),
        factory_mac_address: factory_mac,
        firmware_version: fw_ver[0].clone(),
        firmware_date: fw_date[0].clone(),
    };
    Ok(dpu_info)
}
