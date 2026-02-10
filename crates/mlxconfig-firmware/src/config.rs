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

// src/config.rs
// Defines the SupernicFirmwareConfig structure for TOML-based firmware
// configuration, and provides methods to construct firmware sources
// from that config.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::credentials::Credentials;
use crate::error::{FirmwareError, FirmwareResult};
use crate::source::FirmwareSource;

// SupernicFirmwareConfig is the TOML-serializable configuration for
// SuperNIC firmware management. In the Carbide API config, this lives
// under the [supernic_firmware_config] block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupernicFirmwareConfig {
    // firmware_url is the location of the firmware binary. Supported
    // formats:
    //   - Local path:  /path/to/firmware.signed.bin
    //   - file:// URL: file:///path/to/firmware.signed.bin
    //   - HTTPS URL:   https://host/path/to/firmware.signed.bin
    //   - SSH URL:     ssh://user@host:path/to/firmware.signed.bin
    pub firmware_url: String,

    // firmware_credentials is the optional authentication for
    // downloading the firmware binary.
    pub firmware_credentials: Option<Credentials>,

    // device_conf_url is the optional location of the device config
    // to apply before flashing (e.g., a debug token or mlxconfig
    // configuration blob). When present, the config is applied via
    // `mlxconfig apply` before burning the firmware. Supports the
    // same URL formats as firmware_url.
    pub device_conf_url: Option<String>,

    // device_conf_credentials is the optional authentication for
    // downloading the device config.
    pub device_conf_credentials: Option<Credentials>,

    // expected_version is the firmware version string expected after
    // flashing (e.g., "32.43.1014"). When set, the flasher will
    // verify the installed version matches after a reset.
    pub expected_version: Option<String>,
}

impl SupernicFirmwareConfig {
    // from_file reads a SupernicFirmwareConfig from a TOML file.
    // The file should contain the firmware config fields directly
    // at the top level (not nested under a section key).
    pub fn from_file(path: impl AsRef<Path>) -> FirmwareResult<Self> {
        let content = std::fs::read_to_string(path.as_ref()).map_err(FirmwareError::Io)?;
        Self::from_toml(&content)
    }

    // from_toml parses a SupernicFirmwareConfig from a TOML string.
    pub fn from_toml(toml_str: &str) -> FirmwareResult<Self> {
        toml::from_str(toml_str).map_err(|e| {
            FirmwareError::ConfigError(format!("Failed to parse firmware config: {e}"))
        })
    }

    // build_firmware_source constructs a FirmwareSource from the
    // firmware_url and firmware_credentials fields.
    pub fn build_firmware_source(&self) -> FirmwareResult<FirmwareSource> {
        let source = FirmwareSource::from_url(&self.firmware_url)?;
        Ok(match self.firmware_credentials.clone() {
            Some(cred) => source.with_credentials(cred),
            None => source,
        })
    }

    // build_device_conf_source constructs a FirmwareSource for the
    // device config, if device_conf_url is configured. Returns None
    // if no device config is configured.
    pub fn build_device_conf_source(&self) -> FirmwareResult<Option<FirmwareSource>> {
        match &self.device_conf_url {
            Some(url) => {
                let source = FirmwareSource::from_url(url)?;
                Ok(Some(match self.device_conf_credentials.clone() {
                    Some(cred) => source.with_credentials(cred),
                    None => source,
                }))
            }
            None => Ok(None),
        }
    }
}
