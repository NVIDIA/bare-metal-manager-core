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

// src/flasher.rs
// FirmwareFlasher is the main orchestrator for the firmware flash lifecycle.
// It coordinates device config application, firmware burning, verification,
// and device reset across the mlxconfig-runner, mlxconfig-lockdown, and
// mlxfwreset tools.

use std::path::PathBuf;

use chrono::Utc;
use mlxconfig_lockdown::FlintRunner;
use mlxconfig_runner::{ExecOptions, MlxConfigApplier};
use serde::{Deserialize, Serialize};
use tracing;

use crate::config::SupernicFirmwareConfig;
use crate::error::{FirmwareError, FirmwareResult};
use crate::reset::{DEFAULT_RESET_LEVEL, MlxFwResetRunner};
use crate::source::FirmwareSource;

// FirmwareFlasher manages the firmware flash lifecycle for Mellanox NICs.
// It supports both production firmware (direct flash) and debug firmware
// (device config application followed by flash).
pub struct FirmwareFlasher {
    // device_id is the PCI address of the target device (e.g., "4b:00.0").
    device_id: String,
    // reset_device is the device identifier for mlxfwreset, which may
    // differ from the PCI address (e.g., "/dev/mst/mt41692_pciconf0").
    // If not set, the PCI address from device_id is used.
    reset_device: Option<String>,
    // firmware is the source of the firmware binary to flash.
    // Set via with_firmware(). Required for flash(), not needed
    // for verify_version() or reset().
    firmware: Option<FirmwareSource>,
    // device_conf is the optional device configuration to apply before
    // flashing (e.g., a debug token or mlxconfig config blob). When set,
    // it is applied via `mlxconfig apply` before burning firmware.
    device_conf: Option<FirmwareSource>,
    // expected_version is the firmware version string expected after
    // flashing (e.g., "32.43.1014"). When set, verify_version() will
    // query the device via mlxfwmanager and compare the installed
    // version against this value.
    expected_version: Option<String>,
    // work_dir is the directory for staging downloaded firmware files.
    // Defaults to a temporary directory if not specified.
    work_dir: PathBuf,
    // reset_level is the mlxfwreset level to use when resetting the device.
    reset_level: u8,
    // dry_run enables dry-run mode across all underlying operations.
    dry_run: bool,
}

// FlashResult captures the outcome of a firmware flash operation,
// including details about each step that was performed.
#[derive(Debug, Serialize, Deserialize)]
pub struct FlashResult {
    // device_id is the device that was flashed.
    pub device_id: String,
    // firmware_source is a human-readable description of where the
    // firmware was sourced from.
    pub firmware_source: String,
    // device_conf_applied indicates whether a device config was applied.
    pub device_conf_applied: bool,
    // flint_output is the raw output from the flint burn command.
    pub flint_output: String,
    // timestamp is when the flash operation completed.
    pub timestamp: String,
}

impl FirmwareFlasher {
    // from_config creates a FirmwareFlasher from a SupernicFirmwareConfig.
    // The config's firmware_url and credentials are used to build the
    // firmware source, and the optional device_conf_url and credentials
    // build the device config source. The expected_version field is also
    // applied to the flasher if set.
    pub fn from_config(
        device_id: impl Into<String>,
        config: &SupernicFirmwareConfig,
    ) -> FirmwareResult<Self> {
        let firmware = config.build_firmware_source()?;
        let mut flasher = Self::new(device_id).with_firmware(firmware);

        if let Some(device_conf_source) = config.build_device_conf_source()? {
            flasher = flasher.with_device_conf(device_conf_source);
        }

        if let Some(ref version) = config.expected_version {
            flasher = flasher.with_expected_version(version);
        }

        Ok(flasher)
    }

    // from_config_file creates a FirmwareFlasher by loading a
    // SupernicFirmwareConfig from a TOML file and applying it.
    pub fn from_config_file(
        device_id: impl Into<String>,
        path: impl AsRef<std::path::Path>,
    ) -> FirmwareResult<Self> {
        let config = SupernicFirmwareConfig::from_file(path)?;
        Self::from_config(device_id, &config)
    }

    // new creates a new FirmwareFlasher for the specified device.
    // Use with_firmware() to set the firmware source for flash
    // operations. For verify_version() and reset(), no firmware
    // source is needed.
    pub fn new(device_id: impl Into<String>) -> Self {
        Self {
            device_id: device_id.into(),
            reset_device: None,
            firmware: None,
            device_conf: None,
            expected_version: None,
            work_dir: std::env::temp_dir().join("mlxconfig-firmware"),
            reset_level: DEFAULT_RESET_LEVEL,
            dry_run: false,
        }
    }

    // with_firmware sets the firmware source for flash operations.
    // Required before calling flash().
    pub fn with_firmware(mut self, firmware: FirmwareSource) -> Self {
        self.firmware = Some(firmware);
        self
    }

    // with_device_conf sets the device configuration to apply before
    // flashing. This is used for debug firmware builds that require
    // a configuration blob (e.g., debug token) to be applied via
    // `mlxconfig apply` before the firmware can be burned.
    pub fn with_device_conf(mut self, device_conf: FirmwareSource) -> Self {
        self.device_conf = Some(device_conf);
        self
    }

    // with_reset_device sets the device identifier to use with mlxfwreset.
    // This may differ from the PCI address used with flint and mlxconfig
    // (e.g., an MST device path like "/dev/mst/mt41692_pciconf0").
    pub fn with_reset_device(mut self, device: impl Into<String>) -> Self {
        self.reset_device = Some(device.into());
        self
    }

    // with_work_dir sets the directory used for staging downloaded
    // firmware files. Defaults to a temporary directory.
    pub fn with_work_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.work_dir = dir.into();
        self
    }

    // with_reset_level sets the mlxfwreset level (default: 3).
    pub fn with_reset_level(mut self, level: u8) -> Self {
        self.reset_level = level;
        self
    }

    // with_expected_version sets the expected firmware version string
    // after flashing (e.g., "32.43.1014"). When set, verify_version()
    // will query the device via mlxfwmanager and confirm the installed
    // firmware matches this value.
    pub fn with_expected_version(mut self, version: impl Into<String>) -> Self {
        self.expected_version = Some(version.into());
        self
    }

    // with_dry_run enables or disables dry-run mode. When enabled, no
    // actual operations are performed; commands are logged instead.
    pub fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }

    // flash executes the full firmware flash sequence. For debug firmware
    // (when a device config is configured), this applies the config first.
    // Then burns the firmware image via flint. Requires a firmware source
    // to be set via with_firmware().
    pub async fn flash(&self) -> FirmwareResult<FlashResult> {
        let firmware = self.firmware.as_ref().ok_or_else(|| {
            FirmwareError::ConfigError(
                "No firmware source configured. Use with_firmware() before calling flash()."
                    .to_string(),
            )
        })?;

        tracing::info!(device = %self.device_id, source = %firmware.description(), "Starting firmware flash");

        // Ensure the work directory exists.
        tokio::fs::create_dir_all(&self.work_dir)
            .await
            .map_err(FirmwareError::Io)?;

        let exec_options = ExecOptions::new().with_dry_run(self.dry_run);

        let applier = MlxConfigApplier::with_options(&self.device_id, exec_options);
        let mut device_conf_applied = false;

        // Step 1: If a device config is configured, apply it.
        if let Some(ref device_conf_source) = self.device_conf {
            tracing::info!(source = %device_conf_source.description(), "Applying device config");

            let conf_path = device_conf_source.resolve(&self.work_dir).await?;
            tracing::debug!(path = %conf_path.display(), "Device config resolved");

            applier.apply(&conf_path)?;
            device_conf_applied = true;
            tracing::info!("Device config applied");
        }

        // Step 2: Resolve the firmware source to a local path.
        let firmware_path = firmware.resolve(&self.work_dir).await?;
        tracing::debug!(path = %firmware_path.display(), "Firmware resolved");

        // Step 3: Burn the firmware via flint.
        tracing::info!(device = %self.device_id, "Burning firmware via flint");

        let flint = if self.dry_run {
            FlintRunner::with_path("flint").with_dry_run(true)
        } else {
            FlintRunner::new().map_err(FirmwareError::FlintError)?
        };

        let flint_output = match flint.burn(&self.device_id, &firmware_path) {
            Ok(output) => output,
            Err(mlxconfig_lockdown::MlxError::DryRun(cmd)) => {
                tracing::debug!(cmd = %cmd, "Dry run");
                format!("[DRY RUN] {cmd}")
            }
            Err(e) => return Err(FirmwareError::FlintError(e)),
        };

        tracing::debug!(output = %flint_output, "Flint output");

        let result = FlashResult {
            device_id: self.device_id.clone(),
            firmware_source: firmware.description(),
            device_conf_applied,
            flint_output,
            timestamp: Utc::now().to_rfc3339(),
        };

        tracing::info!(
            device = %result.device_id,
            source = %result.firmware_source,
            device_conf = result.device_conf_applied,
            "Flash complete"
        );

        Ok(result)
    }

    // verify_image verifies the firmware on the device by comparing it
    // against a provided firmware image file. This runs flint's verify
    // command with the -i flag: `flint -d <dev> -i <image> verify`.
    // This is the recommended verification method for encrypted flash
    // devices (e.g., BF3 SuperNIC).
    pub fn verify_image(&self, image_path: &std::path::Path) -> FirmwareResult<String> {
        tracing::info!(
            device = %self.device_id,
            image = %image_path.display(),
            "Verifying firmware image"
        );

        let flint = if self.dry_run {
            FlintRunner::with_path("flint").with_dry_run(true)
        } else {
            FlintRunner::new().map_err(FirmwareError::FlintError)?
        };

        match flint.verify_image(&self.device_id, image_path) {
            Ok(output) => {
                tracing::info!(device = %self.device_id, "Image verification passed");
                tracing::debug!(output = %output, "Flint verify output");
                Ok(output)
            }
            Err(mlxconfig_lockdown::MlxError::DryRun(cmd)) => {
                tracing::debug!(cmd = %cmd, "Dry run");
                Ok(format!("[DRY RUN] {cmd}"))
            }
            Err(e) => Err(FirmwareError::VerificationFailed(e.to_string())),
        }
    }

    // verify_version checks that the firmware version on the device
    // matches the expected version configured via with_expected_version().
    // This queries the device using mlxfwmanager (via mlxconfig-device)
    // and compares the reported firmware version. Returns Ok with the
    // installed version string on match, or a VerificationFailed error
    // if the versions don't match. If no expected version is configured,
    // this is a no-op and returns Ok.
    pub fn verify_version(&self) -> FirmwareResult<Option<String>> {
        let expected = match &self.expected_version {
            Some(v) => v,
            None => return Ok(None),
        };

        tracing::info!(
            device = %self.device_id,
            expected = %expected,
            "Verifying firmware version"
        );

        if self.dry_run {
            tracing::debug!(device = %self.device_id, "Dry run: skipping version query");
            return Ok(Some(expected.clone()));
        }

        let device_info =
            mlxconfig_device::discovery::discover_device(&self.device_id).map_err(|e| {
                FirmwareError::VerificationFailed(format!(
                    "Failed to query device '{}': {e}",
                    self.device_id
                ))
            })?;

        let installed = device_info
            .fw_version_current
            .as_deref()
            .unwrap_or("unknown");

        tracing::debug!(
            device = %self.device_id,
            installed = %installed,
            expected = %expected,
            "Version comparison"
        );

        if installed == expected {
            tracing::info!(version = %installed, "Firmware version verified");
            Ok(Some(installed.to_string()))
        } else {
            Err(FirmwareError::VerificationFailed(format!(
                "Firmware version mismatch on '{}': expected '{}', found '{}'",
                self.device_id, expected, installed
            )))
        }
    }

    // reset resets the device to activate the new firmware. Uses
    // mlxfwreset with the configured reset level (default: 3).
    pub fn reset(&self) -> FirmwareResult<String> {
        let reset_device = self.reset_device.as_deref().unwrap_or(&self.device_id);

        tracing::info!(
            device = %reset_device,
            level = %self.reset_level,
            "Resetting device via mlxfwreset"
        );

        let runner = if self.dry_run {
            MlxFwResetRunner::with_path("mlxfwreset").with_dry_run(true)
        } else {
            MlxFwResetRunner::new()?
        };

        match runner.reset(reset_device, self.reset_level) {
            Ok(output) => {
                tracing::info!(device = %reset_device, "Device reset complete");
                tracing::debug!(output = %output, "mlxfwreset output");
                Ok(output)
            }
            Err(FirmwareError::DryRun(cmd)) => {
                tracing::debug!(cmd = %cmd, "Dry run");
                Ok(format!("[DRY RUN] {cmd}"))
            }
            Err(e) => Err(e),
        }
    }
}
