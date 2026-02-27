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
// It coordinates firmware burning, verification, and device reset across
// flint and mlxfwreset.
//
// Constructed via new(device_id, &FirmwareSpec), which discovers the device
// and validates that the hardware identity (part_number, psid) matches the
// spec. This RAII-esque validation ensures firmware is never flashed to the
// wrong device.
//
// From there, you can use various config structs to perform subsequent
// operations on the underlying target device, or apply an entire workflow
// profile with a FirmwareFlasherProfile.

use std::path::PathBuf;

use tracing;

use crate::firmware::config::{FirmwareFlasherProfile, FirmwareSpec, FlashSpec};
use crate::firmware::error::{FirmwareError, FirmwareResult};
use crate::firmware::reset::{DEFAULT_RESET_LEVEL, MlxFwResetRunner};
use crate::firmware::result::FirmwareFlashReport;
use crate::lockdown::runner::FlintRunner;
use crate::runner::applier::MlxConfigApplier;
use crate::runner::exec_options::ExecOptions;

// FirmwareFlasher manages the firmware flash lifecycle for Mellanox NICs.
// Constructed via new(), which integrates validation by discovering the
// device and confirming the hardware identity matches the FirmwareSpec.
// Individual operations (flash, verify_image, verify_version, reset) can
// be called directly, or apply() orchestrates the full lifecycle from a
// FirmwareFlasherProfile.
pub struct FirmwareFlasher {
    // device_id is the PCI address of the target device (e.g., "4b:00.0").
    device_id: String,
    // firmware_spec is the validated firmware target identity and version.
    firmware_spec: FirmwareSpec,
    // dry_run enables dry-run mode across all underlying operations.
    dry_run: bool,
}

impl FirmwareFlasher {
    // new creates a FirmwareFlasher with integrated validation. Discovers the
    // device via mlxfwmanager and confirms the device's part_number and
    // psid match the provided FirmwareSpec. Returns an error if the device
    // cannot be found or if the identity doesn't match.
    pub fn new(device_id: impl Into<String>, spec: &FirmwareSpec) -> FirmwareResult<Self> {
        let device_id = device_id.into();

        let device_info = crate::device::discovery::discover_device(&device_id).map_err(|e| {
            FirmwareError::ConfigError(format!("Failed to discover device '{}': {e}", device_id))
        })?;

        let actual_pn = device_info.part_number.as_deref().unwrap_or("unknown");
        let actual_psid = device_info.psid.as_deref().unwrap_or("unknown");

        if actual_pn != spec.part_number || actual_psid != spec.psid {
            return Err(FirmwareError::ConfigError(format!(
                "Device '{}' has part_number '{}' / psid '{}', expected '{}' / '{}'",
                device_id, actual_pn, actual_psid, spec.part_number, spec.psid,
            )));
        }

        tracing::info!(
            device = %device_id,
            part_number = %spec.part_number,
            psid = %spec.psid,
            version = %spec.version,
            "FirmwareFlasher initialized — device identity validated"
        );

        Ok(Self {
            device_id,
            firmware_spec: spec.clone(),
            dry_run: false,
        })
    }

    // with_dry_run enables or disables dry-run mode. When enabled, no
    // actual operations are performed; commands are logged instead.
    pub fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }

    // flash burns the firmware image to the device via flint. The FlashSpec
    // provides the firmware source, optional device config, and cache dir.
    // Returns the local path of the resolved firmware image on success.
    //
    // This performs only the burn operation — no reset or verification.
    // For the full lifecycle, use apply().
    pub async fn flash(&self, spec: &FlashSpec) -> FirmwareResult<PathBuf> {
        let firmware = spec.build_firmware_source()?;
        let cache_dir = spec.cache_dir_or_default();

        tracing::info!(
            device = %self.device_id,
            source = %firmware.description(),
            "Starting firmware flash"
        );

        // Ensure the cache directory exists.
        tokio::fs::create_dir_all(&cache_dir)
            .await
            .map_err(FirmwareError::Io)?;

        // If a device config is configured, apply it before burning.
        if let Some(device_conf) = spec.build_device_conf_source()? {
            tracing::info!(source = %device_conf.description(), "Applying device config");

            let exec_options = ExecOptions::new().with_dry_run(self.dry_run);
            let applier = MlxConfigApplier::with_options(&self.device_id, exec_options);

            let conf_path = device_conf.resolve(&cache_dir).await?;
            tracing::debug!(path = %conf_path.display(), "Device config resolved");

            applier.apply(&conf_path)?;
            tracing::info!("Device config applied");
        }

        // Resolve the firmware source to a local path and burn.
        let firmware_path = firmware.resolve(&cache_dir).await?;
        tracing::debug!(path = %firmware_path.display(), "Firmware resolved");

        tracing::info!(device = %self.device_id, "Burning firmware via flint");

        let flint = if self.dry_run {
            FlintRunner::with_path("flint").with_dry_run(true)
        } else {
            FlintRunner::new().map_err(FirmwareError::FlintError)?
        };

        match flint.burn(&self.device_id, &firmware_path) {
            Ok(output) => {
                tracing::debug!(output = %output, "Flint output");
            }
            Err(crate::lockdown::error::MlxError::DryRun(cmd)) => {
                tracing::debug!(cmd = %cmd, "Dry run");
            }
            Err(e) => return Err(FirmwareError::FlintError(e)),
        };

        tracing::info!(
            device = %self.device_id,
            source = %firmware.description(),
            "Flash complete"
        );

        Ok(firmware_path)
    }

    // verify_image verifies the firmware on the device by comparing it
    // against a firmware image file. This runs flint's verify command:
    // `flint -d <dev> -i <image> verify`.
    //
    // If spec.verify_from_cache is true and a cached firmware file exists
    // in cache_dir, that file is used. Otherwise the firmware is resolved
    // from the source URL.
    pub async fn verify_image(&self, spec: &FlashSpec) -> FirmwareResult<String> {
        let cache_dir = spec.cache_dir_or_default();

        // Determine the image path. Attempt to use cache (per cache_dir)
        // if requested. Otherwise resolve + pull from the source. If not
        // found in the cache, also resolve + pull from the source.
        let image_path = if spec.verify_from_cache {
            // Look for an existing firmware file in cache_dir matching the
            // filename from the URL. If not found, fall back to resolving.
            let filename = spec
                .firmware_url
                .rsplit('/')
                .next()
                .unwrap_or("firmware.bin");
            let cached = cache_dir.join(filename);
            if cached.exists() {
                tracing::debug!(path = %cached.display(), "Using cached firmware for verify");
                cached
            } else {
                tracing::debug!("Cached firmware not found, resolving from source");
                let firmware = spec.build_firmware_source()?;
                firmware.resolve(&cache_dir).await?
            }
        } else {
            let firmware = spec.build_firmware_source()?;
            firmware.resolve(&cache_dir).await?
        };

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

        match flint.verify_image(&self.device_id, &image_path) {
            Ok(output) => {
                tracing::info!(device = %self.device_id, "Image verification passed");
                tracing::debug!(output = %output, "Flint verify output");
                Ok(output)
            }
            Err(crate::lockdown::error::MlxError::DryRun(cmd)) => {
                tracing::debug!(cmd = %cmd, "Dry run");
                Ok(format!("[DRY RUN] {cmd}"))
            }
            Err(e) => Err(FirmwareError::VerificationFailed(e.to_string())),
        }
    }

    // verify_version checks that the firmware version on the device
    // matches the version in the FirmwareSpec. Queries the device via
    // mlxfwmanager and compares. Returns Ok(Some(observed_version)) on
    // match, or Err on mismatch.
    pub fn verify_version(&self) -> FirmwareResult<Option<String>> {
        let expected = &self.firmware_spec.version;

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
            crate::device::discovery::discover_device(&self.device_id).map_err(|e| {
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

    // reset resets the device to activate the new firmware using the
    // default reset level (3).
    pub fn reset(&self) -> FirmwareResult<String> {
        self.reset_with_level(DEFAULT_RESET_LEVEL)
    }

    // reset_with_level resets the device via mlxfwreset at the specified
    // reset level.
    pub fn reset_with_level(&self, level: u8) -> FirmwareResult<String> {
        tracing::info!(
            device = %self.device_id,
            level = %level,
            "Resetting device via mlxfwreset"
        );

        let runner = if self.dry_run {
            MlxFwResetRunner::with_path("mlxfwreset").with_dry_run(true)
        } else {
            MlxFwResetRunner::new()?
        };

        match runner.reset(&self.device_id, level) {
            Ok(output) => {
                tracing::info!(device = %self.device_id, "Device reset complete");
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

    // apply executes the full firmware lifecycle from a FirmwareFlasherProfile:
    //
    //   1. Flash firmware (burn via flint) — Err = burn failed, caller retries
    //   2. Reset device via mlxfwreset (if flash_options.reset)
    //   3. Verify firmware image via flint verify (if flash_options.verify_image)
    //   4. Verify firmware version (if flash_options.verify_version)
    //
    // Returns Err if the flash itself fails (step 1).
    // For post-flash steps (2-4), failures are captured in the
    // returned FirmwareFlashReport rather than returning an error,
    // so the caller always gets visibility into what happened, which
    // in this case is useful for scout logging + reporting back to
    // carbide-api which part(s) failed.
    pub async fn apply(
        &self,
        profile: &FirmwareFlasherProfile,
    ) -> FirmwareResult<FirmwareFlashReport> {
        let options = &profile.flash_options;

        // Step 1: Flash firmware.
        self.flash(&profile.flash_spec).await?;

        // Step 2: Reset device (if enabled).
        let reset_result = if options.reset {
            Some(match self.reset_with_level(options.reset_level) {
                Ok(_) => true,
                Err(e) => {
                    tracing::error!(device = %self.device_id, %e, "post-flash reset failed");
                    false
                }
            })
        } else {
            tracing::debug!(device = %self.device_id, "reset not enabled, skipping");
            None
        };

        // Step 3: Verify firmware image (if enabled).
        let verified_image = if options.verify_image {
            Some(match self.verify_image(&profile.flash_spec).await {
                Ok(_) => true,
                Err(e) => {
                    tracing::error!(device = %self.device_id, %e, "post-flash image verification failed");
                    false
                }
            })
        } else {
            tracing::debug!(device = %self.device_id, "image verification not enabled, skipping");
            None
        };

        // Step 4: Verify firmware version (if enabled).
        let (observed_version, verified_version) = if options.verify_version {
            let observed = match crate::device::discovery::discover_device(&self.device_id) {
                Ok(info) => info.fw_version_current,
                Err(e) => {
                    tracing::error!(
                        device = %self.device_id, %e,
                        "failed to query device for observed firmware version"
                    );
                    None
                }
            };

            let expected = &self.firmware_spec.version;
            let verified = match &observed {
                Some(obs) => {
                    let matched = obs == expected;
                    if matched {
                        tracing::info!(
                            device = %self.device_id,
                            observed_version = %obs,
                            expected_version = %expected,
                            "firmware version verified"
                        );
                    } else {
                        tracing::warn!(
                            device = %self.device_id,
                            observed_version = %obs,
                            expected_version = %expected,
                            "firmware version mismatch"
                        );
                    }
                    Some(matched)
                }
                None => {
                    tracing::warn!(
                        device = %self.device_id,
                        expected_version = %expected,
                        "could not query device for observed firmware version"
                    );
                    Some(false)
                }
            };

            (observed, verified)
        } else {
            tracing::debug!(device = %self.device_id, "version verification not enabled, skipping");
            (None, None)
        };

        let report = FirmwareFlashReport {
            flashed: true,
            reset: reset_result,
            verified_image,
            verified_version,
            observed_version,
            expected_version: Some(self.firmware_spec.version.clone()),
        };

        tracing::info!(
            device = %self.device_id,
            flashed = report.flashed,
            reset = ?report.reset,
            verified_image = ?report.verified_image,
            verified_version = ?report.verified_version,
            observed_version = report.observed_version.as_deref().unwrap_or("none"),
            expected_version = report.expected_version.as_deref().unwrap_or("none"),
            "firmware lifecycle complete"
        );

        Ok(report)
    }
}
