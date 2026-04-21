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

use std::cmp::Ordering;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs;
use std::path::PathBuf;
use std::time::SystemTime;

use model::DpuModel;
use model::firmware::Firmware;
use model::site_explorer::{EndpointExplorationReport, ExploredEndpoint};
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub struct FirmwareConfigSnapshot {
    pub(crate) data: HashMap<String, Firmware>,
}

impl FirmwareConfigSnapshot {
    pub fn values(&self) -> impl Iterator<Item = &Firmware> {
        self.data.values()
    }

    pub fn into_values(self) -> impl Iterator<Item = Firmware> {
        self.data.into_values()
    }

    pub fn find(&self, vendor: bmc_vendor::BMCVendor, model: &str) -> Option<Firmware> {
        let dpu_model = DpuModel::from(model);
        let key = if dpu_model != DpuModel::Unknown {
            vendor_model_to_key(vendor, &dpu_model.to_string())
        } else {
            vendor_model_to_key(vendor, model)
        };
        let ret = self.data.get(&key).map(|x| x.to_owned());
        tracing::debug!("FirmwareConfig::find: key {key} found {ret:?}");
        ret
    }

    /// find_fw_info_for_host looks up the firmware config for the given endpoint
    pub fn find_fw_info_for_host(&self, endpoint: &ExploredEndpoint) -> Option<Firmware> {
        self.find_fw_info_for_host_report(&endpoint.report)
    }

    /// find_fw_info_for_host_report looks up the firmware config for the given endpoint report
    pub fn find_fw_info_for_host_report(
        &self,
        report: &EndpointExplorationReport,
    ) -> Option<Firmware> {
        report.vendor.and_then(|vendor| {
            // Use report.model if it is already filled or use model()
            // function to extract model from the report.
            report
                .model
                .as_ref()
                .and_then(|model| self.find(vendor, model))
                .or_else(|| report.model().and_then(|model| self.find(vendor, &model)))
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct FirmwareConfig {
    base_map: HashMap<String, Firmware>,
    firmware_directory: PathBuf,
    #[cfg(test)]
    test_overrides: Vec<String>,
}

impl FirmwareConfig {
    pub fn new(
        firmware_dir: PathBuf,
        host_models: &HashMap<String, Firmware>,
        dpu_models: &HashMap<String, Firmware>,
    ) -> Self {
        let mut base_map: HashMap<String, Firmware> = Default::default();
        for host in host_models.values() {
            base_map.insert(vendor_model_to_key(host.vendor, &host.model), host.clone());
        }
        for dpu in dpu_models.values() {
            base_map.insert(
                vendor_model_to_key(
                    dpu.vendor,
                    &DpuModel::from(dpu.model.to_owned()).to_string(),
                ),
                dpu.clone(),
            );
        }
        Self {
            base_map,
            firmware_directory: firmware_dir,
            #[cfg(test)]
            test_overrides: vec![],
        }
    }

    pub fn create_snapshot(&self) -> FirmwareConfigSnapshot {
        let mut data = self.base_map.clone();
        if self.firmware_directory.to_string_lossy() != "" {
            self.merge_firmware_configs(&mut data, &self.firmware_directory);
        }

        #[cfg(test)]
        {
            // Fake configs to merge for unit tests
            for ovrd in &self.test_overrides {
                if let Err(err) = self.merge_from_string(&mut data, ovrd.clone()) {
                    tracing::error!("Bad override {ovrd}: {err}");
                }
            }
        }

        FirmwareConfigSnapshot { data }
    }

    pub fn config_update_time(&self) -> Option<std::time::SystemTime> {
        if self.firmware_directory.to_string_lossy() == "" {
            return None;
        }

        let metadata = std::fs::metadata(self.firmware_directory.clone()).ok()?;

        metadata.modified().ok()
    }

    fn merge_firmware_configs(
        &self,
        map: &mut HashMap<String, Firmware>,
        firmware_directory: &PathBuf,
    ) {
        if !firmware_directory.is_dir() {
            tracing::error!("Missing firmware directory {:?}", firmware_directory);
            return;
        }

        for dir in subdirectories_sorted_by_modification_date(firmware_directory) {
            if dir
                .path()
                .file_name()
                .unwrap_or(OsStr::new("."))
                .to_string_lossy()
                .starts_with(".")
            {
                continue;
            }
            let metadata_path = dir.path().join("metadata.toml");
            let metadata = match fs::read_to_string(metadata_path.clone()) {
                Ok(str) => str,
                Err(e) => {
                    tracing::error!("Could not read {metadata_path:?}: {e}");
                    continue;
                }
            };
            if let Err(e) = self.merge_from_string(map, metadata) {
                tracing::error!("Failed to merge in metadata from {:?}: {e}", dir.path());
            }
        }
    }

    /// merge_from_string adds the given TOML based config to this Firmware.  Figment based merging won't work for this,
    /// as we want to append new FirmwareEntry instances instead of overwriting.  It is expected that this will be called
    /// on the metadata in order of oldest creation time to newest.
    fn merge_from_string(
        &self,
        map: &mut HashMap<String, Firmware>,
        config_str: String,
    ) -> eyre::Result<()> {
        let cfg: Firmware = toml::from_str(config_str.as_str())?;
        let key = vendor_model_to_key(cfg.vendor, &cfg.model);

        let Some(cur_model) = map.get_mut(&key) else {
            // We haven't seen this model before, so use this as given.
            map.insert(key, cfg);
            return Ok(());
        };

        if !cfg.ordering.is_empty() {
            // Newer ordering definitions take precedence.  For now we don't consider this at a specific version level.
            cur_model.ordering = cfg.ordering
        }

        // if explicit_start_needed is true, it should take precedence. We shouldn't be doing automatic upgrades.
        if cfg.explicit_start_needed {
            cur_model.explicit_start_needed = true;
        }

        for (new_type, new_component) in cfg.components {
            if let Some(cur_component) = cur_model.components.get_mut(&new_type) {
                // The simple fields from the newer version should be used if specified
                if new_component.current_version_reported_as.is_some() {
                    cur_component.current_version_reported_as =
                        new_component.current_version_reported_as;
                }
                if new_component.preingest_upgrade_when_below.is_some() {
                    cur_component.preingest_upgrade_when_below =
                        new_component.preingest_upgrade_when_below;
                }
                if new_component.known_firmware.iter().any(|x| x.default) {
                    // The newer one lists a default, remove default from the old.
                    cur_component.known_firmware = cur_component
                        .known_firmware
                        .iter()
                        .map(|x| {
                            let mut x = x.clone();
                            x.default = false;
                            x
                        })
                        .collect();
                }
                cur_component
                    .known_firmware
                    .extend(new_component.known_firmware.iter().cloned());
            } else {
                // Nothing for this component
                cur_model.components.insert(new_type, new_component);
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn add_test_override(&mut self, ovrd: String) {
        self.test_overrides.push(ovrd);
    }
}

fn vendor_model_to_key(vendor: bmc_vendor::BMCVendor, model: &str) -> String {
    format!("{vendor}:{}", model.to_lowercase())
}

fn subdirectories_sorted_by_modification_date(topdir: &PathBuf) -> Vec<fs::DirEntry> {
    let Ok(dirs) = topdir.read_dir() else {
        tracing::error!("Unreadable firmware directory {:?}", topdir);
        return vec![];
    };

    // We sort in ascending modification time so that we will use the newest made firmware metadata
    let mut dirs: Vec<fs::DirEntry> = dirs.filter_map(|x| x.ok()).collect();
    dirs.sort_unstable_by(|x, y| {
        let x_time = match x.metadata() {
            Err(_) => SystemTime::now(),
            Ok(x) => match x.modified() {
                Err(_) => SystemTime::now(),
                Ok(x) => x,
            },
        };
        let y_time = match y.metadata() {
            Err(_) => SystemTime::now(),
            Ok(y) => match y.modified() {
                Err(_) => SystemTime::now(),
                Ok(y) => y,
            },
        };
        x_time.partial_cmp(&y_time).unwrap_or(Ordering::Equal)
    });
    dirs
}
