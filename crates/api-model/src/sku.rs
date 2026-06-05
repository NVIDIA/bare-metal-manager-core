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
use std::fmt::{Display, Write};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Row};

use super::hardware_info::CpuInfo;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Sku {
    pub schema_version: u32,
    pub id: String,
    pub description: String,
    pub created: DateTime<Utc>,
    pub components: SkuComponents,
    pub device_type: Option<String>,
}

impl<'r> FromRow<'r, PgRow> for Sku {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let schema_version: u32 = row.try_get::<i32, &str>("schema_version")? as u32;
        let id: String = row.try_get("id")?;
        let description: String = row.try_get("description")?;
        let created: DateTime<Utc> = row.try_get("created")?;
        let components = row
            .try_get::<sqlx::types::Json<SkuComponents>, _>("components")?
            .0;
        let device_type = row.try_get("device_type")?;
        Ok(Sku {
            schema_version,
            id,
            description,
            created,
            components,
            device_type,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SkuComponents {
    pub chassis: SkuComponentChassis,
    pub cpus: Vec<SkuComponentCpu>,
    pub gpus: Vec<SkuComponentGpu>,
    pub memory: Vec<SkuComponentMemory>,
    pub infiniband_devices: Vec<SkuComponentInfinibandDevices>,
    #[serde(default)]
    pub storage: Vec<SkuComponentStorage>,
    #[serde(default)]
    pub tpm: Option<SkuComponentTpm>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct SkuComponentChassis {
    pub vendor: String,
    pub model: String,
    pub architecture: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd)]
pub struct SkuComponentCpu {
    pub vendor: String,
    pub model: String,
    pub thread_count: u32,
    pub count: u32,
}

impl From<&CpuInfo> for SkuComponentCpu {
    fn from(value: &CpuInfo) -> Self {
        SkuComponentCpu {
            vendor: value.vendor.clone(),
            model: value.model.clone(),
            count: value.sockets,
            thread_count: value.threads,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd)]
pub struct SkuComponentGpu {
    pub vendor: String,
    pub model: String,
    pub total_memory: String,
    pub count: u32,
}

impl Display for SkuComponentGpu {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}x{}/{}", self.count, self.vendor, self.model)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd)]
pub struct SkuComponentMemory {
    pub memory_type: String,
    pub capacity_mb: u32,
    pub count: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Ord, PartialOrd)]
pub struct SkuComponentInfinibandDevices {
    /// The Vendor of the InfiniBand device. E.g. `Mellanox`
    pub vendor: String,
    /// The Device Name of the InfiniBand device. E.g. `MT2910 Family [ConnectX-7]`
    pub model: String,
    /// The total amount of InfiniBand devices of the given
    /// vendor and model combination
    pub count: u32,
    /// The indexes of InfiniBand Devices which are not active and thereby can
    /// not be utilized by Instances.
    /// Inactive devices are devices where for example there is no connection
    /// between the port and the InfiniBand switch.
    /// Example: A `{count: 4, inactive_devices: [1,3]}` means that the devices
    /// with index `0` and `2` of the Host can be utilized, and devices with index
    /// `1` and `3` can not be used.
    pub inactive_devices: Vec<u32>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd)]
pub struct SkuComponentStorage {
    pub model: String,
    pub count: u32,
}

impl Display for SkuComponentStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "model: {} count {}", self.model, self.count)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd)]
pub struct SkuComponentTpm {
    pub vendor: String,
    pub version: String,
}

impl Display for SkuComponentTpm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "vendor: {} version: {}", self.vendor, self.version)
    }
}

// Store information for communication between the state
// machine and other components.  This is kept as a json
// field in the machines table
#[derive(Clone, Debug, Default, Deserialize, FromRow, Serialize)]
pub struct SkuStatus {
    // The time of the last SKU validation request or None.
    // used by the state machine to determing if a machine needs
    // to be validated against its assigned SKU
    pub verify_request_time: Option<DateTime<Utc>>,
    // Periodically the state machine will attempt to find a match
    // for this machine.  This is the last time an attempt was made.
    // None means no attempt has been made.  This value is not valid
    // if the machine has a SKU assigned.
    pub last_match_attempt: Option<DateTime<Utc>>,
    // If the a SKU is assinged in expected machines but is missing,
    // the state machine will attempt to create it from generated
    // machine data.  This marks the last time an attempt was made.
    // None means no attempt has been made.  This value is not valid
    // if the assigned SKU exists or the assigned SKU is not from the
    // expected machine.
    pub last_generate_attempt: Option<DateTime<Utc>>,
}

/// diff an actual sku against an expected sku and return the differences.
///
/// Note that the version check is done on the expected_sku so order of arguements is important.
/// SKUs with different versions may match one way, but not the other.
pub fn diff_skus(actual_sku: &Sku, expected_sku: &Sku) -> Vec<String> {
    let mut diffs = Vec::default();

    if actual_sku.components.chassis.model != expected_sku.components.chassis.model {
        diffs.push(format!(
            r#"Actual chassis model "{}" does not match expected "{}""#,
            actual_sku.components.chassis.model, expected_sku.components.chassis.model
        ));
    }
    if actual_sku.components.chassis.architecture != expected_sku.components.chassis.architecture {
        diffs.push(format!(
            r#"Actual chassis architecture "{}" does not match expected "{}""#,
            actual_sku.components.chassis.architecture,
            expected_sku.components.chassis.architecture
        ));
    }

    let expected_cpu_count = expected_sku
        .components
        .cpus
        .iter()
        .map(|c| c.count)
        .sum::<u32>();
    let actual_cpu_count = actual_sku
        .components
        .cpus
        .iter()
        .map(|c| c.count)
        .sum::<u32>();

    if expected_cpu_count != actual_cpu_count {
        diffs.push(format!(
            "Number of CPUs ({actual_cpu_count}) does not match expected ({expected_cpu_count})"
        ));
    }

    let expected_thread_count = expected_sku
        .components
        .cpus
        .iter()
        .map(|c| c.thread_count)
        .sum::<u32>();
    let actual_thread_count = actual_sku
        .components
        .cpus
        .iter()
        .map(|c| c.thread_count)
        .sum::<u32>();

    if expected_thread_count != actual_thread_count {
        diffs.push(format!(
            "Number of CPU threads ({actual_thread_count}) does not match expected ({expected_thread_count})"
        ));
    }

    // FORGE-6856: Disable checking of VRAM because the value can change if ECC mode is enabled on the GPU.
    let mut expected_gpus: HashMap<&str, &SkuComponentGpu> = expected_sku
        .components
        .gpus
        .iter()
        .map(|gpu| (gpu.model.as_str(), gpu))
        .collect();

    for actual_gpu in actual_sku.components.gpus.iter() {
        match expected_gpus.remove(&actual_gpu.model.as_str()) {
            None => diffs.push(format!("Unexpected GPU config ({actual_gpu}) found")),
            Some(expected_gpu) => {
                if actual_gpu.count != expected_gpu.count {
                    diffs.push(format!(
                        "Expected gpu count ({}) does not match actual ({}) for gpu model ({})",
                        expected_gpu.count, actual_gpu.count, expected_gpu.model
                    ));
                }
            }
        }
    }

    for missing_gpu in expected_gpus.values() {
        diffs.push(format!("Missing GPU config: {missing_gpu}"));
    }

    let mut expected_ib_device_by_name: HashMap<
        (&String, &String),
        &SkuComponentInfinibandDevices,
    > = HashMap::new();
    for ib_devices in expected_sku.components.infiniband_devices.iter() {
        expected_ib_device_by_name.insert((&ib_devices.vendor, &ib_devices.model), ib_devices);
    }

    for actual_ib_device_definition in actual_sku.components.infiniband_devices.iter() {
        match expected_ib_device_by_name.remove(&(
            &actual_ib_device_definition.vendor,
            &actual_ib_device_definition.model,
        )) {
            Some(expected) => {
                if expected != actual_ib_device_definition {
                    let mut msg = format!(
                        "Configuration mismatch for InfiniBand devices of Vendor: \"{}\" and Model: \"{}\". ",
                        expected.vendor, expected.model
                    );
                    write!(
                        &mut msg,
                        "Expected \"count: {}, inactive_devices: {:?}\". ",
                        expected.count, expected.inactive_devices
                    )
                    .unwrap();
                    write!(
                        &mut msg,
                        "Actual \"count: {}, inactive_devices: {:?}\". ",
                        actual_ib_device_definition.count,
                        actual_ib_device_definition.inactive_devices
                    )
                    .unwrap();
                    diffs.push(msg);
                }
            }
            None => {
                diffs.push(format!(
                    "Unexpected {} InfiniBand devices of Vendor: \"{}\" and Model: \"{}\"",
                    actual_ib_device_definition.count,
                    actual_ib_device_definition.vendor,
                    actual_ib_device_definition.model
                ));
            }
        }
    }
    for missing_ib_devices in expected_ib_device_by_name.values() {
        diffs.push(format!(
            "Missing {} InfiniBand devices of Vendor: \"{}\" and Model: \"{}\"",
            missing_ib_devices.count, missing_ib_devices.vendor, missing_ib_devices.model
        ));
    }

    let actual_total_memory = actual_sku
        .components
        .memory
        .iter()
        .fold(0, |a, m| a + (m.capacity_mb * m.count));
    let expected_total_memory = expected_sku
        .components
        .memory
        .iter()
        .fold(0, |a, m| a + (m.capacity_mb * m.count));

    if expected_total_memory != actual_total_memory {
        diffs.push(format!(
            "Actual memory ({expected_total_memory}) differs from expected ({actual_total_memory})"
        ));
    }

    let mut actual_storage: HashMap<String, SkuComponentStorage> = actual_sku
        .components
        .storage
        .iter()
        .map(|s| (s.model.clone(), s.clone()))
        .collect();

    for es in &expected_sku.components.storage {
        if let Some(actual_storage) = actual_storage.remove(&es.model) {
            if actual_storage.count != es.count {
                diffs.push(format!(
                    "Expected device count ({}) does not match actual ({}) for storage model ({})",
                    es.count, actual_storage.count, actual_storage.model,
                ));
            }
        } else {
            diffs.push(format!("Missing storage config: {es}"));
        };
    }
    for s in actual_storage.values() {
        diffs.push(format!("Found unexpected storage config: {s}"));
    }

    // Vendor and Model fields do not contain useful information.  They seem limited and encoded somehow.
    // We really only care about the spec version supported and that a TPM exists.
    match (&actual_sku.components.tpm, &expected_sku.components.tpm) {
        (None, None) => {}
        (None, Some(expected_tpm)) => diffs.push(format!(
            "Missing a TPM module: version: {}",
            expected_tpm.version
        )),
        (Some(actual_tpm), None) => diffs.push(format!(
            "Found unexpected TPM config: version: {}",
            actual_tpm.version
        )),
        (Some(actual_tpm), Some(expected_tpm)) => {
            if actual_tpm.version != expected_tpm.version {
                diffs.push(format!(
                    "Expected TPM version ({}) does not match actual ({})",
                    expected_tpm.version, actual_tpm.version
                ));
            }
        }
    }
    diffs
}
