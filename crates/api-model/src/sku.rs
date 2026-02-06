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

impl From<Sku> for rpc::forge::Sku {
    fn from(value: Sku) -> Self {
        rpc::forge::Sku {
            schema_version: value.schema_version,
            id: value.id,
            description: Some(value.description),
            created: Some(value.created.into()),
            components: Some(value.components.into()),
            // filled in afterwards
            associated_machine_ids: Vec::default(),
            device_type: value.device_type,
        }
    }
}

impl From<rpc::forge::Sku> for Sku {
    fn from(value: rpc::forge::Sku) -> Self {
        Sku {
            schema_version: value.schema_version,
            id: value.id,
            description: value.description.unwrap_or_default(),
            // Handle optional created field - if not provided, use current time
            created: value
                .created
                .and_then(|t| DateTime::<Utc>::try_from(t).ok())
                .unwrap_or_else(Utc::now),
            components: value.components.unwrap_or_default().into(),
            device_type: value.device_type,
        }
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

impl From<rpc::forge::SkuComponents> for SkuComponents {
    fn from(value: rpc::forge::SkuComponents) -> Self {
        SkuComponents {
            chassis: value.chassis.unwrap_or_default().into(),
            cpus: value
                .cpus
                .into_iter()
                .map(std::convert::Into::into)
                .collect(),
            gpus: value
                .gpus
                .into_iter()
                .map(std::convert::Into::into)
                .collect(),
            memory: value
                .memory
                .into_iter()
                .map(std::convert::Into::into)
                .collect(),
            infiniband_devices: value
                .infiniband_devices
                .into_iter()
                .map(std::convert::Into::into)
                .collect(),
            storage: value
                .storage
                .into_iter()
                .map(std::convert::Into::into)
                .collect(),
            tpm: value.tpm.map(std::convert::Into::into),
        }
    }
}

impl From<SkuComponents> for rpc::forge::SkuComponents {
    fn from(value: SkuComponents) -> Self {
        rpc::forge::SkuComponents {
            chassis: Some(value.chassis.into()),
            cpus: value
                .cpus
                .into_iter()
                .map(std::convert::Into::into)
                .collect(),
            gpus: value
                .gpus
                .into_iter()
                .map(std::convert::Into::into)
                .collect(),
            ethernet_devices: Vec::default(),
            infiniband_devices: value
                .infiniband_devices
                .into_iter()
                .map(std::convert::Into::into)
                .collect(),
            storage: value
                .storage
                .into_iter()
                .map(std::convert::Into::into)
                .collect(),
            memory: value
                .memory
                .into_iter()
                .map(std::convert::Into::into)
                .collect(),
            tpm: value.tpm.map(std::convert::Into::into),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct SkuComponentChassis {
    pub vendor: String,
    pub model: String,
    pub architecture: String,
}

impl From<rpc::forge::SkuComponentChassis> for SkuComponentChassis {
    fn from(value: rpc::forge::SkuComponentChassis) -> Self {
        SkuComponentChassis {
            vendor: value.vendor,
            model: value.model,
            architecture: value.architecture,
        }
    }
}

impl From<SkuComponentChassis> for rpc::forge::SkuComponentChassis {
    fn from(value: SkuComponentChassis) -> Self {
        rpc::forge::SkuComponentChassis {
            vendor: value.vendor,
            model: value.model,
            architecture: value.architecture,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd)]
pub struct SkuComponentCpu {
    pub vendor: String,
    pub model: String,
    pub thread_count: u32,
    pub count: u32,
}

impl From<rpc::forge::SkuComponentCpu> for SkuComponentCpu {
    fn from(value: rpc::forge::SkuComponentCpu) -> Self {
        SkuComponentCpu {
            vendor: value.vendor,
            model: value.model,
            count: value.count,
            thread_count: value.thread_count,
        }
    }
}

impl From<SkuComponentCpu> for rpc::forge::SkuComponentCpu {
    fn from(value: SkuComponentCpu) -> Self {
        rpc::forge::SkuComponentCpu {
            vendor: value.vendor,
            model: value.model,
            count: value.count,
            thread_count: value.thread_count,
        }
    }
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

impl From<rpc::forge::SkuComponentGpu> for SkuComponentGpu {
    fn from(value: rpc::forge::SkuComponentGpu) -> Self {
        SkuComponentGpu {
            vendor: value.vendor,
            model: value.model,
            total_memory: value.total_memory,
            count: value.count,
        }
    }
}

impl From<SkuComponentGpu> for rpc::forge::SkuComponentGpu {
    fn from(value: SkuComponentGpu) -> Self {
        rpc::forge::SkuComponentGpu {
            vendor: value.vendor,
            model: value.model,
            total_memory: value.total_memory,
            count: value.count,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd)]
pub struct SkuComponentMemory {
    pub memory_type: String,
    pub capacity_mb: u32,
    pub count: u32,
}

impl From<rpc::forge::SkuComponentMemory> for SkuComponentMemory {
    fn from(value: rpc::forge::SkuComponentMemory) -> Self {
        SkuComponentMemory {
            memory_type: value.memory_type,
            capacity_mb: value.capacity_mb,
            count: value.count,
        }
    }
}

impl From<SkuComponentMemory> for rpc::forge::SkuComponentMemory {
    fn from(value: SkuComponentMemory) -> Self {
        rpc::forge::SkuComponentMemory {
            memory_type: value.memory_type,
            capacity_mb: value.capacity_mb,
            count: value.count,
        }
    }
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

impl From<rpc::forge::SkuComponentInfinibandDevices> for SkuComponentInfinibandDevices {
    fn from(value: rpc::forge::SkuComponentInfinibandDevices) -> Self {
        SkuComponentInfinibandDevices {
            vendor: value.vendor,
            model: value.model,
            count: value.count,
            inactive_devices: value.inactive_devices,
        }
    }
}

impl From<SkuComponentInfinibandDevices> for rpc::forge::SkuComponentInfinibandDevices {
    fn from(value: SkuComponentInfinibandDevices) -> Self {
        rpc::forge::SkuComponentInfinibandDevices {
            vendor: value.vendor,
            model: value.model,
            count: value.count,
            inactive_devices: value.inactive_devices,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd)]
pub struct SkuComponentStorage {
    pub model: String,
    pub count: u32,
}

impl From<rpc::forge::SkuComponentStorage> for SkuComponentStorage {
    fn from(value: rpc::forge::SkuComponentStorage) -> Self {
        SkuComponentStorage {
            model: value.model,
            count: value.count,
        }
    }
}

impl From<SkuComponentStorage> for rpc::forge::SkuComponentStorage {
    fn from(value: SkuComponentStorage) -> Self {
        rpc::forge::SkuComponentStorage {
            vendor: String::default(),
            model: value.model,
            capacity_mb: 0u32,
            count: value.count,
        }
    }
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

impl From<rpc::forge::SkuComponentTpm> for SkuComponentTpm {
    fn from(value: rpc::forge::SkuComponentTpm) -> Self {
        SkuComponentTpm {
            vendor: value.vendor,
            version: value.version,
        }
    }
}

impl From<SkuComponentTpm> for rpc::forge::SkuComponentTpm {
    fn from(value: SkuComponentTpm) -> Self {
        rpc::forge::SkuComponentTpm {
            vendor: value.vendor,
            version: value.version,
        }
    }
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

impl From<rpc::forge::SkuStatus> for SkuStatus {
    fn from(value: rpc::forge::SkuStatus) -> Self {
        let verify_request_time = value
            .verify_request_time
            .map(|t| DateTime::<Utc>::try_from(t).unwrap_or_default());
        let last_match_attempt = value
            .last_match_attempt
            .map(|t| DateTime::<Utc>::try_from(t).unwrap_or_default());
        let last_generate_attempt = value
            .last_generate_attempt
            .map(|t| DateTime::<Utc>::try_from(t).unwrap_or_default());

        SkuStatus {
            verify_request_time,
            last_match_attempt,
            last_generate_attempt,
        }
    }
}

impl From<SkuStatus> for rpc::forge::SkuStatus {
    fn from(value: SkuStatus) -> Self {
        rpc::forge::SkuStatus {
            verify_request_time: value.verify_request_time.map(|t| t.into()),
            last_match_attempt: value.last_match_attempt.map(|t| t.into()),
            last_generate_attempt: value.last_generate_attempt.map(|t| t.into()),
        }
    }
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
