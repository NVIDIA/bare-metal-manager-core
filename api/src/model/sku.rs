use std::{collections::HashMap, fmt::Display};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgRow, FromRow, Row};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Sku {
    pub id: String,
    pub description: String,
    pub created: DateTime<Utc>,
    pub components: SkuComponents,
}

impl<'r> FromRow<'r, PgRow> for Sku {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let id: String = row.try_get("id")?;
        let description: String = row.try_get("description")?;
        let created: DateTime<Utc> = row.try_get("created")?;
        let components = row
            .try_get::<sqlx::types::Json<SkuComponents>, _>("components")?
            .0;

        Ok(Sku {
            id,
            description,
            created,
            components,
        })
    }
}

impl From<Sku> for rpc::forge::Sku {
    fn from(value: Sku) -> Self {
        rpc::forge::Sku {
            id: value.id,
            description: Some(value.description),
            created: Some(value.created.into()),
            components: Some(value.components.into()),
            machines_associated_count: 0,
        }
    }
}

impl From<rpc::forge::Sku> for Sku {
    fn from(value: rpc::forge::Sku) -> Self {
        let timestamp = value.created.unwrap();

        let created = DateTime::<Utc>::try_from(timestamp).unwrap_or_default();

        Sku {
            id: value.id,
            description: value.description.unwrap_or_default(),
            created,
            components: value.components.unwrap_or_default().into(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SkuComponents {
    pub chassis: SkuComponentChassis,
    pub cpus: Vec<SkuComponentCpu>,
    pub gpus: Vec<SkuComponentGpu>,
    pub memory: Vec<SkuComponentMemory>,
}

impl From<rpc::forge::SkuComponents> for SkuComponents {
    fn from(value: rpc::forge::SkuComponents) -> Self {
        SkuComponents {
            chassis: value.chassis.unwrap_or_default().into(),
            cpus: value.cpus.into_iter().map(|c| c.into()).collect(),
            gpus: value.gpus.into_iter().map(|g| g.into()).collect(),
            memory: value.memory.into_iter().map(|m| m.into()).collect(),
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
            ethernet_adapters: Vec::default(),
            infiniband_adapters: Vec::default(),
            storage: Vec::default(),
            memory: value
                .memory
                .into_iter()
                .map(std::convert::Into::into)
                .collect(),
            tpm: Vec::default(),
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

#[derive(Clone, Debug, Deserialize, Serialize)]
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

#[derive(Clone, Debug, Deserialize, Serialize)]
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

#[derive(Clone, Debug, Deserialize, Serialize)]
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

// Store information for communication between the state
// machine and other components.  This is kept as a json
// field in the machines table
#[derive(Clone, Debug, Default, Deserialize, FromRow, Serialize)]
pub struct SkuStatus {
    // The time of the last SKU validation request or None.
    // used by the state machine to determing if a machine needs
    // to be validated against its assigned SKU
    pub verify_request_time: Option<DateTime<Utc>>,
}

impl From<rpc::forge::SkuStatus> for SkuStatus {
    fn from(value: rpc::forge::SkuStatus) -> Self {
        let verify_request_time = value
            .verify_request_time
            .map(|t| DateTime::<Utc>::try_from(t).unwrap_or_default());

        SkuStatus {
            verify_request_time,
        }
    }
}

impl From<SkuStatus> for rpc::forge::SkuStatus {
    fn from(value: SkuStatus) -> Self {
        rpc::forge::SkuStatus {
            verify_request_time: value.verify_request_time.map(|t| t.into()),
        }
    }
}

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
            "Number of CPUs ({}) does not match expected ({})",
            actual_cpu_count, expected_cpu_count
        ));
    }

    let mut expected_gpus: HashMap<(&str, &str), &SkuComponentGpu> = expected_sku
        .components
        .gpus
        .iter()
        .map(|gpu| ((gpu.model.as_str(), gpu.total_memory.as_str()), gpu))
        .collect();

    for actual_gpu in actual_sku.components.gpus.iter() {
        match expected_gpus.remove(&(actual_gpu.model.as_str(), actual_gpu.total_memory.as_str())) {
            None => diffs.push(format!("Unexpected GPU config ({}) found", actual_gpu)),
            Some(expected_gpu) => {
                if actual_gpu.count != expected_gpu.count {
                    diffs.push(format!(
                        "Expected gpu count ({}) does not match actual ({}) for gpu model({})",
                        expected_gpu.count, actual_gpu.count, expected_gpu.model
                    ));
                }
            }
        }
    }

    for missing_gpu in expected_gpus.values() {
        diffs.push(format!("Missing GPU config: {}", missing_gpu));
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
            "Actaul memory ({}) differs from expected ({})",
            expected_total_memory, actual_total_memory
        ));
    }
    diffs
}
