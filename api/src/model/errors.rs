use forge_uuid::machine::MachineId;

use crate::model::hardware_info::HardwareInfoError;

/// Errors specifically for the (eventual) models crate
#[derive(thiserror::Error, Debug)]
pub enum ModelError {
    #[error("Failed to map device to dpu: {0}")]
    DpuMappingError(String),
    #[error("DPU {0} is missing from host snapshot")]
    MissingDpu(MachineId),
    #[error("Database type conversion error: {0}")]
    DatabaseTypeConversionError(String),
    #[error("Argument is missing in input: {0}")]
    MissingArgument(&'static str),
    #[error("Hardware info error: {0}")]
    HardwareInfo(#[from] HardwareInfoError),
    #[error("Argument is invalid: {0}")]
    InvalidArgument(String),
}

pub type ModelResult<T> = Result<T, ModelError>;
