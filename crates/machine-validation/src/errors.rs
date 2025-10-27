#[derive(thiserror::Error, Debug)]
pub enum MachineValidationError {
    #[error("Machine Validation: {0}")]
    Generic(String),
    #[error("Unable to config read: {0}")]
    ConfigFileRead(String),
    #[error("Yaml parse error: {0}")]
    Parse(String),
    #[error("{0}: {1}")]
    File(String, String),
    #[error("Failed {0}: {1}")]
    ApiClient(String, String),
}
