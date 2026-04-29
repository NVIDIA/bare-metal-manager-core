use carbide_uuid::machine::MachineIdParseError;
use thiserror::Error;

/// Top-level RVS error type.
#[derive(Debug, Error)]
pub enum RvsError {
    /// gRPC call to NICC failed.
    #[error("NICC RPC error: {0}")]
    Rpc(#[from] tonic::Status),

    /// Tray ID string couldn't be parsed as MachineId.
    #[error("Failed to parse Machine ID: {0}")]
    InvalidMachineId(#[from] MachineIdParseError),

    /// An ID string couldn't be parsed as a UUID-based type.
    #[allow(dead_code)]
    #[error("Failed to parse ID: {0}")]
    InvalidId(String),

    /// NICC returned an unexpected number of machines for a single-ID query.
    #[error("Expected 1 machine for tray {tray_id}, got {count}")]
    UnexpectedMachineCount { tray_id: String, count: usize },

    /// A required gRPC message field was missing (would carry invalid data forward).
    #[error("{0}")]
    MissingField(&'static str),

    /// Invalid or missing command-line argument.
    #[error("Invalid argument: {0}")]
    InvalidArg(String),

    /// Configuration loading failed.
    #[error("Config error: {0}")]
    Config(String),

    /// I/O error (e.g. binding a TCP listener).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
