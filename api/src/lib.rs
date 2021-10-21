use eui48::MacAddress;
use log::info;
use std::net::IpAddr;

pub mod db;
mod human_hash;

/// Special user-defined code for PostgreSQL level state transition violation
///
/// This error code is generated when we attempt to move a machine to a new desired state that is
/// an invalid transition (e.g. transitioning from `adopted` to `allocated` is impossible because
/// it requires hardware testing and validation first)
///
const SQL_STATE_TRANSITION_VIOLATION_CODE: &str = "T0100";

/// Represents various Errors that can occur throughout the system.
///
/// CarbideError is a way to represent and enrich lower-level errors with specific business logic
/// that can be handled (e.g. MachineStateTransitionViolation).
///
/// It uses `thiserror` to adapt lower-level errors to this type.
///
/// # Examples
/// ```
/// let error = carbide::CarbideError::GenericError(String::from("unable to yeet foo into the sun"));
///
/// assert_eq!(error.to_string(), "Generic error: unable to yeet foo into the sun");
/// ```
///
#[derive(thiserror::Error, Debug)]
pub enum CarbideError {
    #[error("unable to instanciate datastore connection pool")]
    DatabaseError(tokio_postgres::Error),

    #[error("Invalid machine state transition: {0}")]
    MachineStateTransitionViolation(String, Option<String>),

    #[error("unable to perform database migrations")]
    RefineryError(#[from] refinery::Error),

    #[error("Database type conversion error")]
    DatabaseTypeConversionError(String),

    #[error("Database Pool (bb8) error: {0}")]
    DatabasePoolError(#[from] bb8::RunError<tokio_postgres::Error>),

    #[error("Multiple network segments defined for relay address: {0}")]
    MultipleNetworkSegmentsForRelay(IpAddr),

    #[error("No network segment defined for relay address: {0}")]
    NoNetworkSegmentsForRelay(IpAddr),

    #[error("Unable to generate ephemeral hostname from uuid: {0}")]
    HostnameGenerationError(String),

    #[error("Attempted to retrieve the next IP from a network segment without a subnet for that address family: {0}")]
    NetworkSegmentMissingAddressFamilyError(String),

    #[error("Duplicate MAC address for network: {0}")]
    NetworkSegmentDuplicateMacAddress(MacAddress),

    #[error("Attempted to retrieve the next IP from a network segment exhausted of IP space: {0}")]
    NetworkSegmentExhaustedAddressFamily(String),

    #[error("A machine that was just created, failed to return any rows: {0}")]
    DatabaseInconsistencyOnMachineCreate(uuid::Uuid),

    #[error("Generic error: {0}")]
    GenericError(String),
}

/// Convert a tokio_postgres::Error to a CarbideError
///
/// This conversion will intercept an SQL State code of T0100 to catch the invalid state change of
/// a machine instead of just returning a raw SqlError.  This requires not deriving `from` for the
/// enum variant.
///
impl From<tokio_postgres::Error> for CarbideError {
    fn from(error: tokio_postgres::Error) -> CarbideError {
        info!("Error: {:?}", error);

        if let Some(sql_error) = error.code() {
            match sql_error.code() {
                SQL_STATE_TRANSITION_VIOLATION_CODE => {
                    if let Some(db_error) = error.as_db_error() {
                        Self::MachineStateTransitionViolation(
                            String::from(db_error.message()),
                            db_error.hint().map(String::from),
                        )
                    } else {
                        Self::DatabaseError(error)
                    }
                }
                _ => Self::DatabaseError(error),
            }
        } else {
            Self::DatabaseError(error)
        }
    }
}

/// Result type for the return type of Carbide functions
///
/// Wraps `CarbideError` into `CarbideResult<T>`
///
/// # Examples
/// ```
/// use carbide::{CarbideError, CarbideResult};
///
/// pub fn do_something() -> CarbideResult<u8> {
///   Err(CarbideError::GenericError(String::from("can't make u8")))
/// }
/// assert!(matches!(do_something(), Err(CarbideError::GenericError(_))));
/// ```
pub type CarbideResult<T> = Result<T, CarbideError>;
