use log::info;
use std::net::IpAddr;

pub mod db;

const SQL_STATE_TRANSITION_VIOLATION_CODE: &str = "T0100";

#[derive(thiserror::Error, Debug)]
pub enum CarbideError {
    #[error("unable to instanciate datastore connection pool")]
    DatabaseError(tokio_postgres::Error),

    #[error("Invalid machine state transition")]
    MachineStateTransitionViolation(String, Option<String>),

    #[error("unable to perform database migrations")]
    RefineryError(#[from] refinery::Error),

    #[error("Database type conversion error")]
    DatabaseTypeConversionError(String),

    #[error("Database Pool (bb8) error")]
    DatabasePoolError(#[from] bb8::RunError<tokio_postgres::Error>),

    #[error("Multiple network segments defined for relay address")]
    MultipleNetworkSegmentsForRelay(IpAddr),

    #[error("No network segment defined for relay address")]
    NoNetworkSegmentsForRelay(IpAddr),

    #[error("Unable to generate ephemeral hostname from uuid")]
    HostnameGenerationError(String),

    #[error("Generic error")]
    GenericError(String),
}

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

pub type CarbideResult<T> = Result<T, CarbideError>;
