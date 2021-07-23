use std::net::IpAddr;
use std::str::FromStr;

use tokio_postgres::{tls::NoTlsStream, NoTls, Socket};

pub mod models;
pub mod protos {
    tonic::include_proto!("carbide");
}

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

pub type Pool = bb8::Pool<bb8_postgres::PostgresConnectionManager<tokio_postgres::NoTls>>;

pub type DatabaseConnection<'a> =
    bb8::PooledConnection<'a, bb8_postgres::PostgresConnectionManager<tokio_postgres::NoTls>>;

pub struct Datastore;
impl Datastore {
    pub async fn pool_from_url(database_url: &str) -> CarbideResult<Pool> {
        let manager = bb8_postgres::PostgresConnectionManager::new(
            tokio_postgres::config::Config::from_str(database_url)?,
            tokio_postgres::NoTls,
        );

        Ok(bb8::Pool::builder()
            .max_size(10)
            .build(manager)
            .await
            .unwrap())
    }

    pub async fn pool_from_config(config: tokio_postgres::config::Config) -> CarbideResult<Pool> {
        let manager = bb8_postgres::PostgresConnectionManager::new(config, tokio_postgres::NoTls);

        Ok(bb8::Pool::builder().max_size(10).build(manager).await?)
    }

    pub async fn direct_from_url(
        database_url: &str,
    ) -> CarbideResult<(
        tokio_postgres::Client,
        tokio_postgres::Connection<Socket, NoTlsStream>,
    )> {
        Ok(tokio_postgres::connect(database_url, NoTls).await?)
    }

    pub async fn migrate(db: Pool) -> CarbideResult<refinery::Report> {
        models::migrations::Migrator::migrate(db).await
    }
}
