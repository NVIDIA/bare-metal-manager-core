use tokio_postgres::{tls::NoTlsStream, NoTls, Socket};

mod machine;
mod machine_action;
mod machine_event;
mod machine_interface;
mod machine_state;
mod network_segment;

pub mod migrations;

use std::str::FromStr;

pub use machine::Machine;
pub use machine_action::MachineAction;
pub use machine_event::MachineEvent;
pub use machine_interface::MachineInterface;
pub use machine_state::MachineState;
pub use network_segment::NetworkSegment;
pub use machine::MachineIdsFilter;

use super::CarbideResult;

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
        migrations::Migrator::migrate(db).await
    }
}
