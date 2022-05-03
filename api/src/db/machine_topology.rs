use super::{MachineEvent, MachineInterface, MachineState, UuidKeyedObjectFilter};
use crate::CarbideResult;
use chrono::prelude::*;

use sqlx::postgres::PgRow;
use sqlx::{FromRow, Postgres, Row, Transaction};

#[derive(Debug)]
pub struct MachineTopology {
    machine_id: uuid::Uuid,
    topology: serde_json::Value,
    created: DateTime<Utc>,
    updated: DateTime<Utc>,
}

impl<'r> FromRow<'r, PgRow> for MachineTopology {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(MachineTopology {
            machine_id: row.try_get("machine_id")?,
            topology: row.try_get("topology")?,
            created: row.try_get("created")?,
            updated: row.try_get("updated")?,
        })
    }
}

impl MachineTopology {
    pub async fn create(
        txn: &mut Transaction<'_, Postgres>,
        machine_id: uuid::Uuid,
        discovery: String,
    ) -> CarbideResult<Self> {
        Ok(
            sqlx::query_as(
                "INSERT INTO machine_topologies VALUES ($1::uuid, $2::json) RETURNING *",
            )
            .bind(machine_id)
            .bind(discovery)
            .fetch_one(&mut *txn)
            .await?,
        )
    }
}
