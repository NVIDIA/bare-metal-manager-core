use crate::db::network_segment::NetworkSegmentType;
use crate::db::{ColumnInfo, DatabaseError, FilterableQueryBuilder, ObjectColumnFilter};
use ::rpc::uuid::machine::MachineId;
use mac_address::MacAddress;
use sqlx::{FromRow, PgConnection};
use uuid::Uuid;

#[derive(Debug, Clone, FromRow)]
pub struct PredictedMachineInterface {
    pub id: Uuid,
    pub machine_id: MachineId,
    pub mac_address: MacAddress,
    pub expected_network_segment_type: NetworkSegmentType,
}

#[derive(Debug, Clone)]
pub struct NewPredictedMachineInterface<'a> {
    pub machine_id: &'a MachineId,
    pub mac_address: MacAddress,
    pub expected_network_segment_type: NetworkSegmentType,
}

#[cfg(test)]
#[derive(Clone, Copy)]
pub struct MachineIdColumn;

#[cfg(test)]
impl ColumnInfo<'_> for crate::db::predicted_machine_interface::MachineIdColumn {
    type TableType = PredictedMachineInterface;
    type ColumnType = MachineId;
    fn column_name(&self) -> &'static str {
        "machine_id"
    }
}

#[derive(Clone, Copy)]
pub struct MacAddressColumn;
impl ColumnInfo<'_> for MacAddressColumn {
    type TableType = PredictedMachineInterface;
    type ColumnType = MacAddress;
    fn column_name(&self) -> &'static str {
        "mac_address"
    }
}

impl PredictedMachineInterface {
    pub async fn find_by<'a, C: ColumnInfo<'a, TableType = PredictedMachineInterface>>(
        txn: &mut PgConnection,
        filter: ObjectColumnFilter<'a, C>,
    ) -> Result<Vec<PredictedMachineInterface>, DatabaseError> {
        let mut query = FilterableQueryBuilder::new("SELECT * FROM predicted_machine_interfaces")
            .filter(&filter);
        query
            .build_query_as()
            .fetch_all(txn)
            .await
            .map_err(|e| DatabaseError::query(query.sql(), e))
    }

    pub async fn delete(&self, txn: &mut PgConnection) -> Result<(), DatabaseError> {
        let query = "DELETE FROM predicted_machine_interfaces WHERE id = $1";
        sqlx::query(query)
            .bind(self.id)
            .execute(txn)
            .await
            .map_err(|e| DatabaseError::query(query, e))?;
        Ok(())
    }

    pub async fn find_by_mac_address(
        txn: &mut PgConnection,
        mac_address: MacAddress,
    ) -> Result<Option<PredictedMachineInterface>, DatabaseError> {
        Ok(
            Self::find_by(txn, ObjectColumnFilter::One(MacAddressColumn, &mac_address))
                .await?
                .into_iter()
                .next(),
        )
    }
}

impl NewPredictedMachineInterface<'_> {
    pub async fn create(
        self,
        txn: &mut PgConnection,
    ) -> Result<PredictedMachineInterface, DatabaseError> {
        let query = "INSERT INTO predicted_machine_interfaces (machine_id, mac_address, expected_network_segment_type) VALUES ($1, $2, $3) RETURNING *";
        sqlx::query_as(query)
            .bind(self.machine_id)
            .bind(self.mac_address)
            .bind(self.expected_network_segment_type)
            .fetch_one(txn)
            .await
            .map_err(|e| DatabaseError::query(query, e))
    }
}
