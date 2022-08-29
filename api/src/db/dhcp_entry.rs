use sqlx::{FromRow, Postgres, Transaction};

use crate::CarbideResult;

///
/// A machine dhcp response is a representation of some booting interface by Mac Address or DUID
/// (not implemented) that returns the network information for that interface on that node, and
/// contains everything necessary to return a DHCP response
///
#[derive(Debug, FromRow)]
pub struct DhcpEntry {
    pub machine_interface_id: uuid::Uuid,
    pub vendor_class: String,
}

impl DhcpEntry {
    pub async fn find_by_interface_id(
        txn: &mut Transaction<'_, Postgres>,
        machine_interface_id: &uuid::Uuid,
    ) -> CarbideResult<Vec<DhcpEntry>> {
        Ok(
            sqlx::query_as("SELECT * FROM dhcp_entries WHERE machine_interface_id = $1::uuid")
                .bind(machine_interface_id)
                .fetch_all(&mut *txn)
                .await?,
        )
    }

    pub async fn persist(
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> CarbideResult<DhcpEntry> {
        Ok(
            sqlx::query_as("INSERT INTO dhcp_entries (machine_interface_id, vendor_string) VALUES ($1::uuid, $2::varchar) RETURNING *")
                .bind(&self.machine_interface_id)
                .bind(&self.vendor_class)
                .fetch_one(&mut *txn)
                .await?,
        )
    }
}
