use ipnetwork::IpNetwork;
use mac_address::MacAddress;
use sqlx::{FromRow, Postgres, Transaction};

use ::rpc::forge as rpc;

use crate::CarbideResult;

///
/// A machine dhcp response is a representation of some booting interface by Mac Address or DUID
/// (not implemented) that returns the network information for that interface on that node, and
/// contains everything necessary to return a DHCP response
///
#[derive(Debug, FromRow)]
pub struct DhcpRecord {
    machine_id: Option<uuid::Uuid>,
    segment_id: uuid::Uuid,
    machine_interface_id: uuid::Uuid,
    subdomain_id: Option<uuid::Uuid>,

    fqdn: String,

    mac_address: MacAddress,
    address: IpNetwork,
    mtu: i32,

    prefix: IpNetwork,
    gateway: Option<IpNetwork>,
}

impl From<DhcpRecord> for rpc::DhcpRecord {
    fn from(record: DhcpRecord) -> Self {
        Self {
            machine_id: record.machine_id.map(rpc::Uuid::from),
            machine_interface_id: Some(record.machine_interface_id.into()),
            segment_id: Some(record.segment_id.into()),
            subdomain_id: record.subdomain_id.map(rpc::Uuid::from),
            fqdn: record.fqdn,
            mac_address: record.mac_address.to_string(),
            address: record.address.to_string(),
            mtu: record.mtu,
            prefix: record.prefix.to_string(),
            gateway: record.gateway.map(|gw| gw.to_string()),
        }
    }
}

impl DhcpRecord {
    pub async fn find_by_mac_address(
        txn: &mut Transaction<'_, Postgres>,
        mac_address: &MacAddress,
        segment_id: &uuid::Uuid,
    ) -> CarbideResult<DhcpRecord> {
        Ok(sqlx::query_as("SELECT * FROM machine_dhcp_records WHERE mac_address = $1::macaddr AND segment_id = $2::uuid")
            .bind(mac_address)
            .bind(segment_id)
            .fetch_one(&mut *txn).await?)
    }

    pub async fn find_for_instance(
        txn: &mut Transaction<'_, Postgres>,
        mac_address: &MacAddress,
        segment_id: &uuid::Uuid,
        machine_id: uuid::Uuid,
    ) -> CarbideResult<DhcpRecord> {
        Ok(sqlx::query_as("SELECT * FROM instance_dhcp_records WHERE mac_address = $1::macaddr AND segment_id = $2::uuid AND machine_id=$3::uuid AND vfid IS null AND family(prefix) = 4")
            .bind(mac_address)
            .bind(segment_id)
            .bind(machine_id)
            .fetch_one(&mut *txn).await?)
    }

    pub fn address(&self) -> IpNetwork {
        self.address
    }
}
