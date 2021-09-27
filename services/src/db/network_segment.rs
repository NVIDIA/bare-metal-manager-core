use crate::{CarbideError, CarbideResult};
use ip_network::{Ipv4Network, Ipv6Network};
use std::convert::From;
use std::net::IpAddr;

use rpc::v0 as rpc;

#[derive(Debug)]
pub struct NetworkSegment {
    id: uuid::Uuid,
    name: String,
    subdomain: String,
    mtu: i32,
    subnet_ipv4: Option<Ipv4Network>,
    subnet_ipv6: Option<Ipv6Network>,
}

impl From<tokio_postgres::Row> for NetworkSegment {
    fn from(row: tokio_postgres::Row) -> Self {
        Self {
            id: row.get("id"),
            name: row.get("name"),
            subdomain: row.get("subdomain"),
            mtu: row.get("mtu"),
            subnet_ipv4: row.get("subnet_ipv4"),
            subnet_ipv6: row.get("subnet_ipv6"),
        }
    }
}

impl From<NetworkSegment> for rpc::NetworkSegment {
    fn from(network_segment: NetworkSegment) -> Self {
        rpc::NetworkSegment {
            id: Some(network_segment.id.into()),
            name: network_segment.name,
            subdomain: network_segment.subdomain,

            // TODO(ajf) get a better IPv4 / IPv6 type
            subnet_ipv4: network_segment.subnet_ipv4.map(|s| s.to_string()),
            subnet_ipv6: network_segment.subnet_ipv6.map(|s| s.to_string()),
            mtu: network_segment.mtu,
        }
    }
}

impl NetworkSegment {
    pub async fn create(
        dbc: &tokio_postgres::Transaction<'_>,
        name: &str,
        subdomain: &str,
        mtu: &i32,
        subnet_ipv4: Option<Ipv4Network>,
        subnet_ipv6: Option<Ipv6Network>,
    ) -> CarbideResult<Self> {
        Ok(
            Self::from(
                dbc.query_one("INSERT INTO network_segments (name, subdomain, mtu, subnet_ipv4, subnet_ipv6) VALUES ($1, $2, $3, $4, $5) RETURNING *", &[&name, &subdomain, mtu, &subnet_ipv4, &subnet_ipv6]).await?))
    }

    pub async fn delete(self, dbc: &tokio_postgres::Transaction<'_>) -> CarbideResult<()> {
        dbc.query_one("DELETE FROM network_segements WHERE id=$1", &[&self.id])
            .await?;

        Ok(())
    }

    pub fn subdomain(&self) -> &str {
        &self.subdomain
    }

    pub fn id(&self) -> &uuid::Uuid {
        &self.id
    }

    pub async fn for_relay(
        txn: &tokio_postgres::Transaction<'_>,
        relay: IpAddr,
    ) -> CarbideResult<Option<Self>> {
        let mut results =
            txn
            .query("SELECT * FROM network_segments WHERE (($1::inet <<= subnet_ipv4 OR $1::inet <<= subnet_ipv6))", &[&relay])
            .await?;

        match results.len() {
            0 => Ok(None),
            1 => Ok(Some(Self::from(results.remove(0)))),
            _ => Err(CarbideError::MultipleNetworkSegmentsForRelay(relay)),
        }
    }

    pub async fn find(txn: &tokio_postgres::Transaction<'_>) -> CarbideResult<Vec<Self>> {
        let segments = txn
            .query("SELECT * FROM network_segments", &[])
            .await?
            .into_iter()
            .map(Self::from)
            .collect();

        Ok(segments)
    }

    pub async fn find_by_id(
        txn: &tokio_postgres::Transaction<'_>,
        id: uuid::Uuid,
    ) -> CarbideResult<Option<Self>> {
        let mut results =
            txn
            .query("SELECT * FROM network_segments WHERE (($1::inet <<= subnet_ipv4 OR $1::inet <<= subnet_ipv6))", &[&id])
            .await?;

        match results.len() {
            0 => Ok(None),
            1 => Ok(Some(Self::from(results.remove(0)))),
            _ => unreachable!(),
        }
    }
}
