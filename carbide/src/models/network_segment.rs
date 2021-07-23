use crate::{CarbideResult, CarbideError};
use ip_network::{Ipv4Network, Ipv6Network};
use std::convert::From;
use std::net::IpAddr;

#[derive(Debug)]
pub struct NetworkSegment {
    id: uuid::Uuid,
    name: String,
    subdomain: String,
    mtu: i16,
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

impl NetworkSegment {
    pub async fn create(
        dbc: &tokio_postgres::Transaction<'_>,
        name: String,
        subdomain: String,
        subnet_ipv4: Option<Ipv4Network>,
        subnet_ipv6: Option<Ipv6Network>,
    ) -> CarbideResult<Self> {
        Ok(
            Self::from(
                    dbc.query_one("INSERT INTO network_segments (name, subdomain, subnet_ipv4, subnet_ipv6) VALUES ($1, $2, $3, $4) RETURNING *", &[&name, &subdomain, &subnet_ipv4, &subnet_ipv6]).await?))
    }

    pub fn subdomain(&self) -> &str {
        &self.subdomain
    }

    pub fn id(&self) -> &uuid::Uuid {
        &self.id
    }

    pub async fn for_relay(dbc: &tokio_postgres::Transaction<'_>, relay: IpAddr) -> CarbideResult<Option<Self>> {
        let mut results = 
            dbc
            .query("SELECT * FROM network_segments WHERE (($1::inet <<= subnet_ipv4 OR $1::inet <<= subnet_ipv6))", &[&relay])
            .await?;

        match results.len() {
            0 => Ok(None),
            1 => Ok(Some(Self::from(results.remove(0)))),
            _ => Err(CarbideError::MultipleNetworkSegmentsForRelay(relay)),
        }
    }
}
