use crate::{CarbideError, CarbideResult};
use ip_network::{Ipv4Network, Ipv6Network};
use patricia_tree::PatriciaMap;
use std::convert::From;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rpc::v0 as rpc;

#[derive(Debug)]
pub struct NetworkSegment {
    id: uuid::Uuid,
    name: String,
    subdomain: String,
    mtu: i32,
    subnet_ipv4: Option<Ipv4Network>,
    subnet_ipv6: Option<Ipv6Network>,
    reserve_first_ipv4: i32,
    reserve_first_ipv6: i32,
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
            reserve_first_ipv4: row.get("reserve_first_ipv4"),
            reserve_first_ipv6: row.get("reserve_first_ipv6"),
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

            reserve_first_ipv4: network_segment.reserve_first_ipv4,
            reserve_first_ipv6: network_segment.reserve_first_ipv6,
            mtu: network_segment.mtu,
        }
    }
}

impl NetworkSegment {
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        dbc: &tokio_postgres::Transaction<'_>,
        name: &str,
        subdomain: &str,
        mtu: &i32,
        subnet_ipv4: Option<Ipv4Network>,
        subnet_ipv6: Option<Ipv6Network>,
        reserve_first_ipv4: &i32,
        reserve_first_ipv6: &i32,
    ) -> CarbideResult<Self> {
        Ok(
            Self::from(
                dbc.query_one("INSERT INTO network_segments (name, subdomain, mtu, subnet_ipv4, subnet_ipv6, reserve_first_ipv4, reserve_first_ipv6) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *", &[&name, &subdomain, mtu, &subnet_ipv4, &subnet_ipv6, &reserve_first_ipv4, &reserve_first_ipv6]).await?))
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

    pub fn subnet_ipv4(&self) -> Option<&Ipv4Network> {
        self.subnet_ipv4.as_ref()
    }

    pub fn subnet_ipv6(&self) -> Option<&Ipv6Network> {
        self.subnet_ipv6.as_ref()
    }

    pub fn next_ipv4<'a>(
        &self,
        used_ips: impl Iterator<Item = &'a Ipv4Addr>,
    ) -> CarbideResult<Ipv4Addr> {
        self.subnet_ipv4()
            .ok_or_else(|| {
                CarbideError::NetworkSegmentMissingAddressFamilyError(String::from("IPv4"))
            })
            .and_then(|subnet| {
                let mut map: PatriciaMap<()> = PatriciaMap::new();

                map.extend(used_ips.map(|ip| (ip.octets(), ())));

                subnet
                    .hosts()
                    .into_iter()
                    .find(|host| map.get(host.octets()).is_none())
                    .ok_or_else(|| {
                        CarbideError::NetworkSegmentExhaustedAddressFamily(String::from("huh"))
                    })
            })
    }

    pub fn next_ipv6<'a>(
        &self,
        used_ips: impl Iterator<Item = &'a Ipv6Addr>,
    ) -> CarbideResult<Ipv6Addr> {
        self.subnet_ipv6()
            .ok_or_else(|| {
                CarbideError::NetworkSegmentMissingAddressFamilyError(String::from("IPv6"))
            })
            .and_then(|subnet| {
                let mut map: PatriciaMap<()> = PatriciaMap::new();

                map.extend(used_ips.map(|ip| (ip.octets(), ())));

                subnet
                    .subnets_with_prefix(128)
                    .into_iter()
                    .find(|network| map.get(network.network_address().octets()).is_none())
                    .ok_or_else(|| {
                        CarbideError::NetworkSegmentExhaustedAddressFamily(String::from("huh"))
                    })
                    .map(|network| network.network_address())
            })
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CarbideError;
    use ip_network::Ipv4Network;
    use std::str::FromStr;
    use uuid::Uuid;

    #[test]
    fn test_unused_ipv4_address() -> Result<(), String> {
        let segment = NetworkSegment {
            id: Uuid::new_v4(),
            name: String::from("test-network"),
            subdomain: String::from("example.com"),
            mtu: 1500,
            subnet_ipv4: Some(Ipv4Network::from_str("10.0.0.0/24").unwrap()),
            subnet_ipv6: None,
            reserve_first_ipv4: 3,
            reserve_first_ipv6: 0,
        };
        let mut usedips: Vec<Ipv4Addr> = vec![];

        usedips.extend((1..=200).map(|i| Ipv4Addr::new(10, 0, 0, i)));

        assert_eq!(
            segment.next_ipv4(usedips.iter()).unwrap(),
            Ipv4Addr::from_str("10.0.0.201").unwrap()
        );
        Ok(())
    }

    #[test]
    fn test_exhausted_ipv4_address() -> Result<(), String> {
        let segment = NetworkSegment {
            id: Uuid::new_v4(),
            name: String::from("test-network"),
            subdomain: String::from("example.com"),
            mtu: 1500,
            subnet_ipv4: Some(Ipv4Network::from_str("10.0.0.0/24").unwrap()),
            subnet_ipv6: None,
            reserve_first_ipv4: 3,
            reserve_first_ipv6: 0,
        };
        let mut usedips: Vec<Ipv4Addr> = vec![];

        let address_list = (1..=255).map(|i| Ipv4Addr::new(10, 0, 0, i));

        usedips.extend(address_list);

        assert!(matches!(
            segment.next_ipv4(usedips.iter()),
            Err(CarbideError::NetworkSegmentExhaustedAddressFamily(_))
        ));
        Ok(())
    }
}
