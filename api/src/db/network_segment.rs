use crate::{CarbideError, CarbideResult};
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use patricia_tree::PatriciaMap;
use sqlx::postgres::PgRow;
use sqlx::{Postgres, Row};
use std::convert::TryFrom;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use uuid::Uuid;

use rpc::v0 as rpc;

#[derive(Clone, Debug)]
pub struct NetworkSegment {
    pub id: Uuid,
    pub name: String,
    pub subdomain: String,
    pub mtu: i32,

    pub subnet_ipv4: Option<Ipv4Network>,
    pub subnet_ipv6: Option<Ipv6Network>,
    pub gateway_ipv4: Option<Ipv4Addr>,

    pub reserve_first_ipv4: i32,
    pub reserve_first_ipv6: i32,
}

impl<'r> sqlx::FromRow<'r, PgRow> for NetworkSegment {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let possible_subnet_ipv4: Option<IpNetwork> = row.try_get("subnet_ipv4")?;
        let possible_subnet_ipv6: Option<IpNetwork> = row.try_get("subnet_ipv6")?;
        let possible_gateway_ipv4: Option<IpNetwork> = row.try_get("gateway_ipv4")?;

        let subnet_ipv4 = match possible_subnet_ipv4 {
            Some(IpNetwork::V4(network)) => Ok(Some(network)),
            Some(IpNetwork::V6(network)) => Err(sqlx::Error::Protocol(format!(
                "IP address field in subnet_ipv4 ({}) is not an IPv4 subnet",
                network
            ))),
            None => Ok(None),
        }?;

        let subnet_ipv6 = match possible_subnet_ipv6 {
            Some(IpNetwork::V6(network)) => Ok(Some(network)),
            Some(IpNetwork::V4(network)) => Err(sqlx::Error::Protocol(format!(
                "IP address field in subnet_ipv6 ({}) is not an IPv6 subnet",
                network
            ))),
            None => Ok(None),
        }?;

        let gateway_ipv4 = match possible_gateway_ipv4 {
            Some(IpNetwork::V4(network)) if network.prefix() == 32 => Ok(Some(network.ip())),
            Some(IpNetwork::V4(network)) => Err(sqlx::Error::Protocol(format!(
                "IP address field in gateway_ipv4 ({}) is not a single host",
                network
            ))),
            Some(IpNetwork::V6(network)) => Err(sqlx::Error::Protocol(format!(
                "IP address field in gateway_ipv4 ({}) is not an IPv4 subnet",
                network
            ))),
            None => Ok(None),
        }?;

        Ok(NetworkSegment {
            id: row.try_get("id")?,
            name: row.try_get("name")?,
            subdomain: row.try_get("subdomain")?,
            mtu: row.try_get("mtu")?,
            subnet_ipv4,
            subnet_ipv6,
            gateway_ipv4,
            reserve_first_ipv4: row.try_get("reserve_first_ipv4")?,
            reserve_first_ipv6: row.try_get("reserve_first_ipv6")?,
        })
    }
}

#[derive(Clone, Debug)]
pub struct NewNetworkSegment {
    pub name: String,
    pub subdomain: String,
    pub mtu: Option<i32>,

    pub subnet_ipv4: Option<Ipv4Network>,
    pub subnet_ipv6: Option<Ipv6Network>,
    pub gateway_ipv4: Option<Ipv4Network>,

    pub reserve_first_ipv4: Option<i32>,
    pub reserve_first_ipv6: Option<i32>,
}

impl TryFrom<rpc::NewNetworkSegment> for NewNetworkSegment {
    type Error = CarbideError;

    fn try_from(value: rpc::NewNetworkSegment) -> Result<Self, Self::Error> {
        Ok(NewNetworkSegment {
            name: value.name,
            subdomain: value.subdomain,
            mtu: value.mtu,
            subnet_ipv4: match value.subnet_ipv4 {
                Some(v) => Some(v.parse()?),
                None => None,
            },
            subnet_ipv6: match value.subnet_ipv6 {
                Some(v) => Some(v.parse()?),
                None => None,
            },
            gateway_ipv4: match value.gateway_ipv4 {
                Some(v) => Some(v.parse()?),
                None => None,
            },
            reserve_first_ipv4: value.reserve_first_ipv4,
            reserve_first_ipv6: value.reserve_first_ipv6,
        })
    }
}

impl From<NetworkSegment> for rpc::NetworkSegment {
    fn from(src: NetworkSegment) -> Self {
        rpc::NetworkSegment {
            id: Some(src.id.into()),
            name: src.name,
            subdomain: src.subdomain,
            mtu: src.mtu,
            subnet_ipv4: src.subnet_ipv4.map(|s| s.to_string()),
            subnet_ipv6: src.subnet_ipv6.map(|s| s.to_string()),
            gateway_ipv4: src.gateway_ipv4.map(|s| s.to_string()),
            reserve_first_ipv4: src.reserve_first_ipv4,
            reserve_first_ipv6: src.reserve_first_ipv6,
        }
    }
}

impl NewNetworkSegment {
    pub async fn persist(
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> CarbideResult<NetworkSegment> {
        Ok(sqlx::query_as("INSERT INTO network_segments (name, subdomain, mtu, subnet_ipv4, subnet_ipv6, gateway_ipv4, reserve_first_ipv4, reserve_first_ipv6) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *")
            .bind(&self.name)
            .bind(&self.subdomain)
            .bind(self.mtu)
            .bind(self.subnet_ipv4.map(IpNetwork::from))
            .bind(self.subnet_ipv6.map(IpNetwork::from))
            .bind(self.gateway_ipv4.map(IpNetwork::from))
            .bind(self.reserve_first_ipv4)
            .bind(self.reserve_first_ipv6)
            .fetch_one(&mut *txn).await?)
    }
}

impl NetworkSegment {
    pub async fn for_relay(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        relay: IpAddr,
    ) -> CarbideResult<Option<Self>> {
        let mut results = sqlx::query_as("SELECT * FROM network_segments WHERE ($1::inet <<= subnet_ipv4 OR $1::inet <<= subnet_ipv6)")
            .bind(IpNetwork::from(relay))
            .fetch_all(&mut *txn).await?;

        match results.len() {
            0 => Ok(None),
            1 => Ok(Some(results.remove(0))),
            _ => Err(CarbideError::MultipleNetworkSegmentsForRelay(relay)),
        }
    }

    pub async fn find(txn: &mut sqlx::Transaction<'_, Postgres>) -> CarbideResult<Vec<Self>> {
        Ok(sqlx::query_as("SELECT * FROM network_segments")
            .fetch_all(txn)
            .await?)
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
                map.extend(std::iter::once((subnet.network().octets(), ())));

                if let Some(gateway) = self.gateway_ipv4 {
                    map.extend(std::iter::once((gateway.octets(), ())));
                }

                map.extend(
                    subnet
                        .iter()
                        .skip(1)
                        .take(self.reserve_first_ipv4 as usize)
                        .map(|ip| (ip.octets(), ())),
                );

                subnet
                    .iter()
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
                    .iter()
                    .find(|address| map.get(address.octets()).is_none())
                    .ok_or_else(|| {
                        CarbideError::NetworkSegmentExhaustedAddressFamily(String::from("huh"))
                    })
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CarbideError;
    use std::str::FromStr;
    use uuid::Uuid;

    #[test]
    fn test_unused_ipv4_address() -> Result<(), String> {
        let segment = NetworkSegment {
            id: Uuid::new_v4(),
            name: String::from("test-network"),
            subdomain: String::from("example.com"),
            mtu: 1500,
            subnet_ipv4: Some("10.0.0.0/24".parse().unwrap()),
            subnet_ipv6: None,
            reserve_first_ipv4: 3,
            reserve_first_ipv6: 0,
            gateway_ipv4: Some("10.0.0.1".parse().unwrap()),
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
            subnet_ipv4: Some("10.0.0.0/24".parse().unwrap()),
            subnet_ipv6: None,
            reserve_first_ipv4: 3,
            reserve_first_ipv6: 0,
            gateway_ipv4: Some("10.0.0.1".parse().unwrap()),
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
