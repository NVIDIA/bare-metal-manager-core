use crate::{CarbideError, CarbideResult};
use chrono::prelude::*;
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use log::warn;
use patricia_tree::PatriciaMap;
use sqlx::postgres::PgRow;
use sqlx::{Acquire, Postgres, Row};
use std::convert::{TryFrom, TryInto};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use uuid::Uuid;

use crate::db::{Domain, NewDomain};
use rpc::v0 as rpc;

#[derive(Clone, Debug)]
pub struct NetworkSegment {
    pub id: Uuid,
    pub name: String,
    pub subdomain_id: Option<Uuid>,
    pub mtu: i32,

    pub prefix_ipv4: Option<Ipv4Network>,
    pub prefix_ipv6: Option<Ipv6Network>,
    pub gateway_ipv4: Option<Ipv4Addr>,

    pub reserve_first_ipv4: i32,
    pub reserve_first_ipv6: i32,

    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
}

impl<'r> sqlx::FromRow<'r, PgRow> for NetworkSegment {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let possible_prefix_ipv4: Option<IpNetwork> = row.try_get("prefix_ipv4")?;
        let possible_prefix_ipv6: Option<IpNetwork> = row.try_get("prefix_ipv6")?;
        let possible_gateway_ipv4: Option<IpNetwork> = row.try_get("gateway_ipv4")?;

        let prefix_ipv4 = match possible_prefix_ipv4 {
            Some(IpNetwork::V4(network)) => Ok(Some(network)),
            Some(IpNetwork::V6(network)) => Err(sqlx::Error::Protocol(format!(
                "IP address field in prefix_ipv4 ({}) is not an IPv4 subnet",
                network
            ))),
            None => Ok(None),
        }?;

        let prefix_ipv6 = match possible_prefix_ipv6 {
            Some(IpNetwork::V6(network)) => Ok(Some(network)),
            Some(IpNetwork::V4(network)) => Err(sqlx::Error::Protocol(format!(
                "IP address field in prefix_ipv6 ({}) is not an IPv6 subnet",
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
            subdomain_id: row.try_get("subdomain_id")?,
            mtu: row.try_get("mtu")?,
            prefix_ipv4,
            prefix_ipv6,
            gateway_ipv4,
            reserve_first_ipv4: row.try_get("reserve_first_ipv4")?,
            reserve_first_ipv6: row.try_get("reserve_first_ipv6")?,
            created: row.try_get("created")?,
            updated: row.try_get("updated")?,
        })
    }
}

#[derive(Clone, Debug)]
pub struct NewNetworkSegment {
    pub name: String,
    pub subdomain_id: Option<Uuid>,
    pub mtu: Option<i32>,

    pub prefix_ipv4: Option<Ipv4Network>,
    pub prefix_ipv6: Option<Ipv6Network>,
    pub gateway_ipv4: Option<Ipv4Network>,

    pub reserve_first_ipv4: Option<i32>,
    pub reserve_first_ipv6: Option<i32>,
}

impl TryFrom<rpc::NetworkSegment> for NewNetworkSegment {
    type Error = CarbideError;

    fn try_from(value: rpc::NetworkSegment) -> Result<Self, Self::Error> {
        if let Some(id) = value.id {
            return Err(CarbideError::IdentifierSpecifiedForNewObject(String::from(
                "Network Segment",
            )));
        }

        Ok(NewNetworkSegment {
            name: value.name,
            subdomain_id: match value.subdomain_id {
                Some(v) => Some(uuid::Uuid::try_from(v)?),
                None => None,
            },
            mtu: value.mtu,
            prefix_ipv4: match value.prefix_ipv4 {
                Some(v) => Some(v.parse()?),
                None => None,
            },
            prefix_ipv6: match value.prefix_ipv6 {
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

/*
 * Marshal a Data Object (NetworkSegment) into an RPC NetworkSegment
 */
impl From<NetworkSegment> for rpc::NetworkSegment {
    fn from(src: NetworkSegment) -> Self {
        rpc::NetworkSegment {
            id: Some(src.id.into()),
            name: src.name,
            subdomain_id: Some(rpc::Uuid::try_from(src.subdomain_id.unwrap()).unwrap()),
            mtu: Some(src.mtu),
            prefix_ipv4: src.prefix_ipv4.map(|s| s.to_string()),
            prefix_ipv6: src.prefix_ipv6.map(|s| s.to_string()),
            gateway_ipv4: src.gateway_ipv4.map(|s| s.to_string()),
            reserve_first_ipv4: Some(src.reserve_first_ipv4),
            reserve_first_ipv6: Some(src.reserve_first_ipv6),

            created: Some(rpc::Timestamp {
                seconds: src.created.timestamp(),
                nanos: 0,
            }),

            updated: Some(rpc::Timestamp {
                seconds: src.updated.timestamp(),
                nanos: 0,
            }),

            // TODO(ajf): Projects aren't modeled yet so just return 0 UUID.
            project: Some(uuid::Uuid::nil().into()),
        }
    }
}

impl NewNetworkSegment {
    pub async fn persist(
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> CarbideResult<NetworkSegment> {
        Ok(sqlx::query_as("INSERT INTO network_segments (name, subdomain_id, mtu, prefix_ipv4, prefix_ipv6, gateway_ipv4, reserve_first_ipv4, reserve_first_ipv6) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *")
            .bind(&self.name)
            .bind(&self.subdomain_id)
            .bind(self.mtu)
            .bind(self.prefix_ipv4.map(IpNetwork::from))
            .bind(self.prefix_ipv6.map(IpNetwork::from))
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
        let mut results = sqlx::query_as("SELECT * FROM network_segments WHERE ($1::inet <<= prefix_ipv4 OR $1::inet <<= prefix_ipv6)")
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

    pub fn subdomain_id(&self) -> Option<&uuid::Uuid> {
        self.subdomain_id.as_ref()
    }

    pub fn id(&self) -> &uuid::Uuid {
        &self.id
    }

    pub fn prefix_ipv4(&self) -> Option<&Ipv4Network> {
        self.prefix_ipv4.as_ref()
    }

    pub fn prefix_ipv6(&self) -> Option<&Ipv6Network> {
        self.prefix_ipv6.as_ref()
    }

    pub fn next_ipv4<'a>(
        &self,
        used_ips: impl Iterator<Item = &'a Ipv4Addr>,
    ) -> CarbideResult<Ipv4Addr> {
        self.prefix_ipv4()
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
        self.prefix_ipv6()
            .ok_or_else(|| {
                CarbideError::NetworkSegmentMissingAddressFamilyError(String::from("IPv6"))
            })
            .and_then(|subnet| {
                let mut map: PatriciaMap<()> = PatriciaMap::new();

                map.extend(used_ips.map(|ip| (ip.octets(), ())));

                map.extend(
                    subnet
                        .iter()
                        .take(self.reserve_first_ipv6 as usize)
                        .map(|ip| (ip.octets(), ())),
                );

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
        let domain = Domain::new("testdomain");

        let segment = NetworkSegment {
            id: Uuid::new_v4(),
            name: String::from("test-network"),
            subdomain_id: Some(*domain.id()),
            mtu: 1500,
            prefix_ipv4: Some("10.0.0.0/24".parse().unwrap()),
            prefix_ipv6: None,
            reserve_first_ipv4: 3,
            reserve_first_ipv6: 0,
            gateway_ipv4: Some("10.0.0.1".parse().unwrap()),
            created: Utc::now(),
            updated: Utc::now(),
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
        let domain = Domain::new("Testdomain");

        let segment = NetworkSegment {
            id: Uuid::new_v4(),
            name: String::from("test-network"),
            subdomain_id: Some(*domain.id()),
            mtu: 1500,
            prefix_ipv4: Some("10.0.0.0/24".parse().unwrap()),
            prefix_ipv6: None,
            reserve_first_ipv4: 3,
            reserve_first_ipv6: 0,
            gateway_ipv4: Some("10.0.0.1".parse().unwrap()),
            created: Utc::now(),
            updated: Utc::now(),
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
