use std::convert::TryFrom;
use std::net::IpAddr;

use crate::{
    db::NetworkPrefix, db::NewNetworkPrefix, db::UuidKeyedObjectFilter, CarbideError, CarbideResult,
};
use chrono::prelude::*;
use ipnetwork::IpNetwork;
use itertools::Itertools;
use log::warn;
use patricia_tree::PatriciaMap;
use rpc::v0 as rpc;
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Transaction};
use sqlx::{Postgres, Row};
use uuid::Uuid;

#[derive(Debug)]
pub enum IpAllocationError {
    PrefixExhausted(NetworkPrefix),
}

pub type IpAllocationResult = Result<IpAddr, IpAllocationError>;

#[derive(Debug)]
pub struct NetworkSegment {
    pub id: Uuid,
    pub name: String,
    pub subdomain_id: Option<Uuid>,
    pub vpc_id: Option<Uuid>,
    pub mtu: i32,

    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,

    pub prefixes: Vec<NetworkPrefix>,
}

#[derive(Debug)]
pub struct NewNetworkSegment {
    pub name: String,
    pub subdomain_id: Option<Uuid>,
    pub vpc_id: Option<Uuid>,
    pub mtu: Option<i32>,
    pub prefixes: Vec<NewNetworkPrefix>,
}

// We need to implement FromRow because we can't associate dependent tables with the default derive
// (i.e. it can't default unknown fields)
impl<'r> FromRow<'r, PgRow> for NetworkSegment {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(NetworkSegment {
            id: row.try_get("id")?,
            name: row.try_get("name")?,
            subdomain_id: row.try_get("subdomain_id")?,
            vpc_id: row.try_get("vpc_id")?,
            created: row.try_get("created")?,
            updated: row.try_get("updated")?,
            mtu: row.try_get("mtu")?,
            prefixes: Vec::new(),
        })
    }
}

/// Marshal from Rust NewNetworkSegment to ProtoBuf NetworkSegment.
///
/// subdomain_id - Converting from Protobuf UUID(String) to Rust UUID type can fail.
/// Use try_from in order to return a Result where Result is an error if the conversion
/// from String -> UUID fails
///
impl TryFrom<rpc::NetworkSegment> for NewNetworkSegment {
    type Error = CarbideError;

    fn try_from(value: rpc::NetworkSegment) -> Result<Self, Self::Error> {
        if let Some(_id) = value.id {
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
            vpc_id: match value.vpc_id {
                Some(v) => Some(uuid::Uuid::try_from(v)?),
                None => None,
            },
            mtu: value.mtu,
            prefixes: value
                .prefixes
                .into_iter()
                .map(NewNetworkPrefix::try_from)
                .collect::<Result<Vec<NewNetworkPrefix>, CarbideError>>()?,
        })
    }
}

///
/// Marshal a Data Object (NetworkSegment) into an RPC NetworkSegment
///
/// subdomain_id - Rust UUID -> ProtoBuf UUID(String) cannot fail, so convert it or return None
///
impl From<NetworkSegment> for rpc::NetworkSegment {
    fn from(src: NetworkSegment) -> Self {
        rpc::NetworkSegment {
            id: Some(src.id.into()),
            name: src.name,
            subdomain_id: src.subdomain_id.map(rpc::Uuid::from),
            mtu: Some(src.mtu),

            created: Some(rpc::Timestamp {
                seconds: src.created.timestamp(),
                nanos: 0,
            }),

            updated: Some(rpc::Timestamp {
                seconds: src.updated.timestamp(),
                nanos: 0,
            }),
            prefixes: src
                .prefixes
                .into_iter()
                .map(rpc::NetworkPrefix::from)
                .collect_vec(),
            vpc_id: src.vpc_id.map(rpc::Uuid::from),
        }
    }
}

impl NewNetworkSegment {
    pub async fn persist(
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> CarbideResult<NetworkSegment> {
        let mut segment: NetworkSegment = sqlx::query_as("INSERT INTO network_segments (name, subdomain_id, vpc_id, mtu) VALUES ($1, $2, $3, $4) RETURNING *")
            .bind(&self.name)
            .bind(&self.subdomain_id)
            .bind(self.vpc_id)
            .bind(self.mtu)
            .fetch_one(&mut *txn).await?;

        segment.prefixes = NetworkPrefix::create_for(txn, &segment.id, &self.prefixes).await?;

        Ok(segment)
    }
}

impl NetworkSegment {
    pub async fn for_vpc(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        vpc_id: uuid::Uuid,
    ) -> CarbideResult<Vec<Self>> {
        let results: Vec<NetworkSegment> = {
            sqlx::query_as("SELECT * FROM network_segments WHERE vpc_id=$1::uuid")
                .bind(vpc_id)
                .fetch_all(&mut *txn)
                .await?
        };

        Ok(results)
    }

    pub async fn for_relay(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        relay: IpAddr,
    ) -> CarbideResult<Option<Self>> {
        let mut results = sqlx::query_as(
            r#"SELECT network_segments.* FROM network_segments INNER JOIN network_prefixes ON network_prefixes.segment_id = network_segments.id WHERE $1::inet <<= network_prefixes.prefix"#,
        )
            .bind(IpNetwork::from(relay))
            .fetch_all(&mut *txn)
            .await?;

        match results.len() {
            0 => Ok(None),
            1 => {
                let mut segment: NetworkSegment = results.remove(0);

                segment.prefixes =
                    sqlx::query_as(r#"SELECT * FROM network_prefixes WHERE segment_id=$1::uuid"#)
                        .bind(segment.id())
                        .fetch_all(&mut *txn)
                        .await?;

                Ok(Some(segment))
            }
            _ => Err(CarbideError::MultipleNetworkSegmentsForRelay(relay)),
        }
    }

    pub async fn find(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        filter: UuidKeyedObjectFilter<'_>,
    ) -> CarbideResult<Vec<Self>> {
        let base_query = "SELECT * FROM network_segments {where}".to_owned();

        let mut all_records: Vec<NetworkSegment> = match filter {
            UuidKeyedObjectFilter::All => {
                sqlx::query_as::<_, NetworkSegment>(&base_query.replace("{where}", ""))
                    .fetch_all(&mut *txn)
                    .await?
            }

            UuidKeyedObjectFilter::List(uuids) => {
                sqlx::query_as::<_, NetworkSegment>(
                    &base_query.replace("{where}", "WHERE network_segments.id=ANY($1)"),
                )
                .bind(uuids)
                .fetch_all(&mut *txn)
                .await?
            }
            UuidKeyedObjectFilter::One(uuid) => {
                sqlx::query_as::<_, NetworkSegment>(
                    &base_query.replace("{where}", "WHERE network_segments.id=$1"),
                )
                .bind(uuid)
                .fetch_all(&mut *txn)
                .await?
            }
        };

        let all_uuids = all_records
            .iter()
            .map(|record| record.id)
            .collect::<Vec<Uuid>>();

        // TODO(ajf): N+1 query alert.  Optimize later.

        let mut grouped_prefixes =
            NetworkPrefix::find_by_segment(&mut *txn, UuidKeyedObjectFilter::List(&all_uuids))
                .await?
                .into_iter()
                .into_group_map_by(|prefix| prefix.segment_id);

        all_records.iter_mut().for_each(|record| {
            if let Some(prefixes) = grouped_prefixes.remove(&record.id) {
                record.prefixes = prefixes;
            } else {
                warn!("Network {0} ({1}) has no prefixes?", record.id, record.name);
            }
        });

        Ok(all_records)
    }

    pub fn subdomain_id(&self) -> Option<&uuid::Uuid> {
        self.subdomain_id.as_ref()
    }

    pub fn id(&self) -> &uuid::Uuid {
        &self.id
    }

    /// Returns a Vec<IpNetwork> of the next ip address for all the prefixes of this segment.
    ///
    /// It will allocate both address families, if both are present.
    ///
    /// This function assumes that proper DB locking has been done prior to calling this function
    ///
    /// # Arguments
    ///
    /// None
    ///
    /// # Examples
    ///
    /// let network = NetworkSegment::for_relay("192.0.2.1")
    ///
    /// let next_addresses: Vec<IpNetwork> = network.next_addresses();
    ///
    /// # Returns
    ///
    pub async fn next_address<'a>(
        &self,
        txn: &mut Transaction<'_, Postgres>,
    ) -> CarbideResult<Vec<IpAllocationResult>> {
        let used_ips: Vec<(IpNetwork, )> = sqlx::query_as(r"
             SELECT address FROM machine_interface_addresses
             INNER JOIN machine_interfaces ON machine_interfaces.id = machine_interface_addresses.interface_id
             INNER JOIN network_segments ON machine_interfaces.segment_id = network_segments.id
             WHERE network_segments.id = $1::uuid")
            .bind(self.id())
            .fetch_all(&mut *txn)
            .await?;

        let segment_prefixes: Vec<NetworkPrefix> =
            sqlx::query_as("SELECT * FROM network_prefixes WHERE segment_id = $1::uuid")
                .bind(self.id())
                .fetch_all(&mut *txn)
                .await?;

        let addresses = segment_prefixes
            .into_iter()
            .map(|segment_prefix| {
                let mut excluded_ips: PatriciaMap<()> = PatriciaMap::new();

                /// This looks dumb, because octets() isn't on IpAddr, only on IpXAddr
                ///
                /// https://github.com/rust-lang/rfcs/issues/1881
                ///
                fn to_vec(addr: &IpAddr) -> Vec<u8> {
                    match addr {
                        IpAddr::V4(address) => address.octets().to_vec(),
                        IpAddr::V6(address) => address.octets().to_vec(),
                    }
                }

                excluded_ips.extend(used_ips.iter().filter_map(|(ip,)| {
                    segment_prefix
                        .prefix
                        .contains(ip.ip())
                        .then(|| (to_vec(&ip.ip()), ()))
                }));

                // TODO: add gateway to the list of used IPs above?
                if let Some(gateway) = segment_prefix.gateway {
                    assert!(segment_prefix.prefix.is_ipv4());

                    excluded_ips.extend(std::iter::once((to_vec(&gateway.ip()), ())));
                }

                // Exclude the first "N" number of addresses
                //
                // The gateway will be excluded separately, so if `num_reserved` == 1` and that's
                // also the gateway address, then we'll exclude the same address twice, and you'll
                // get the second address.
                //
                excluded_ips.extend(
                    segment_prefix
                        .prefix
                        .iter()
                        .take(segment_prefix.num_reserved as usize)
                        .map(|ip| (to_vec(&ip), ())),
                );

                // Iterate over all the IPs until we find one that's not in the map, that's our
                // first free IPs
                segment_prefix
                    .prefix
                    .iter()
                    .find_map(|address| {
                        excluded_ips
                            .get(to_vec(&address))
                            .is_none()
                            .then(|| address)
                    })
                    .ok_or(IpAllocationError::PrefixExhausted(segment_prefix))
            })
            .collect();

        Ok(addresses)
    }
}
