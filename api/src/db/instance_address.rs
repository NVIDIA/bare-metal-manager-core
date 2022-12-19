/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::collections::{HashMap, HashSet};

use ipnetwork::IpNetwork;
use itertools::Itertools;
use sqlx::{query_as, Acquire, FromRow, Postgres, Transaction};
use uuid::Uuid;

use crate::dhcp::allocation::{IpAllocator, UsedIpResolver};
use crate::model::network_segment::NetworkSegmentControllerState;
use crate::model::ConfigValidationError;
use crate::{model::instance::config::network::InstanceNetworkConfig, CarbideError, CarbideResult};

use super::{
    address_selection_strategy::AddressSelectionStrategy, network_segment::NetworkSegment,
    UuidKeyedObjectFilter,
};

#[derive(Debug, FromRow, Clone)]
pub struct InstanceSegmentAddress {
    pub segment_id: Uuid,
    pub address: IpNetwork,
}

#[derive(Debug, FromRow, Clone)]
pub struct InstanceAddress {
    pub id: Uuid,
    pub instance_id: Uuid,
    pub circuit_id: String,
    pub address: IpNetwork,
}

impl InstanceAddress {
    pub fn is_ipv4(&self) -> bool {
        self.address.is_ipv4()
    }

    pub fn is_ipv6(&self) -> bool {
        self.address.is_ipv6()
    }

    pub async fn find_for_instance(
        txn: &mut Transaction<'_, Postgres>,
        filter: UuidKeyedObjectFilter<'_>,
    ) -> CarbideResult<HashMap<Uuid, Vec<InstanceAddress>>> {
        let base_query = "SELECT * FROM instance_addresses isa {where}".to_owned();

        Ok(match filter {
            UuidKeyedObjectFilter::All => {
                sqlx::query_as::<_, InstanceAddress>(&base_query.replace("{where}", ""))
                    .fetch_all(&mut *txn)
                    .await?
            }
            UuidKeyedObjectFilter::One(uuid) => {
                sqlx::query_as::<_, InstanceAddress>(
                    &base_query.replace("{where}", "WHERE isa.instance_id=$1"),
                )
                .bind(uuid)
                .fetch_all(&mut *txn)
                .await?
            }
            UuidKeyedObjectFilter::List(list) => {
                sqlx::query_as::<_, InstanceAddress>(
                    &base_query.replace("{where}", "WHERE isa.instance_id=ANY($1)"),
                )
                .bind(list)
                .fetch_all(&mut *txn)
                .await?
            }
        }
        .into_iter()
        .into_group_map_by(|address| address.instance_id))
    }

    async fn get_allocated_address(
        txn: &mut Transaction<'_, Postgres>,
        instance_id: uuid::Uuid,
    ) -> CarbideResult<Vec<InstanceSegmentAddress>> {
        Ok(query_as(
            r"
            SELECT network_segments.id as segment_id, instance_addresses.address as address 
            FROM instance_addresses
            INNER JOIN network_prefixes ON network_prefixes.circuit_id = instance_addresses.circuit_id
            INNER JOIN network_segments ON network_segments.id = network_prefixes.segment_id
            WHERE instance_addresses.instance_id = $1::uuid",
            )
            .bind(instance_id)
            .fetch_all(&mut *txn)
            .await?)
    }

    pub async fn delete(
        txn: &mut Transaction<'_, Postgres>,
        instance_id: uuid::Uuid,
    ) -> CarbideResult<()> {
        // Lock MUST be taken by calling function.
        let _: Vec<(uuid::Uuid,)> =
            sqlx::query_as("DELETE FROM instance_addresses WHERE instance_id=$1 RETURNING id")
                .bind(instance_id)
                .fetch_all(&mut *txn)
                .await?;
        Ok(())
    }

    fn validate(
        segments: &Vec<NetworkSegment>,
        instance_network: &InstanceNetworkConfig,
    ) -> CarbideResult<()> {
        if segments.len() != instance_network.interfaces.len() {
            // Missing at least one segment in db.
            return Err(ConfigValidationError::UnknownSegments.into());
        }

        let mut vpc_ids = HashSet::new();

        for segment in segments {
            if segment.is_marked_as_deleted() {
                // TODO: Single error for not ready and deleted?
                return Err(ConfigValidationError::NetworkSegmentToBeDeleted(segment.id).into());
            }

            match &segment.controller_state.value {
                NetworkSegmentControllerState::Ready => {}
                _ => {
                    return Err(ConfigValidationError::NetworkSegmentNotReady(
                        segment.id,
                        format!("{:?}", segment.controller_state.value),
                    )
                    .into());
                }
            }

            match segment.vpc_id {
                Some(x) => {
                    vpc_ids.insert(x);
                }
                None => {
                    return Err(ConfigValidationError::VpcNotAttachedToSegment(segment.id).into());
                }
            };
        }

        if vpc_ids.len() != 1 {
            return Err(ConfigValidationError::MultipleVpcFound.into());
        }

        Ok(())
    }

    pub async fn allocate(
        txn: &mut Transaction<'_, Postgres>,
        instance_id: uuid::Uuid,
        instance_network: &InstanceNetworkConfig,
    ) -> CarbideResult<Vec<InstanceSegmentAddress>> {
        // We expect only one ipv4 prefix. Also Ipv6 is not supported yet.
        // We're potentially about to insert a couple rows, so create a savepoint.
        let mut inner_txn = txn.begin().await?;

        let segments = NetworkSegment::find(
            &mut inner_txn,
            crate::db::UuidKeyedObjectFilter::List(
                &instance_network
                    .interfaces
                    .iter()
                    .map(|x| x.network_segment_id)
                    .collect_vec()[..],
            ),
        )
        .await?;

        InstanceAddress::validate(&segments, instance_network)?;

        sqlx::query("LOCK TABLE instance_addresses IN ACCESS EXCLUSIVE MODE")
            .execute(&mut inner_txn)
            .await?;

        // Assign all addresses in one shot.
        for iface in &instance_network.interfaces {
            let segment = match segments
                .iter()
                .find(|x| x.id() == &iface.network_segment_id)
            {
                Some(x) => x,
                None => {
                    return Err(CarbideError::FindOneReturnedNoResultsError(
                        iface.network_segment_id,
                    ));
                }
            };

            let mut circuit_id = segment
                .prefixes
                .iter()
                .filter_map(|x| {
                    if x.prefix.is_ipv4() {
                        x.circuit_id.to_owned()
                    } else {
                        None
                    }
                })
                .collect_vec();

            if circuit_id.is_empty() {
                log::error!("Circuit id is not yet updated for segment: {}", segment.id);
                return Err(CarbideError::FindOneReturnedNoResultsError(segment.id));
            } else if circuit_id.len() > 1 {
                return Err(CarbideError::FindOneReturnedManyResultsError(segment.id));
            }
            let circuit_id = circuit_id.remove(0);

            let dhcp_handler = UsedOverlayNetworkIpResolver {
                segment_id: segment.id,
            };

            let allocated_addresses = IpAllocator::new(
                &mut inner_txn,
                segment,
                &dhcp_handler,
                AddressSelectionStrategy::Automatic,
            )
            .await?;

            for address in allocated_addresses {
                sqlx::query("INSERT INTO instance_addresses (instance_id, circuit_id, address) VALUES ($1::uuid, $2, $3::inet)")
                .bind(instance_id)
                .bind(circuit_id.to_owned())
                .bind(address?)
                .fetch_all(&mut *inner_txn).await?;
            }
        }

        inner_txn.commit().await?;

        InstanceAddress::get_allocated_address(&mut *txn, instance_id).await
    }
}

struct UsedOverlayNetworkIpResolver {
    segment_id: uuid::Uuid,
}

#[async_trait::async_trait]
impl UsedIpResolver for UsedOverlayNetworkIpResolver {
    async fn used_ips(
        &self,
        txn: &mut Transaction<'_, Postgres>,
    ) -> CarbideResult<Vec<(IpNetwork,)>> {
        let query: &str = r"
             SELECT address FROM instance_addresses
             INNER JOIN network_prefixes ON instance_addresses.circuit_id = network_prefixes.circuit_id
             INNER JOIN network_segments ON network_prefixes.segment_id = network_segments.id
             WHERE network_segments.id = $1::uuid";

        sqlx::query_as(query)
            .bind(self.segment_id)
            .fetch_all(&mut *txn)
            .await
            .map_err(CarbideError::from)
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use crate::model::{
        config_version::ConfigVersion,
        instance::config::network::{
            InstanceInterfaceConfig, InterfaceFunctionId, INTERFACE_VFID_MAX,
        },
    };

    use super::*;

    fn create_valid_validation_data() -> Vec<NetworkSegment> {
        let vpc_id = uuid::uuid!("11609f10-c11d-1101-3261-6293ea0c0100");
        let network_segments: Vec<NetworkSegment> = (0..=INTERFACE_VFID_MAX)
            .map(|idx| {
                let id = format!("91609f10-c91d-470d-a260-6293ea0c00{:02}", idx);
                let version = ConfigVersion::initial();
                NetworkSegment {
                    id: uuid::Uuid::parse_str(&id).unwrap(),
                    version,
                    name: id,
                    subdomain_id: None,
                    vpc_id: Some(vpc_id),
                    mtu: 1500,
                    created: Utc::now(),
                    updated: Utc::now(),
                    deleted: None,
                    prefixes: Vec::new(),
                    controller_state: crate::model::config_version::Versioned {
                        value: NetworkSegmentControllerState::Ready,
                        version,
                    },
                    resource_groups_created: true,
                }
            })
            .collect_vec();

        network_segments
    }

    const BASE_SEGMENT_ID: uuid::Uuid = uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c0000");
    fn create_valid_network_config() -> InstanceNetworkConfig {
        let interfaces: Vec<InstanceInterfaceConfig> = (0..=INTERFACE_VFID_MAX)
            .map(|idx| {
                let function_id = if idx == 0 {
                    InterfaceFunctionId::PhysicalFunctionId {}
                } else {
                    InterfaceFunctionId::VirtualFunctionId { id: idx as u8 }
                };

                let network_segment_id = Uuid::from_u128(BASE_SEGMENT_ID.as_u128() + idx as u128);
                InstanceInterfaceConfig {
                    function_id,
                    network_segment_id,
                }
            })
            .collect();

        InstanceNetworkConfig { interfaces }
    }

    #[test]
    fn instance_address_segment_validation() {
        let data = create_valid_validation_data();
        let config = create_valid_network_config();
        let x = InstanceAddress::validate(&data, &config);
        assert!(x.is_ok());
    }

    #[test]
    fn validate_missing_segment_in_db_fail() {
        let mut data = create_valid_validation_data();
        let config = create_valid_network_config();
        data.swap_remove(10);
        assert!(InstanceAddress::validate(&data, &config).is_err());
    }

    #[test]
    fn validate_multiple_vpc_must_fail() {
        let mut data = create_valid_validation_data();
        let config = create_valid_network_config();
        data[0].vpc_id = Some(uuid::Uuid::new_v4());
        assert!(InstanceAddress::validate(&data, &config).is_err());
    }

    #[test]
    fn validate_missing_vpc_fail() {
        let mut data = create_valid_validation_data();
        let config = create_valid_network_config();
        data[2].vpc_id = None;
        assert!(InstanceAddress::validate(&data, &config).is_err());
    }

    #[test]
    fn validate_marked_deleted_segment_fail() {
        let mut data = create_valid_validation_data();
        let config = create_valid_network_config();
        data[12].deleted = Some(Utc::now());
        assert!(InstanceAddress::validate(&data, &config).is_err());
    }

    #[test]
    fn validate_not_ready_segment_fail() {
        let mut data = create_valid_validation_data();
        let config = create_valid_network_config();
        data[9].controller_state.value = NetworkSegmentControllerState::Provisioning;
        assert!(InstanceAddress::validate(&data, &config).is_err());
    }
}
