/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Transactional database view of the site routing-safety graph.
//!
//! Routing writers acquire one site-local transaction lock before any
//! resource-specific row lock. Address rows are loaded first; peerings,
//! security groups, and retained instance transitions are loaded only when
//! exact tenant address reuse makes policy analysis necessary. Soft-deleted
//! rows remain in the snapshots while controllers may still route or drain
//! them, so admission cannot forget an in-flight path.

use model::DeletedFilter;
use model::instance::config::network::{InstanceNetworkConfig, InstanceNetworkConfigUpdate};
use model::network_security_group::NetworkSecurityGroup;
use model::network_segment::{NetworkSegment, NetworkSegmentSearchConfig};
use model::site_prefix::{SitePrefix, SitePrefixSearchFilter};
use model::vpc::{Vpc, VpcPeering};
use model::vpc_prefix::VpcPrefix;
use sqlx::PgConnection;

use crate::{DatabaseError, DatabaseResult, ObjectColumnFilter};

const SITE_ROUTING_SAFETY_LOCK: &str = "site-routing-safety";

/// The address inventory needed to decide whether policy paths can possibly
/// matter for the current mutation.
#[derive(Debug)]
pub struct RoutingAddressSnapshot {
    /// Every VPC row, including soft-deleted parents retained by routed children.
    pub vpcs: Vec<Vpc>,
    /// SitePrefix roots used to prove tenant ownership and routing scope.
    pub site_prefixes: Vec<SitePrefix>,
    /// VPC prefixes, including soft-deleted rows that have not finished draining.
    pub vpc_prefixes: Vec<VpcPrefix>,
    /// Segments and their direct prefixes, including soft-deleted retained rows.
    pub network_segments: Vec<NetworkSegment>,
}

/// A routing-only instance projection. Retained current and pending old/new
/// network configs stay present without hydrating OS and unrelated status.
#[derive(Debug, sqlx::FromRow)]
pub struct RoutingInstance {
    /// Instance identity retained for operator-only failure diagnostics.
    pub id: carbide_uuid::instance::InstanceId,
    /// Current network attachment set.
    pub network_config: sqlx::types::Json<InstanceNetworkConfig>,
    /// Pending old/new union that remains routable during an update.
    pub update_network_config_request: Option<sqlx::types::Json<InstanceNetworkConfigUpdate>>,
    /// Instance-level NSG that can add reachability to any retained path.
    pub network_security_group_id:
        Option<carbide_uuid::network_security_group::NetworkSecurityGroupId>,
}

/// Policy and retained-path rows loaded only after exact tenant reuse is present.
#[derive(Debug)]
pub struct RoutingPolicySnapshot {
    /// Every persisted peering edge used by the DPU routing renderer.
    pub peerings: Vec<VpcPeering>,
    /// All NSGs, including soft-deleted groups retained by a routing attachment.
    pub network_security_groups: Vec<NetworkSecurityGroup>,
    /// Routing-only current and pending instance projections, including soft-deleted rows.
    pub instances: Vec<RoutingInstance>,
}

/// `lock_site_mutation` serializes site-wide routing graph mutations for the
/// duration of the caller's transaction.
///
/// This must be the transaction's first database lock. No short lock timeout is
/// applied: losing a routing update to ordinary contention would weaken atomic
/// admission. The wait belongs to the caller's request or controller-task
/// lifecycle; canceling that work rolls back the transaction, and commit or
/// rollback releases the lock normally.
pub async fn lock_site_mutation(txn: &mut PgConnection) -> DatabaseResult<()> {
    let query = "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))";
    sqlx::query(query)
        .bind(SITE_ROUTING_SAFETY_LOCK)
        .execute(txn)
        .await
        .map(|_| ())
        .map_err(|error| DatabaseError::query(query, error))
}

/// `load_addresses` reads the authoritative address inventory after the site
/// mutation lock has been acquired.
pub async fn load_addresses(txn: &mut PgConnection) -> DatabaseResult<RoutingAddressSnapshot> {
    // VPC deletion is soft. Retain the parent while a soft-deleted segment or
    // instance transition can still refer to it.
    let vpc_query = "SELECT * FROM vpcs ORDER BY id";
    let vpcs = sqlx::query_as(vpc_query)
        .fetch_all(&mut *txn)
        .await
        .map_err(|error| DatabaseError::query(vpc_query, error))?;

    let site_prefix_ids =
        crate::site_prefix::find_ids(&mut *txn, SitePrefixSearchFilter::default()).await?;
    let site_prefixes = crate::site_prefix::find_by_ids(&mut *txn, &site_prefix_ids).await?;

    let vpc_prefixes = crate::vpc_prefix::get_by_id(
        &mut *txn,
        ObjectColumnFilter::All::<crate::vpc_prefix::IdColumn>,
        DeletedFilter::Include,
    )
    .await?;

    // `find_by` deliberately has no deleted predicate; the segment controller
    // keeps a soft-deleted segment routed until final deletion.
    let network_segments = crate::network_segment::find_by(
        &mut *txn,
        ObjectColumnFilter::All::<crate::network_segment::IdColumn>,
        NetworkSegmentSearchConfig::default(),
    )
    .await?;

    Ok(RoutingAddressSnapshot {
        vpcs,
        site_prefixes,
        vpc_prefixes,
        network_segments,
    })
}

/// `load_policy_paths` reads policy and retained paths after the site mutation
/// lock is held.
///
/// All peerings are included. Soft-deleted security groups and instances remain
/// included so draining resources continue to constrain admission.
pub async fn load_policy_paths(txn: &mut PgConnection) -> DatabaseResult<RoutingPolicySnapshot> {
    let peering_ids = crate::vpc_peering::find_ids(&mut *txn, None).await?;
    let peerings = crate::vpc_peering::find_by_ids(&mut *txn, peering_ids).await?;

    // An NSG can be soft-deleted after its last active attachment disappears,
    // while a retained VPC or instance still references that policy during drain.
    let network_security_group_query = "SELECT * FROM network_security_groups ORDER BY id";
    let network_security_groups = sqlx::query_as(network_security_group_query)
        .fetch_all(&mut *txn)
        .await
        .map_err(|error| DatabaseError::query(network_security_group_query, error))?;

    // Release preserves these routing columns until hard delete. Avoid the
    // full instance/OS snapshot on every graph mutation.
    let instance_query = "SELECT id, network_config, update_network_config_request, \
                          network_security_group_id FROM instances ORDER BY id";
    let instances = sqlx::query_as(instance_query)
        .fetch_all(&mut *txn)
        .await
        .map_err(|error| DatabaseError::query(instance_query, error))?;

    Ok(RoutingPolicySnapshot {
        peerings,
        network_security_groups,
        instances,
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use carbide_uuid::machine::{MachineId, MachineIdSource, MachineType};
    use model::instance::config::network::{
        InstanceNetworkAutoConfig, InstanceNetworkConfig, InstanceNetworkConfigUpdate,
    };
    use model::network_prefix::NewNetworkPrefix;
    use model::network_segment::{
        AllocationStrategy, NetworkSegmentControllerState, NetworkSegmentType, NewNetworkSegment,
    };
    use sqlx::PgPool;

    use super::*;

    #[crate::sqlx_test]
    async fn site_mutation_lock_serializes_transactions(
        pool: PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut first = pool.begin().await?;
        let first_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(first.as_mut())
            .await?;
        lock_site_mutation(first.as_mut()).await?;

        let (pid_sender, pid_receiver) = tokio::sync::oneshot::channel();
        let second_pool = pool.clone();
        let mut second = tokio::spawn(async move {
            let mut txn = second_pool
                .begin()
                .await
                .map_err(|error| error.to_string())?;
            let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(txn.as_mut())
                .await
                .map_err(|error| error.to_string())?;
            pid_sender
                .send(pid)
                .map_err(|_| "could not report second transaction pid".to_string())?;
            lock_site_mutation(txn.as_mut())
                .await
                .map_err(|error| error.to_string())?;
            txn.commit().await.map_err(|error| error.to_string())
        });

        let second_pid = pid_receiver.await?;
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let blocked_by_first: bool =
                    sqlx::query_scalar("SELECT $1 = ANY(pg_blocking_pids($2))")
                        .bind(first_pid)
                        .bind(second_pid)
                        .fetch_one(&pool)
                        .await?;
                if blocked_by_first {
                    return Ok::<(), sqlx::Error>(());
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .map_err(|_| std::io::Error::other("second transaction did not wait on site lock"))??;

        first.commit().await?;
        tokio::time::timeout(Duration::from_secs(5), &mut second)
            .await
            .map_err(|_| std::io::Error::other("site lock remained blocked after commit"))?
            .map_err(|error| std::io::Error::other(error.to_string()))?
            .map_err(std::io::Error::other)?;
        Ok(())
    }

    #[crate::sqlx_test]
    async fn snapshot_retains_soft_deleted_routing_parents_and_children(
        pool: PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let vpc_id = carbide_uuid::vpc::VpcId::new();
        let old_vpc_id = carbide_uuid::vpc::VpcId::new();
        let new_vpc_id = carbide_uuid::vpc::VpcId::new();
        let network_security_group_id: carbide_uuid::network_security_group::NetworkSecurityGroupId =
            "retained-routing-policy".parse()?;
        let machine_id = MachineId::new(
            MachineIdSource::ProductBoardChassisSerial,
            [0x39; 32],
            MachineType::Host,
        );
        let mut setup = pool.begin().await?;
        sqlx::query(
            "INSERT INTO vpcs (id, name, organization_id, version) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(vpc_id)
        .bind("retained-routing-parent")
        .bind("tenant-a")
        .bind(config_version::ConfigVersion::initial())
        .execute(setup.as_mut())
        .await?;
        sqlx::query(
            "INSERT INTO tenants (organization_id, organization_name, version) \
             VALUES ($1, $2, $3)",
        )
        .bind("tenant-a")
        .bind("Tenant A")
        .bind(config_version::ConfigVersion::initial())
        .execute(setup.as_mut())
        .await?;
        sqlx::query("INSERT INTO machines (id, dpf) VALUES ($1, '{}'::jsonb)")
            .bind(machine_id)
            .execute(setup.as_mut())
            .await?;
        let current_network = InstanceNetworkConfig {
            interfaces: vec![],
            auto_config: Some(InstanceNetworkAutoConfig { vpc_id }),
        };
        let update = InstanceNetworkConfigUpdate {
            old_config: InstanceNetworkConfig {
                interfaces: vec![],
                auto_config: Some(InstanceNetworkAutoConfig { vpc_id: old_vpc_id }),
            },
            new_config: InstanceNetworkConfig {
                interfaces: vec![],
                auto_config: Some(InstanceNetworkAutoConfig { vpc_id: new_vpc_id }),
            },
        };
        let instance_id: carbide_uuid::instance::InstanceId = sqlx::query_scalar(
            "INSERT INTO instances \
             (machine_id, tenant_org, os_ipxe_script, network_config, \
              update_network_config_request, nvlink_config, deleted) \
             VALUES ($1, $2, $3, $4, $5, '{\"gpu_configs\": []}'::jsonb, NOW()) RETURNING id",
        )
        .bind(machine_id)
        .bind("tenant-a")
        .bind("#!ipxe retained-routing-instance")
        .bind(sqlx::types::Json(&current_network))
        .bind(sqlx::types::Json(&update))
        .fetch_one(setup.as_mut())
        .await?;
        sqlx::query(
            "INSERT INTO network_security_groups (id, tenant_organization_id, name, deleted) \
             VALUES ($1, $2, $3, NOW())",
        )
        .bind(&network_security_group_id)
        .bind("tenant-a")
        .bind("retained-routing-policy")
        .execute(setup.as_mut())
        .await?;
        let segment = crate::network_segment::persist(
            NewNetworkSegment {
                id: carbide_uuid::network::NetworkSegmentId::new(),
                name: "retained-routing-child".to_string(),
                subdomain_id: None,
                vpc_id: Some(vpc_id),
                mtu: 1500,
                prefixes: vec![NewNetworkPrefix {
                    prefix: "192.0.2.0/24".parse()?,
                    gateway: None,
                    dhcpv6_link_address: None,
                    num_reserved: 0,
                }],
                vlan_id: None,
                vni: None,
                segment_type: NetworkSegmentType::Tenant,
                can_stretch: None,
                allocation_strategy: AllocationStrategy::Dynamic,
                infer_slaac_eui64_addresses: false,
            },
            setup.as_mut(),
            NetworkSegmentControllerState::Ready,
        )
        .await?;
        crate::network_segment::mark_as_deleted(&segment, setup.as_mut()).await?;
        sqlx::query("UPDATE vpcs SET deleted=NOW() WHERE id=$1")
            .bind(vpc_id)
            .execute(setup.as_mut())
            .await?;
        setup.commit().await?;

        let mut txn = pool.begin().await?;
        lock_site_mutation(txn.as_mut()).await?;
        let addresses = load_addresses(txn.as_mut()).await?;
        let policy = load_policy_paths(txn.as_mut()).await?;
        assert!(
            addresses.vpcs.iter().any(|vpc| vpc.id == vpc_id),
            "soft-deleted VPC must remain available to resolve retained routing children"
        );
        let retained_segment = addresses
            .network_segments
            .iter()
            .find(|candidate| candidate.id == segment.id)
            .expect("soft-deleted segment must remain in the routing snapshot");
        assert_eq!(retained_segment.config.vpc_id, Some(vpc_id));
        assert_eq!(retained_segment.prefixes.len(), 1);
        assert!(retained_segment.prefixes[0].vpc_prefix_id.is_none());
        assert!(
            policy
                .network_security_groups
                .iter()
                .any(|group| group.id == network_security_group_id),
            "soft-deleted NSG must remain available for retained routing attachments"
        );
        let retained_instance = policy
            .instances
            .iter()
            .find(|instance| instance.id == instance_id)
            .expect("soft-deleted instance must remain in the routing snapshot");
        assert_eq!(retained_instance.network_config.0, current_network);
        assert_eq!(
            retained_instance
                .update_network_config_request
                .as_ref()
                .map(|request| &request.0),
            Some(&update)
        );
        txn.commit().await?;
        Ok(())
    }
}
