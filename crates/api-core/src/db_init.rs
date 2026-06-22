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

use std::collections::HashMap;

use carbide_network::virtualization::VpcVirtualizationType;
use carbide_uuid::vpc::VpcId;
use db::dns::domain;
use db::network_segment::reconcile_network_defs;
use db::vpc::{self};
use db::{ObjectColumnFilter, Transaction, dpu_agent_upgrade_policy, network_segment};
use itertools::Itertools;
use model::dns::NewDomain;
use model::firmware::AgentUpgradePolicyChoice;
use model::machine::upgrade_policy::AgentUpgradePolicy;
use model::metadata::Metadata;
use model::network_prefix::NewNetworkPrefix;
use model::network_segment::{NetworkDefinition, NetworkSegmentType, NewNetworkSegment};
use model::resource_pool;
use model::resource_pool::ResourcePool;
use model::vpc::{NewVpc, VpcDefinition, VpcStatus, VpcVirtualizationTypeCapabilities};
use sqlx::{Pool, Postgres};

use crate::CarbideError;
use crate::api::Api;

/// Create a Domain if we don't already have one.
/// Returns true if we created an entry in the db (we had no domains yet), false otherwise.
pub async fn create_initial_domain(
    db_pool: sqlx::pool::Pool<Postgres>,
    domain_name: &str,
) -> Result<bool, CarbideError> {
    let mut txn = Transaction::begin(&db_pool).await?;
    let domains = domain::find_by(&mut txn, ObjectColumnFilter::<domain::IdColumn>::All).await?;
    if domains.is_empty() {
        let domain = NewDomain::new(domain_name);
        db::dns::domain::persist_first(&domain, &mut txn).await?;
        txn.commit().await?;
        Ok(true)
    } else {
        let names: Vec<String> = domains.into_iter().map(|d| d.name).collect();
        if !names.iter().any(|n| n == domain_name) {
            tracing::warn!(
                "Initial domain name '{domain_name}' in config file does not match existing database domains: {:?}",
                names
            );
        }
        Ok(false)
    }
}
pub async fn create_initial_networks(
    api: &Api,
    db_pool: &Pool<Postgres>,
    networks: &HashMap<String, NetworkDefinition>,
) -> Result<(), CarbideError> {
    let mut txn = Transaction::begin(db_pool).await?;
    let all_domains = db::dns::domain::find_by(
        &mut txn,
        ObjectColumnFilter::<db::dns::domain::IdColumn>::All,
    )
    .await?;
    if all_domains.is_empty() {
        tracing::warn!("No domain configured, skipping initial network creation");
        return Ok(());
    }
    if all_domains.len() > 1 {
        // We only create initial networks if we only have a single domain - usually created
        // as initial_domain_name in config file.
        // Having multiple domains is fine, it means we probably created the network much
        // earlier.
        tracing::info!("Multiple domains, skipping initial network creation");
        return Ok(());
    }
    let domain_id = all_domains[0].id;
    reconcile_network_defs(&mut txn, networks).await?;

    for (name, def) in networks {
        if db::network_segment::find_by_name(&mut txn, name)
            .await
            .is_ok()
        {
            // Network segments are only created the first time we start carbide-api;
            // `reconcile_network_defs` above has already recorded the snapshot if
            // it was missing (the backfill path).
            tracing::debug!("Network segment {name} exists");
            continue;
        }

        let mut ns = NewNetworkSegment::build_from(name, domain_id, def)?;
        ns.can_stretch = Some(true);
        ns.vpc_id = if let Some(vpc_name) = &def.vpc_name {
            match db::vpc::find_by_name(&mut txn, vpc_name).await?.as_slice() {
                [vpc] => {
                    vpc.network_virtualization_type
                        .ensure_supports_segment(&ns)?;
                    Some(vpc.id)
                }
                [] => {
                    return Err(CarbideError::InvalidArgument(format!(
                        "Network segment {name} references VPC {vpc_name}, but no VPC with that name exists"
                    )));
                }
                _ => {
                    return Err(CarbideError::InvalidArgument(format!(
                        "Network segment {name} references VPC {vpc_name}, but multiple VPCs with that name exist"
                    )));
                }
            }
        } else {
            None
        };

        // Capture before `save` moves `ns`. `insert_network_def` needs
        // the id because `network_def.segment_id` is FK-bound to it.
        let segment_id = ns.id;
        // update_network_segments_svi_ip will take care of allocating svi ip.
        tracing::info!("Creating network segment {name} from config: {ns:?}");
        crate::handlers::network_segment::save(api, &mut txn, ns, true, false).await?;
        // Snapshot the network definition in the same transaction as the network_segment row,
        // so the two stay consistent across restarts.
        db::network_segment::insert_network_def(&mut txn, name, segment_id, def).await?;
        tracing::info!("Created network segment {name}");
    }

    ensure_static_assignments_segment(api, &mut txn, Some(domain_id)).await?;

    txn.commit().await?;
    Ok(())
}

pub async fn create_initial_vpcs(
    db_pool: &Pool<Postgres>,
    vpcs: &HashMap<String, VpcDefinition>,
    vni_pool: &ResourcePool<i32>,
) -> Result<(), CarbideError> {
    let mut txn = Transaction::begin(db_pool).await?;
    for (name, def) in vpcs {
        if db::vpc::find_by_name(&mut txn, name)
            .await
            .is_ok_and(|v| !v.is_empty())
        {
            tracing::debug!("VPC {name} exists");
            continue;
        }

        let vpc_id = VpcId::new();
        let tenant_organization_id = def
            .organization_id
            .clone()
            .unwrap_or(uuid::Uuid::new_v4().into());

        let vni = db::resource_pool::allocate(
            vni_pool,
            &mut txn,
            resource_pool::OwnerType::Vpc,
            vpc_id.to_string().as_ref(),
            def.vni,
        )
        .await?;

        let vpc = NewVpc {
            id: vpc_id,
            tenant_organization_id,
            network_virtualization_type: def.network_virtualization_type,
            metadata: Metadata {
                name: name.to_owned(),
                ..Default::default()
            },
            network_security_group_id: None,
            routing_profile_type: def.routing_profile_type.clone(),
            vni: Some(vni),
        };

        // Validation
        if def.routing_profile_type.is_some() {
            def.network_virtualization_type
                .ensure_supports_routing_profiles()
                .map_err(CarbideError::from)?;
        }

        db::vpc::persist(vpc, VpcStatus { vni: Some(vni) }, &mut txn).await?;
        tracing::info!("Created VPC {name}");
    }

    txn.commit().await?;
    Ok(())
}

/// Create the static-assignments anchor segment if it doesn't exist.
/// This segment holds external static IP assignments that don't fall
/// within any managed network prefix. The placeholder prefixes are never
/// handed out by the allocator; they exist because the schema requires
/// segment prefixes and because static assignments can be IPv4 or IPv6.
pub async fn ensure_static_assignments_segment(
    api: &Api,
    txn: &mut db::Transaction<'_>,
    subdomain_id: Option<carbide_uuid::domain::DomainId>,
) -> Result<(), CarbideError> {
    let segment_name = network_segment::STATIC_ASSIGNMENTS_SEGMENT_NAME;
    if db::network_segment::find_by_name(txn, segment_name)
        .await
        .is_ok()
    {
        return Ok(());
    }

    let ns = NewNetworkSegment {
        id: uuid::Uuid::new_v4().into(),
        name: segment_name.to_string(),
        subdomain_id,
        vpc_id: None,
        mtu: 1500,
        prefixes: vec![
            NewNetworkPrefix {
                prefix: "169.254.254.254/32".parse().unwrap(),
                gateway: None,
                dhcpv6_link_address: None,
                num_reserved: 1,
            },
            NewNetworkPrefix {
                prefix: "100::/128".parse().unwrap(),
                gateway: None,
                dhcpv6_link_address: None,
                num_reserved: 1,
            },
        ],
        vlan_id: None,
        vni: None,
        segment_type: NetworkSegmentType::Underlay,
        can_stretch: Some(false),
        allocation_strategy: model::network_segment::AllocationStrategy::Reserved,
    };
    crate::handlers::network_segment::save(api, txn, ns, true, false).await?;
    tracing::info!("Created internal {segment_name} segment for holding static assignments");

    Ok(())
}

pub async fn update_network_segments_svi_ip(db_pool: &Pool<Postgres>) -> Result<(), CarbideError> {
    let mut txn = Transaction::begin(db_pool).await?;
    let all_segments = db::network_segment::find_by(
        &mut txn,
        ObjectColumnFilter::<network_segment::IdColumn>::All,
        model::network_segment::NetworkSegmentSearchConfig::default(),
    )
    .await?;

    let all_segments = all_segments
        .into_iter()
        .filter(|x| x.status.can_stretch.is_some_and(|x| x))
        .collect::<Vec<_>>();

    let all_vpcs_ids = all_segments
        .iter()
        .filter_map(|x| x.config.vpc_id)
        .collect_vec();
    let all_vpcs = db::vpc::find_by(
        &mut txn,
        ObjectColumnFilter::List(vpc::IdColumn, &all_vpcs_ids),
    )
    .await?;

    let all_vpcs = all_vpcs
        .iter()
        .map(|x| (x.id, x))
        .collect::<HashMap<_, _>>();

    txn.rollback().await?;

    // Allocate SVI IP for the segments attached to a FNN VPC.
    for segment in all_segments {
        let Some(vpc_id) = segment.config.vpc_id else {
            continue;
        };

        let Some(vpc) = all_vpcs.get(&vpc_id) else {
            continue;
        };

        // SVI IP is needed only for FNN.
        if vpc.network_virtualization_type != VpcVirtualizationType::Fnn {
            continue;
        }

        // Already SVI IP is allocated for every prefix. Prefixless segments
        // still fall through so allocate_svi_ip reports the invalid state.
        if !segment.prefixes.is_empty() && segment.prefixes.iter().all(|x| x.svi_ip.is_some()) {
            continue;
        }

        let mut txn = Transaction::begin(db_pool).await?;

        match db::network_segment::allocate_svi_ip(&segment, &mut txn).await {
            Ok(_) => {
                txn.commit().await?;
            }
            Err(err) => {
                tracing::error!(
                    "Updating SVI IP filed for segment: {} - Error: {err}",
                    segment.id
                );
                txn.rollback().await?;
            }
        }
    }

    Ok(())
}

pub async fn store_initial_dpu_agent_upgrade_policy(
    db_pool: &Pool<Postgres>,
    initial_dpu_agent_upgrade_policy: Option<AgentUpgradePolicyChoice>,
) -> Result<(), CarbideError> {
    let mut txn = Transaction::begin(db_pool).await?;
    let initial_policy: AgentUpgradePolicy = initial_dpu_agent_upgrade_policy
        .unwrap_or(AgentUpgradePolicyChoice::UpDown)
        .into();
    let current_policy = dpu_agent_upgrade_policy::get(&mut txn).await?;
    // Only set if the very first time, it's the initial policy
    if current_policy.is_none() {
        dpu_agent_upgrade_policy::set(&mut txn, initial_policy).await?;
        tracing::debug!(
            %initial_policy,
            "Initialized DPU agent upgrade policy"
        );
    }
    txn.commit().await?;

    Ok(())
}

pub(crate) async fn create_admin_vpc(
    db_pool: &Pool<Postgres>,
    vpc_vni: Option<u32>,
) -> Result<(), CarbideError> {
    let Some(vpc_vni) = vpc_vni else {
        return Err(CarbideError::internal(
            "No VNI is configured for admin VPC.".to_string(),
        ));
    };

    let mut txn = Transaction::begin(db_pool).await?;

    let configured_vni = vpc_vni as i32;
    let admin_segments = db::network_segment::admin(&mut txn).await?;
    let attached_admin_vpc_ids = admin_segments
        .iter()
        .filter_map(|segment| segment.config.vpc_id)
        .unique()
        .collect_vec();

    // Admin VPC startup reconciliation has three expected cases:
    // 1. Fresh install with admin FNN enabled: no admin segments are attached
    //    and no VPC should already own the configured admin VNI, so create it.
    // 2. Existing install with admin FNN already seeded: admin segments point
    //    at one admin VPC, so that attached VPC is authoritative and its VNI
    //    may be updated from config.
    // 3. Existing install enabling admin FNN for the first time: admin segments
    //    are unattached, but tenant VPCs may already exist. In this case we
    //    must reject if any VPC already owns the configured admin VNI rather
    //    than adopting that VPC as the admin VPC.
    let existing_vpc = match attached_admin_vpc_ids.as_slice() {
        [admin_vpc_id] => {
            // The attached VPC is the authoritative admin VPC across config changes.
            let mut vpcs = db::vpc::find_by(
                &mut txn,
                ObjectColumnFilter::One(vpc::IdColumn, admin_vpc_id),
            )
            .await?;
            if vpcs.len() != 1 {
                return Err(CarbideError::internal(format!(
                    "Admin network segment references missing VPC {admin_vpc_id}."
                )));
            }
            Some(vpcs.remove(0))
        }
        [] => {
            // This is first-time admin VPC seeding. Do not adopt an existing
            // tenant VPC that happens to use the configured admin VNI.
            if let Some(conflicting_vpc) =
                db::vpc::find_by_vni(&mut txn, configured_vni).await?.pop()
            {
                return Err(CarbideError::internal(format!(
                    "Configured admin VPC VNI {configured_vni} is already used by VPC {}, but no admin VPC is attached to admin network segments.",
                    conflicting_vpc.id
                )));
            }
            None
        }
        _ => {
            return Err(CarbideError::internal(format!(
                "Admin network segments are attached to multiple VPCs: {}.",
                attached_admin_vpc_ids.iter().join(", ")
            )));
        }
    };

    if let Some(mut existing_vpc) = existing_vpc {
        let existing_vni = existing_vpc.status.as_ref().and_then(|status| status.vni);
        if existing_vni != Some(configured_vni) || existing_vpc.vni != Some(configured_vni) {
            if let Some(conflicting_vpc) = db::vpc::find_by_vni(&mut txn, configured_vni)
                .await?
                .into_iter()
                .find(|vpc| vpc.id != existing_vpc.id)
            {
                return Err(CarbideError::internal(format!(
                    "Configured admin VPC VNI {configured_vni} is already used by VPC {}, but admin network segments are attached to VPC {}.",
                    conflicting_vpc.id, existing_vpc.id
                )));
            }

            existing_vpc = db::vpc::set_vni(&existing_vpc, &mut txn, configured_vni).await?;
            tracing::info!(
                vpc_id = %existing_vpc.id,
                previous_vni = ?existing_vni,
                configured_vni,
                "Updated admin VPC VNI from FNN config"
            );
        }

        for admin_segment in admin_segments {
            match admin_segment.config.vpc_id {
                Some(vpc_id) if vpc_id != existing_vpc.id => {
                    return Err(CarbideError::internal(format!(
                        "Mismatch found in admin vpc id {} and admin network segment's attached vpc id {vpc_id}.",
                        existing_vpc.id
                    )));
                }
                Some(_) => {}
                None => {
                    // Attach any newly-created admin segment to the existing admin VPC.
                    db::network_segment::set_vpc_id_and_can_stretch(
                        &admin_segment,
                        &mut txn,
                        existing_vpc.id,
                    )
                    .await?;
                }
            }
        }

        txn.commit().await?;

        return Ok(());
    }

    // Let's create admin vpc.
    let admin_vpc = NewVpc {
        id: uuid::Uuid::new_v4().into(),
        vni: Some(configured_vni),
        tenant_organization_id: "carbide_internal".to_string(),
        // For consistency, but admin routing profile is defined in-line in the
        // FNN config.
        routing_profile_type: None, // It's purely informational.  Admin profile is pulled from an inline-config and not tied to a name or ID.
        network_security_group_id: None,
        network_virtualization_type: carbide_network::virtualization::VpcVirtualizationType::Fnn,
        metadata: Metadata {
            name: "admin".to_string(),
            labels: HashMap::from([("kind".to_string(), "admin".to_string())]),
            ..Metadata::default()
        },
    };

    let vpc = db::vpc::persist(
        admin_vpc,
        VpcStatus {
            vni: Some(configured_vni),
        },
        &mut txn,
    )
    .await?;

    // Attach it to admin network segments.
    for admin_segment in admin_segments {
        db::network_segment::set_vpc_id_and_can_stretch(&admin_segment, &mut txn, vpc.id).await?;
    }

    txn.commit().await?;

    Ok(())
}
