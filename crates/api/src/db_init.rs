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

use db::dns::domain;
use db::vpc::{self};
use db::{ObjectColumnFilter, Transaction, dpu_agent_upgrade_policy, network_segment};
use forge_network::virtualization::VpcVirtualizationType;
use itertools::Itertools;
use model::dns::NewDomain;
use model::firmware::AgentUpgradePolicyChoice;
use model::machine::upgrade_policy::AgentUpgradePolicy;
use model::metadata::Metadata;
use model::network_segment::{NetworkDefinition, NewNetworkSegment};
use model::vpc::NewVpc;
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
    if all_domains.len() != 1 {
        // We only create initial networks if we only have a single domain - usually created
        // as initial_domain_name in config file.
        // Having multiple domains is fine, it means we probably created the network much
        // earlier.
        tracing::info!("Multiple domains, skipping initial network creation");
        return Ok(());
    }
    let domain_id = all_domains[0].id;
    for (name, def) in networks {
        if db::network_segment::find_by_name(&mut txn, name)
            .await
            .is_ok()
        {
            // Network segments are only created the first time we start carbide-api
            tracing::debug!("Network segment {name} exists");
            continue;
        }
        let mut ns = NewNetworkSegment::build_from(name, domain_id, def)?;
        ns.can_stretch = Some(true);
        // update_network_segments_svi_ip will take care of allocating svi ip.
        crate::handlers::network_segment::save(api, &mut txn, ns, true, false).await?;
        tracing::info!("Created network segment {name}");
    }
    txn.commit().await?;
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
        .filter(|x| x.can_stretch.is_some_and(|x| x))
        .collect::<Vec<_>>();

    let all_vpcs_ids = all_segments.iter().filter_map(|x| x.vpc_id).collect_vec();
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
        let Some(vpc_id) = segment.vpc_id else {
            continue;
        };

        let Some(vpc) = all_vpcs.get(&vpc_id) else {
            continue;
        };

        // SVI IP is needed only for FNN.
        if vpc.network_virtualization_type != VpcVirtualizationType::Fnn {
            continue;
        }

        // Already SVI IP is allocated.
        if segment.prefixes.iter().any(|x| x.svi_ip.is_some()) {
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
        .unwrap_or(AgentUpgradePolicyChoice::UpOnly)
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

    let admin_segment = db::network_segment::admin(&mut txn).await?;
    let existing_vpc = db::vpc::find_by_vni(&mut txn, vpc_vni as i32).await?;
    if let Some(existing_vpc) = existing_vpc.first() {
        if let Some(vpc_id) = admin_segment.vpc_id {
            if vpc_id != existing_vpc.id {
                return Err(CarbideError::internal(format!(
                    "Mismatch found in admin vpc id {} and admin network segment's attached vpc id {vpc_id}.",
                    existing_vpc.id
                )));
            }

            // All good here. We have valid admin vpc and it is attached to valid segment.
            return Ok(());
        } else {
            // Somehow vni field is not updated in network segment table. do it now.
            db::network_segment::set_vpc_id_and_can_stretch(
                &admin_segment,
                &mut txn,
                existing_vpc.id,
            )
            .await?;
            return Ok(());
        }
    }

    // Let's create admin vpc.
    let admin_vpc = NewVpc {
        id: uuid::Uuid::new_v4().into(),
        tenant_organization_id: "carbide_internal".to_string(),
        // For consistency, but admin routing profile is defined in-line in the
        // FNN config.
        routing_profile_type: Some(model::tenant::RoutingProfileType::Admin),
        network_security_group_id: None,
        network_virtualization_type: forge_network::virtualization::VpcVirtualizationType::Fnn,
        metadata: Metadata {
            name: "admin".to_string(),
            labels: HashMap::from([("kind".to_string(), "admin".to_string())]),
            ..Metadata::default()
        },
    };

    let vpc = db::vpc::persist(admin_vpc, &mut txn).await?;
    db::vpc::set_vni(&mut txn, vpc.id, vpc_vni as i32).await?;

    // Attach it to admin network segment.
    db::network_segment::set_vpc_id_and_can_stretch(&admin_segment, &mut txn, vpc.id).await?;

    txn.commit().await?;

    Ok(())
}
