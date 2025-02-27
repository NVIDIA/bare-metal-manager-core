/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::{collections::HashMap, net::IpAddr, str::FromStr, sync::Arc};

use forge_network::virtualization::VpcVirtualizationType;
use itertools::Itertools;
use sqlx::{Pool, Postgres};

use crate::db::vpc::{self, NewVpc, Vpc};
use crate::db::{ObjectColumnFilter, network_segment};
use crate::model::metadata::Metadata;
use crate::{
    CarbideError,
    api::Api,
    cfg::file::{AgentUpgradePolicyChoice, CarbideConfig},
    db::{
        DatabaseError,
        domain::{self, Domain, NewDomain},
        dpu_agent_upgrade_policy::DpuAgentUpgradePolicy,
        network_segment::{NetworkSegment, NewNetworkSegment},
        route_servers::RouteServer,
    },
    model::{machine::upgrade_policy::AgentUpgradePolicy, network_segment::NetworkDefinition},
};

/// Create a Domain if we don't already have one.
/// Returns true if we created an entry in the db (we had no domains yet), false otherwise.
pub async fn create_initial_domain(
    db_pool: sqlx::pool::Pool<Postgres>,
    domain_name: &str,
) -> Result<bool, CarbideError> {
    let mut txn = db_pool
        .begin()
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "begin create_initial_domain", e))?;
    let domains = Domain::find_by(&mut txn, ObjectColumnFilter::<domain::IdColumn>::All).await?;
    if domains.is_empty() {
        let domain = NewDomain::new(domain_name);
        domain.persist_first(&mut txn).await?;
        txn.commit()
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), "commit create_initial_domain", e))?;
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

// pub so we can test it from integration test
pub async fn create_initial_networks(
    api: &Api,
    db_pool: &Pool<Postgres>,
    networks: &HashMap<String, NetworkDefinition>,
) -> Result<(), CarbideError> {
    let mut txn = db_pool
        .begin()
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "begin create_initial_networks", e))?;
    let all_domains =
        Domain::find_by(&mut txn, ObjectColumnFilter::<domain::IdColumn>::All).await?;
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
        if NetworkSegment::find_by_name(&mut txn, name).await.is_ok() {
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
    txn.commit()
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "commit create_initial_networks", e))?;
    Ok(())
}

pub async fn update_network_segments_svi_ip(db_pool: &Pool<Postgres>) -> Result<(), CarbideError> {
    let mut txn = db_pool
        .begin()
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "begin allocate SVI IP", e))?;
    let all_segments = NetworkSegment::find_by(
        &mut txn,
        ObjectColumnFilter::<network_segment::IdColumn>::All,
        crate::db::network_segment::NetworkSegmentSearchConfig::default(),
    )
    .await?;

    let all_segments = all_segments
        .into_iter()
        .filter(|x| x.can_stretch.is_some_and(|x| x))
        .collect::<Vec<_>>();

    let all_vpcs_ids = all_segments.iter().filter_map(|x| x.vpc_id).collect_vec();
    let all_vpcs = Vpc::find_by(
        &mut txn,
        ObjectColumnFilter::List(vpc::IdColumn, &all_vpcs_ids),
    )
    .await?;

    let all_vpcs = all_vpcs
        .iter()
        .map(|x| (x.id, x))
        .collect::<HashMap<_, _>>();

    txn.rollback()
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "rollback update svi_ip", e))?;

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

        let mut txn = db_pool.begin().await.map_err(|e| {
            DatabaseError::new(file!(), line!(), "begin inetrnal allocate SVI IP", e)
        })?;

        match segment.allocate_svi_ip(&mut txn).await {
            Ok(_) => {
                txn.commit()
                    .await
                    .map_err(|e| DatabaseError::new(file!(), line!(), "commit update svi_ip", e))?;
            }
            Err(err) => {
                tracing::error!(
                    "Updating SVI IP filed for segment: {} - Error: {err}",
                    segment.id
                );
                txn.rollback()
                    .await
                    .map_err(|e| DatabaseError::new(file!(), line!(), "commit update svi_ip", e))?;
            }
        }
    }

    Ok(())
}

pub async fn create_initial_route_servers(
    db_pool: &Pool<Postgres>,
    carbide_config: &Arc<CarbideConfig>,
) -> Result<Vec<String>, CarbideError> {
    let mut txn = db_pool.begin().await.map_err(|e| {
        DatabaseError::new(file!(), line!(), "begin create_initial_route_servers", e)
    })?;
    let result = if carbide_config.enable_route_servers {
        let route_servers: Vec<IpAddr> = carbide_config
            .route_servers
            .iter()
            .map(|rs| IpAddr::from_str(rs))
            .collect::<Result<Vec<IpAddr>, _>>()
            .map_err(CarbideError::AddressParseError)?;

        RouteServer::get_or_create(&mut txn, &route_servers).await?
    } else {
        RouteServer::replace(&mut txn, &[]).await?;
        vec![]
    };

    txn.commit().await.map_err(|e| {
        DatabaseError::new(file!(), line!(), "commit create_initial_route_servers", e)
    })?;

    Ok(result.into_iter().map(|rs| rs.to_string()).collect())
}

pub async fn store_initial_dpu_agent_upgrade_policy(
    db_pool: &Pool<Postgres>,
    initial_dpu_agent_upgrade_policy: Option<AgentUpgradePolicyChoice>,
) -> Result<(), CarbideError> {
    let mut txn = db_pool
        .begin()
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "begin agent upgrade policy", e))?;
    let initial_policy: AgentUpgradePolicy = initial_dpu_agent_upgrade_policy
        .unwrap_or(super::cfg::file::AgentUpgradePolicyChoice::UpOnly)
        .into();
    let current_policy = DpuAgentUpgradePolicy::get(&mut txn).await?;
    // Only set if the very first time, it's the initial policy
    if current_policy.is_none() {
        DpuAgentUpgradePolicy::set(&mut txn, initial_policy).await?;
        tracing::debug!(
            %initial_policy,
            "Initialized DPU agent upgrade policy"
        );
    }
    txn.commit()
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "commit agent upgrade policy", e))?;

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

    let mut txn = db_pool
        .begin()
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "begin agent upgrade policy", e))?;

    let admin_segment = NetworkSegment::admin(&mut txn).await?;
    let existing_vpc = Vpc::find_by_vni(&mut txn, vpc_vni as i32).await?;
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
            admin_segment
                .set_vpc_id_and_can_stretch(&mut txn, existing_vpc.id)
                .await?;
            return Ok(());
        }
    }

    // Let's create admin vpc.
    let admin_vpc = NewVpc {
        id: uuid::Uuid::new_v4().into(),
        tenant_organization_id: "carbide_internal".to_string(),
        network_security_group_id: None,
        network_virtualization_type: forge_network::virtualization::VpcVirtualizationType::Fnn,
        metadata: Metadata {
            name: "admin".to_string(),
            labels: HashMap::from([("kind".to_string(), "admin".to_string())]),
            ..Metadata::default()
        },
    };

    let vpc = admin_vpc.persist(&mut txn).await?;
    Vpc::set_vni(&mut txn, vpc.id, vpc_vni as i32).await?;

    // Attach it to admin network segment.
    admin_segment
        .set_vpc_id_and_can_stretch(&mut txn, vpc.id)
        .await?;

    txn.commit()
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "commit agent upgrade policy", e))?;

    Ok(())
}
