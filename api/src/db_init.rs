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

use sqlx::{Pool, Postgres};

use crate::{
    api::Api,
    cfg::{AgentUpgradePolicyChoice, CarbideConfig},
    db::{
        domain::{Domain, NewDomain},
        dpu_agent_upgrade_policy::DpuAgentUpgradePolicy,
        network_segment::{NetworkSegment, NewNetworkSegment},
        route_servers::RouteServer,
        DatabaseError, UuidKeyedObjectFilter,
    },
    model::{machine::upgrade_policy::AgentUpgradePolicy, network_segment::NetworkDefinition},
    CarbideError,
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
    let domains = Domain::find(&mut txn, UuidKeyedObjectFilter::All).await?;
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
    let all_domains = Domain::find(&mut txn, UuidKeyedObjectFilter::All).await?;
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
        let ns = NewNetworkSegment::build_from(name, domain_id, def)?;
        crate::handlers::network_segment::save(api, &mut txn, ns, true).await?;
        tracing::info!("Created network segment {name}");
    }
    txn.commit()
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "commit create_initial_networks", e))?;
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
        .unwrap_or(super::cfg::AgentUpgradePolicyChoice::UpOnly)
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
