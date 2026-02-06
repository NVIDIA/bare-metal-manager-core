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
use ::rpc::forge as rpc;
use db::resource_pool::ResourcePoolDatabaseError;
use db::{AnnotatedSqlxError, DatabaseError, ObjectColumnFilter, WithTransaction, network_segment};
use forge_network::virtualization::VpcVirtualizationType;
use futures_util::FutureExt;
use model::network_segment::{
    NetworkSegment, NetworkSegmentControllerState, NetworkSegmentSearchConfig, NetworkSegmentType,
    NewNetworkSegment,
};
use sqlx::{PgConnection, PgTransaction};
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::{Api, log_request_data};

pub(crate) async fn find_ids(
    api: &Api,
    request: Request<rpc::NetworkSegmentSearchFilter>,
) -> Result<Response<rpc::NetworkSegmentIdList>, Status> {
    log_request_data(&request);

    let filter: rpc::NetworkSegmentSearchFilter = request.into_inner();

    let network_segments_ids = api
        .with_txn(|txn| db::network_segment::find_ids(txn, filter).boxed())
        .await??;

    Ok(Response::new(rpc::NetworkSegmentIdList {
        network_segments_ids,
    }))
}

pub(crate) async fn find_by_ids(
    api: &Api,
    request: Request<rpc::NetworkSegmentsByIdsRequest>,
) -> Result<Response<rpc::NetworkSegmentList>, Status> {
    log_request_data(&request);
    let rpc::NetworkSegmentsByIdsRequest {
        network_segments_ids,
        include_history,
        include_num_free_ips,
        ..
    } = request.into_inner();

    let max_find_by_ids = api.runtime_config.max_find_by_ids as usize;
    if network_segments_ids.len() > max_find_by_ids {
        return Err(CarbideError::InvalidArgument(format!(
            "no more than {max_find_by_ids} IDs can be accepted"
        ))
        .into());
    } else if network_segments_ids.is_empty() {
        return Err(
            CarbideError::InvalidArgument("at least one ID must be provided".to_string()).into(),
        );
    }

    let segments = api
        .with_txn(|txn| {
            db::network_segment::find_by(
                txn,
                ObjectColumnFilter::List(network_segment::IdColumn, &network_segments_ids),
                NetworkSegmentSearchConfig {
                    include_history,
                    include_num_free_ips,
                },
            )
            .boxed()
        })
        .await??;

    let mut result = Vec::with_capacity(segments.len());
    for seg in segments {
        result.push(seg.try_into()?);
    }
    Ok(Response::new(rpc::NetworkSegmentList {
        network_segments: result,
    }))
}

pub(crate) async fn create(
    api: &Api,
    request: Request<rpc::NetworkSegmentCreationRequest>,
) -> Result<Response<rpc::NetworkSegment>, Status> {
    crate::api::log_request_data(&request);

    let request = request.into_inner();

    let new_network_segment = NewNetworkSegment::try_from(request)?;

    if new_network_segment.segment_type.is_tenant()
        && let Some(site_fabric_prefixes) = api.eth_data.site_fabric_prefixes.as_ref()
    {
        let segment_prefixes: Vec<_> = new_network_segment
            .prefixes
            .iter()
            .map(|np| np.prefix)
            .collect();

        let uncontained_prefixes: Vec<_> = segment_prefixes
            .into_iter()
            .filter(|segment_prefix| !site_fabric_prefixes.contains(*segment_prefix))
            .collect();

        // Anything in uncontained_prefixes did not match any of our
        // site fabric prefixes, and if we allowed it to be used then VPC
        // isolation would not function properly for traffic addressed to
        // that prefix.
        if !uncontained_prefixes.is_empty() {
            let uncontained_prefixes = itertools::join(uncontained_prefixes, ", ");
            let msg = format!(
                "One or more requested network segment prefixes were not contained \
                        within the configured site fabric prefixes: {uncontained_prefixes}"
            );
            return Err(CarbideError::InvalidArgument(msg).into());
        }
    }

    let mut txn = api.txn_begin().await?;

    let allocate_svi_ip = if let Some(vpc_id) = new_network_segment.vpc_id {
        if new_network_segment.can_stretch.unwrap_or(true) {
            let vpcs = db::vpc::find_by(
                &mut txn,
                ObjectColumnFilter::One(db::vpc::IdColumn, &vpc_id),
            )
            .await?;

            let vpc = vpcs
                .first()
                .ok_or_else(|| CarbideError::internal(format!("VPC ID: {vpc_id} not found.")))?;

            vpc.network_virtualization_type == VpcVirtualizationType::Fnn
        } else {
            false
        }
    } else {
        false
    };

    let network_segment = save(api, &mut txn, new_network_segment, false, allocate_svi_ip).await?;

    let response = Ok(Response::new(network_segment.try_into()?));
    txn.commit().await?;
    response
}

pub(crate) async fn delete(
    api: &Api,
    request: Request<rpc::NetworkSegmentDeletionRequest>,
) -> Result<Response<rpc::NetworkSegmentDeletionResult>, Status> {
    crate::api::log_request_data(&request);

    let mut txn = api.txn_begin().await?;

    let rpc::NetworkSegmentDeletionRequest { id, .. } = request.into_inner();

    let segment_id = id.ok_or_else(|| CarbideError::MissingArgument("id"))?;

    let mut segments = db::network_segment::find_by(
        &mut txn,
        ObjectColumnFilter::One(network_segment::IdColumn, &segment_id),
        NetworkSegmentSearchConfig::default(),
    )
    .await?;

    let segment = match segments.len() {
        1 => segments.remove(0),
        _ => {
            return Err(CarbideError::NotFoundError {
                kind: "network segment",
                id: segment_id.to_string(),
            }
            .into());
        }
    };

    let response = Ok(db::network_segment::mark_as_deleted(&segment, &mut txn)
        .await
        .map(|_| rpc::NetworkSegmentDeletionResult {})
        .map(Response::new)?);

    txn.commit().await?;

    response
}

pub(crate) async fn for_vpc(
    api: &Api,
    request: Request<rpc::VpcSearchQuery>,
) -> Result<Response<rpc::NetworkSegmentList>, Status> {
    crate::api::log_request_data(&request);

    let rpc::VpcSearchQuery { id, .. } = request.into_inner();

    let uuid = id.ok_or_else(|| CarbideError::InvalidArgument("id".to_string()))?;

    let results = api
        .with_txn(|txn| db::network_segment::for_vpc(txn, uuid).boxed())
        .await??;

    let mut network_segments = Vec::with_capacity(results.len());

    for result in results {
        network_segments.push(result.try_into()?);
    }

    Ok(Response::new(rpc::NetworkSegmentList { network_segments }))
}

// Called by db_init::create_initial_networks
pub(crate) async fn save(
    api: &Api,
    // Note: This is a PgTransaction, not a PgConnection, because we will be doing table locking,
    // which must happen in a transaction.
    txn: &mut PgTransaction<'_>,
    mut ns: NewNetworkSegment,
    set_to_ready: bool,
    allocate_svi_ip: bool,
) -> Result<NetworkSegment, CarbideError> {
    if ns.segment_type != NetworkSegmentType::Underlay {
        ns.vlan_id = Some(allocate_vlan_id(api, txn, &ns.name).await?);
        ns.vni = Some(allocate_vni(api, txn, &ns.name).await?);
    }
    let initial_state = if set_to_ready {
        NetworkSegmentControllerState::Ready
    } else {
        NetworkSegmentControllerState::Provisioning
    };
    let mut network_segment = match db::network_segment::persist(ns, txn, initial_state).await {
        Ok(segment) => segment,
        Err(DatabaseError::Sqlx(AnnotatedSqlxError {
            source: sqlx::Error::Database(e),
            ..
        })) if e.constraint() == Some("network_prefixes_prefix_excl") => {
            return Err(CarbideError::InvalidArgument(
                "Prefix overlaps with an existing one".to_string(),
            ));
        }
        Err(err) => {
            return Err(err.into());
        }
    };

    if allocate_svi_ip {
        db::network_segment::allocate_svi_ip(&network_segment, txn).await?;
        let network_segments = db::network_segment::find_by(
            txn,
            ObjectColumnFilter::One(network_segment::IdColumn, &network_segment.id),
            NetworkSegmentSearchConfig::default(),
        )
        .await?;

        network_segment = network_segments
            .first()
            .ok_or_else(|| CarbideError::NotFoundError {
                kind: "NetworkSegment",
                id: network_segment.id.to_string(),
            })?
            .clone();
    }

    Ok(network_segment)
}

/// Allocate a value from the vni resource pool.
///
/// If the pool exists but is empty or has en error, return that.
pub async fn allocate_vni(
    api: &Api,
    txn: &mut PgConnection,
    owner_id: &str,
) -> Result<i32, CarbideError> {
    match db::resource_pool::allocate(
        &api.common_pools.ethernet.pool_vni,
        txn,
        model::resource_pool::OwnerType::NetworkSegment,
        owner_id,
    )
    .await
    {
        Ok(val) => Ok(val),
        Err(ResourcePoolDatabaseError::ResourcePool(
            model::resource_pool::ResourcePoolError::Empty,
        )) => {
            tracing::error!(owner_id, pool = "vni", "Pool exhausted, cannot allocate");
            Err(CarbideError::ResourceExhausted("pool vni".to_string()))
        }
        Err(err) => {
            tracing::error!(owner_id, error = %err, pool = "vni", "Error allocating from resource pool");
            Err(err.into())
        }
    }
}

/// Allocate a value from the vlan id resource pool.
///
/// If the pool exists but is empty or has en error, return that.
pub async fn allocate_vlan_id(
    api: &Api,
    txn: &mut PgConnection,
    owner_id: &str,
) -> Result<i16, CarbideError> {
    match db::resource_pool::allocate(
        &api.common_pools.ethernet.pool_vlan_id,
        txn,
        model::resource_pool::OwnerType::NetworkSegment,
        owner_id,
    )
    .await
    {
        Ok(val) => Ok(val),
        Err(ResourcePoolDatabaseError::ResourcePool(
            model::resource_pool::ResourcePoolError::Empty,
        )) => {
            tracing::error!(
                owner_id,
                pool = "vlan_id",
                "Pool exhausted, cannot allocate"
            );
            Err(CarbideError::ResourceExhausted("pool vlan_id".to_string()))
        }
        Err(err) => {
            tracing::error!(owner_id, error = %err, pool = "vlan_id", "Error allocating from resource pool");
            Err(err.into())
        }
    }
}
