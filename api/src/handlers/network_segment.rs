/*
 * SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use ::rpc::forge as rpc;
use sqlx::{Postgres, Transaction};
use tonic::{Request, Response, Status};

use crate::api::{log_request_data, Api};
use crate::db::network_segment::NetworkSegment;
use crate::db::network_segment::NetworkSegmentSearchConfig;
use crate::db::network_segment::NetworkSegmentType;
use crate::db::network_segment::NewNetworkSegment;
use crate::db::network_segment::{NetworkSegmentId, NetworkSegmentIdKeyedObjectFilter};
use crate::db::DatabaseError;
use crate::model::network_segment::NetworkSegmentControllerState;
use crate::model::RpcDataConversionError;
use crate::CarbideError;

pub(crate) async fn find_ids(
    api: &Api,
    request: Request<rpc::NetworkSegmentSearchFilter>,
) -> Result<Response<rpc::NetworkSegmentIdList>, Status> {
    log_request_data(&request);

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin network_segment::find_ids",
            e,
        ))
    })?;

    let filter: rpc::NetworkSegmentSearchFilter = request.into_inner();

    let segment_ids = NetworkSegment::find_ids(&mut txn, filter).await?;

    Ok(Response::new(rpc::NetworkSegmentIdList {
        network_segments_ids: segment_ids
            .into_iter()
            .map(|id| ::rpc::common::Uuid {
                value: id.to_string(),
            })
            .collect(),
    }))
}

pub(crate) async fn find_by_ids(
    api: &Api,
    request: Request<rpc::NetworkSegmentsByIdsRequest>,
) -> Result<Response<rpc::NetworkSegmentList>, Status> {
    log_request_data(&request);
    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin network_segment::find_by_ids",
            e,
        ))
    })?;

    let rpc::NetworkSegmentsByIdsRequest {
        network_segments_ids,
        include_history,
        include_num_free_ips,
        ..
    } = request.into_inner();

    let network_segments_ids: Result<Vec<NetworkSegmentId>, CarbideError> = network_segments_ids
        .iter()
        .map(|id| {
            NetworkSegmentId::try_from(id).map_err(|_| {
                CarbideError::from(RpcDataConversionError::InvalidNetworkSegmentId(
                    id.value.to_string(),
                ))
            })
        })
        .collect();
    let network_segments_ids = network_segments_ids?;

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

    let segments = NetworkSegment::find(
        &mut txn,
        NetworkSegmentIdKeyedObjectFilter::List(&network_segments_ids),
        NetworkSegmentSearchConfig {
            include_history,
            include_num_free_ips,
        },
    )
    .await
    .map_err(CarbideError::from)?;

    let mut result = Vec::with_capacity(segments.len());
    for seg in segments {
        result.push(seg.try_into()?);
    }
    Ok(Response::new(rpc::NetworkSegmentList {
        network_segments: result,
    }))
}

// DEPRECATED: use find_ids and find_by_ids instead
pub(crate) async fn find(
    api: &Api,
    request: Request<rpc::NetworkSegmentQuery>,
) -> Result<Response<rpc::NetworkSegmentList>, Status> {
    crate::api::log_request_data(&request);

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin find_network_segments",
            e,
        ))
    })?;

    let rpc::NetworkSegmentQuery {
        id, search_config, ..
    } = request.into_inner();

    let segment_id_filter = match id {
        Some(id) => match NetworkSegmentId::try_from(id) {
            Ok(uuid) => NetworkSegmentIdKeyedObjectFilter::One(uuid),
            Err(err) => {
                return Err(Status::invalid_argument(format!(
                    "Supplied invalid UUID: {}",
                    err
                )));
            }
        },
        None => NetworkSegmentIdKeyedObjectFilter::All,
    };

    let search_config = search_config
        .map(NetworkSegmentSearchConfig::from)
        .unwrap_or(NetworkSegmentSearchConfig::default());
    let results = NetworkSegment::find(&mut txn, segment_id_filter, search_config)
        .await
        .map_err(CarbideError::from)?;
    let mut network_segments = Vec::with_capacity(results.len());

    for result in results {
        network_segments.push(result.try_into()?);
    }
    Ok(Response::new(rpc::NetworkSegmentList { network_segments }))
}

pub(crate) async fn create(
    api: &Api,
    request: Request<rpc::NetworkSegmentCreationRequest>,
) -> Result<Response<rpc::NetworkSegment>, Status> {
    crate::api::log_request_data(&request);

    let request = request.into_inner();

    let new_network_segment = NewNetworkSegment::try_from(request)?;

    if new_network_segment.segment_type == NetworkSegmentType::Tenant {
        if let Some(site_fabric_prefixes) = api.eth_data.site_fabric_prefixes.as_ref() {
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
    }

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin create_network_segment",
            e,
        ))
    })?;
    let network_segment = save(api, &mut txn, new_network_segment, false).await?;

    let response = Ok(Response::new(network_segment.try_into()?));
    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit create_network_segment",
            e,
        ))
    })?;
    response
}

pub(crate) async fn delete(
    api: &Api,
    request: Request<rpc::NetworkSegmentDeletionRequest>,
) -> Result<Response<rpc::NetworkSegmentDeletionResult>, Status> {
    crate::api::log_request_data(&request);

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin delete_network_segment",
            e,
        ))
    })?;

    let rpc::NetworkSegmentDeletionRequest { id, .. } = request.into_inner();

    let segment_id = NetworkSegmentId::from_grpc(id)?;

    let mut segments = NetworkSegment::find(
        &mut txn,
        NetworkSegmentIdKeyedObjectFilter::One(segment_id),
        NetworkSegmentSearchConfig::default(),
    )
    .await
    .map_err(CarbideError::from)?;

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

    let response = Ok(segment
        .mark_as_deleted(&mut txn)
        .await
        .map(|_| rpc::NetworkSegmentDeletionResult {})
        .map(Response::new)?);

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit delete_network_segment",
            e,
        ))
    })?;

    response
}

pub(crate) async fn for_vpc(
    api: &Api,
    request: Request<rpc::VpcSearchQuery>,
) -> Result<Response<rpc::NetworkSegmentList>, Status> {
    crate::api::log_request_data(&request);

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin network_segments_for_vpc",
            e,
        ))
    })?;

    let rpc::VpcSearchQuery { id, .. } = request.into_inner();

    let uuid = match id {
        Some(id) => match uuid::Uuid::try_from(id) {
            Ok(uuid) => uuid,
            Err(_) => {
                return Err(CarbideError::MissingArgument("id").into());
            }
        },
        None => {
            return Err(CarbideError::InvalidArgument("id".to_string()).into());
        }
    };

    let results = NetworkSegment::for_vpc(&mut txn, uuid)
        .await
        .map_err(CarbideError::from)?;

    let mut network_segments = Vec::with_capacity(results.len());

    for result in results {
        network_segments.push(result.try_into()?);
    }

    Ok(Response::new(rpc::NetworkSegmentList { network_segments }))
}

// Called by db_init::create_initial_networks
pub(crate) async fn save(
    api: &Api,
    txn: &mut Transaction<'_, Postgres>,
    mut ns: NewNetworkSegment,
    set_to_ready: bool,
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
    let network_segment = match ns.persist(txn, initial_state).await {
        Ok(segment) => segment,
        Err(DatabaseError {
            source: sqlx::Error::Database(e),
            ..
        }) if e.constraint() == Some("network_prefixes_prefix_excl") => {
            return Err(CarbideError::NetworkSegmentPrefixOverlap);
        }
        Err(err) => {
            return Err(err.into());
        }
    };
    Ok(network_segment)
}

/// Allocate a value from the vni resource pool.
///
/// If the pool exists but is empty or has en error, return that.
async fn allocate_vni(
    api: &Api,
    txn: &mut Transaction<'_, Postgres>,
    owner_id: &str,
) -> Result<i32, CarbideError> {
    match api
        .common_pools
        .ethernet
        .pool_vni
        .allocate(
            txn,
            crate::resource_pool::OwnerType::NetworkSegment,
            owner_id,
        )
        .await
    {
        Ok(val) => Ok(val),
        Err(crate::resource_pool::ResourcePoolError::Empty) => {
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
async fn allocate_vlan_id(
    api: &Api,
    txn: &mut Transaction<'_, Postgres>,
    owner_id: &str,
) -> Result<i16, CarbideError> {
    match api
        .common_pools
        .ethernet
        .pool_vlan_id
        .allocate(
            txn,
            crate::resource_pool::OwnerType::NetworkSegment,
            owner_id,
        )
        .await
    {
        Ok(val) => Ok(val),
        Err(crate::resource_pool::ResourcePoolError::Empty) => {
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
