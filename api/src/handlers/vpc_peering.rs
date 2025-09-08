/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use crate::cfg::file::VpcPeeringPolicy;
use crate::db::vpc::Vpc;
use crate::db::{ObjectColumnFilter, vpc_peering as db};
use crate::{
    CarbideError,
    api::{Api, log_request_data},
    db::DatabaseError,
};
use ::rpc::forge as rpc;
use ::rpc::uuid::vpc::VpcId;
use forge_network::virtualization::VpcVirtualizationType;
use tonic::{Request, Response, Status};

pub async fn create(
    api: &Api,
    request: Request<rpc::VpcPeeringCreationRequest>,
) -> Result<Response<rpc::VpcPeering>, Status> {
    log_request_data(&request);

    let rpc::VpcPeeringCreationRequest {
        vpc_id,
        peer_vpc_id,
    } = request.into_inner();

    let vpc_id = vpc_id
        .ok_or_else(|| CarbideError::MissingArgument("vpc_id cannot be null"))
        .and_then(|id| {
            VpcId::try_from(id).map_err(|_| {
                CarbideError::InvalidArgument("Fail to convert vpc_id into uuid".into())
            })
        })?;

    let peer_vpc_id = peer_vpc_id
        .ok_or_else(|| CarbideError::MissingArgument("peer_vpc_id cannot be null"))
        .and_then(|id| {
            VpcId::try_from(id).map_err(|_| {
                CarbideError::InvalidArgument("Fail to convert peer_vpc_id into uuid".into())
            })
        })?;

    const DB_TXN_NAME: &str = "vpc_peering::create";

    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| DatabaseError::txn_begin(DB_TXN_NAME, e))?;

    // Check this VPC peering is permitted under current site vpc_peering_policy
    match api.runtime_config.vpc_peering_policy {
        None | Some(VpcPeeringPolicy::None) => {
            return Err(CarbideError::internal("VPC Peering feature disabled.".to_string()).into());
        }
        Some(VpcPeeringPolicy::Exclusive) => {
            let vpcs1 = Vpc::find_by(
                &mut txn,
                ObjectColumnFilter::One(crate::db::vpc::IdColumn, &vpc_id),
            )
            .await?;
            let vpc1 = vpcs1.first().ok_or_else(|| CarbideError::NotFoundError {
                kind: "VPC",
                id: vpc_id.clone().to_string(),
            })?;
            let vpcs2 = Vpc::find_by(
                &mut txn,
                ObjectColumnFilter::One(crate::db::vpc::IdColumn, &peer_vpc_id),
            )
            .await?;
            let vpc2 = vpcs2.first().ok_or_else(|| CarbideError::NotFoundError {
                kind: "VPC",
                id: peer_vpc_id.clone().to_string(),
            })?;
            // If nvue_enabled, then ETHERNET_VIRTUALIZER = ETHERNET_VIRTUALIZER_WITH_NVUE and
            // only type of peering not allowed is between Fnn <-> ETV/ETV_WITH_NVUE
            if vpc1.network_virtualization_type != vpc2.network_virtualization_type
                && (!api.runtime_config.nvue_enabled
                    || (vpc1.network_virtualization_type == VpcVirtualizationType::Fnn
                        || vpc2.network_virtualization_type == VpcVirtualizationType::Fnn))
            {
                return Err(CarbideError::internal(
                            "VPC peering between VPCs of different network virtualization type not allowed.".to_string(),
                        ).into());
            }
        }
        Some(VpcPeeringPolicy::Mixed) => {
            // Any combination of network virtualization types allowed
        }
    }

    let vpc_peering = db::VpcPeering::create(&mut txn, vpc_id, peer_vpc_id).await?;

    txn.commit()
        .await
        .map_err(|e| DatabaseError::txn_commit(DB_TXN_NAME, e))?;

    Ok(tonic::Response::new(vpc_peering.into()))
}

pub async fn find_ids(
    api: &Api,
    request: Request<rpc::VpcPeeringSearchFilter>,
) -> Result<Response<rpc::VpcPeeringIdList>, Status> {
    log_request_data(&request);

    let rpc::VpcPeeringSearchFilter { vpc_id } = request.into_inner();

    let vpc_id = match vpc_id {
        Some(id) => Some(VpcId::try_from(id).map_err(|_| {
            CarbideError::InvalidArgument("Fail to convert vpc_id to type VpcId".into())
        })?),
        None => None,
    };

    const DB_TXN_NAME: &str = "vpc_peering::find_ids";

    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| DatabaseError::txn_begin(DB_TXN_NAME, e))?;

    let vpc_peering_ids = db::VpcPeering::find_ids(&mut txn, vpc_id).await?;

    txn.commit()
        .await
        .map_err(|e| DatabaseError::txn_commit(DB_TXN_NAME, e))?;

    let vpc_peering_ids = vpc_peering_ids
        .into_iter()
        .map(|id| ::rpc::common::Uuid {
            value: id.to_string(),
        })
        .collect();

    Ok(tonic::Response::new(rpc::VpcPeeringIdList {
        vpc_peering_ids,
    }))
}

pub async fn find_by_ids(
    api: &Api,
    request: Request<rpc::VpcPeeringsByIdsRequest>,
) -> Result<Response<rpc::VpcPeeringList>, Status> {
    log_request_data(&request);

    let rpc::VpcPeeringsByIdsRequest { vpc_peering_ids } = request.into_inner();

    let vpc_peering_ids: Result<Vec<uuid::Uuid>, CarbideError> = vpc_peering_ids
        .into_iter()
        .map(|id| {
            uuid::Uuid::parse_str(&id.value).map_err(|_| {
                CarbideError::InvalidArgument("Invalid UUID in vpc_peering_ids".into())
            })
        })
        .collect();
    let vpc_peering_ids = vpc_peering_ids?;

    const DB_TXN_NAME: &str = "vpc_peering::find_by_ids";

    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| DatabaseError::txn_begin(DB_TXN_NAME, e))?;

    let vpc_peerings = db::VpcPeering::find_by_ids(&mut txn, vpc_peering_ids).await?;

    txn.commit()
        .await
        .map_err(|e| DatabaseError::txn_commit(DB_TXN_NAME, e))?;

    let vpc_peerings = vpc_peerings.into_iter().map(Into::into).collect();

    Ok(tonic::Response::new(rpc::VpcPeeringList { vpc_peerings }))
}

pub async fn delete(
    api: &Api,
    request: Request<rpc::VpcPeeringDeletionRequest>,
) -> Result<Response<rpc::VpcPeeringDeletionResult>, Status> {
    log_request_data(&request);

    let rpc::VpcPeeringDeletionRequest { id } = request.into_inner();

    let id = id
        .ok_or_else(|| CarbideError::MissingArgument("id cannot be null"))
        .and_then(|id| {
            uuid::Uuid::try_from(id)
                .map_err(|_| CarbideError::InvalidArgument("Fail to convert id".into()))
        })?;

    const DB_TXN_NAME: &str = "vpc_peering::delete";

    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| DatabaseError::txn_begin(DB_TXN_NAME, e))?;

    let _ = db::VpcPeering::delete(&mut txn, id).await?;

    txn.commit()
        .await
        .map_err(|e| DatabaseError::txn_commit(DB_TXN_NAME, e))?;

    Ok(tonic::Response::new(rpc::VpcPeeringDeletionResult {}))
}
