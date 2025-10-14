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

use ::rpc::errors::RpcDataConversionError;
use ::rpc::forge as rpc;
use db::vpc::{self};
use db::{self, DatabaseError, ObjectColumnFilter, network_security_group};
use forge_uuid::network_security_group::NetworkSecurityGroupId;
use forge_uuid::vpc::VpcId;
use model::tenant::InvalidTenantOrg;
use model::vpc::{NewVpc, UpdateVpc, UpdateVpcVirtualization};
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::{Api, log_request_data};

pub(crate) async fn create(
    api: &Api,
    request: Request<rpc::VpcCreationRequest>,
) -> Result<Response<rpc::Vpc>, Status> {
    log_request_data(&request);
    let vpc_creation_request = request.get_ref();

    if let Some(metadata) = &vpc_creation_request.metadata
        && !vpc_creation_request.name.is_empty()
        && metadata.name != vpc_creation_request.name
    {
        return Err(CarbideError::InvalidArgument(
            "VPC name must be specified under metadata only.".to_string(),
        )
        .into());
    }

    const DB_TXN_NAME: &str = "create_vpc";

    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| DatabaseError::txn_begin(DB_TXN_NAME, e))?;

    if let Some(ref nsg_id) = vpc_creation_request.network_security_group_id {
        let id = nsg_id.parse::<NetworkSecurityGroupId>().map_err(|e| {
            CarbideError::from(RpcDataConversionError::InvalidNetworkSecurityGroupId(
                e.value(),
            ))
        })?;

        // Query to check the validity of the NSG ID but to also grab
        // a row-level lock on it if it exists.
        if network_security_group::find_by_ids(
            &mut txn,
            std::slice::from_ref(&id),
            Some(
                &vpc_creation_request
                    .tenant_organization_id
                    .parse()
                    .map_err(|e: InvalidTenantOrg| {
                        CarbideError::from(RpcDataConversionError::InvalidTenantOrg(e.to_string()))
                    })?,
            ),
            true,
        )
        .await?
        .pop()
        .is_none()
        {
            return Err(CarbideError::FailedPrecondition(format!(
                "NetworkSecurityGroup `{}` does not exist or is not owned by Tenant `{}`",
                id, vpc_creation_request.tenant_organization_id,
            ))
            .into());
        }
    }

    let mut vpc = db::vpc::persist(NewVpc::try_from(request.into_inner())?, &mut txn).await?;

    vpc.vni = Some(api.allocate_vpc_vni(&mut txn, &vpc.id.to_string()).await?);

    // We will allocate an dpa_vni for this VPC when the first instance with DPA NICs gets added
    // to this VPC.
    db::vpc::set_vni(&mut txn, vpc.id, vpc.vni.unwrap()).await?;

    let rpc_out: rpc::Vpc = vpc.into();

    txn.commit()
        .await
        .map_err(|e| DatabaseError::txn_commit(DB_TXN_NAME, e))?;

    Ok(Response::new(rpc_out))
}

pub(crate) async fn update(
    api: &Api,
    request: Request<rpc::VpcUpdateRequest>,
) -> Result<Response<rpc::VpcUpdateResult>, Status> {
    log_request_data(&request);

    let vpc_update_request = request.get_ref();

    const DB_TXN_NAME: &str = "update_vpc";

    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| DatabaseError::txn_begin(DB_TXN_NAME, e))?;

    // If a security group is applied to the VPC, we need to do some validation.
    if let Some(ref nsg_id) = vpc_update_request.network_security_group_id {
        let id = nsg_id.parse::<NetworkSecurityGroupId>().map_err(|e| {
            CarbideError::from(RpcDataConversionError::InvalidNetworkSecurityGroupId(
                e.value(),
            ))
        })?;

        let vpc_id = vpc_update_request
            .id
            .ok_or_else(|| CarbideError::InvalidArgument("VPC ID is required".to_string()))?;

        // Query for the VPC because we need to do
        // some validation against the request.
        let Some(vpc) = db::vpc::find_by(&mut txn, ObjectColumnFilter::One(vpc::IdColumn, &vpc_id))
            .await?
            .pop()
        else {
            return Err(CarbideError::NotFoundError {
                kind: "Vpc",
                id: vpc_id.to_string(),
            }
            .into());
        };

        // Query to check the validity of the NSG ID but to also grab
        // a row-level lock on it if it exists.
        if network_security_group::find_by_ids(
            &mut txn,
            std::slice::from_ref(&id),
            Some(
                &vpc.tenant_organization_id
                    .parse()
                    .map_err(|e: InvalidTenantOrg| {
                        CarbideError::from(RpcDataConversionError::InvalidTenantOrg(e.to_string()))
                    })?,
            ),
            true,
        )
        .await?
        .pop()
        .is_none()
        {
            return Err(CarbideError::FailedPrecondition(format!(
                "NetworkSecurityGroup `{}` does not exist or is not owned by Tenant `{}`",
                id, vpc.tenant_organization_id
            ))
            .into());
        }
    }

    let vpc = db::vpc::update(&UpdateVpc::try_from(request.into_inner())?, &mut txn).await?;

    txn.commit()
        .await
        .map_err(|e| DatabaseError::txn_commit(DB_TXN_NAME, e))?;

    Ok(Response::new(rpc::VpcUpdateResult {
        vpc: Some(vpc.into()),
    }))
}

pub(crate) async fn update_virtualization(
    api: &Api,
    request: Request<rpc::VpcUpdateVirtualizationRequest>,
) -> Result<Response<rpc::VpcUpdateVirtualizationResult>, Status> {
    log_request_data(&request);

    const DB_TXN_NAME: &str = "update_vpc";

    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| DatabaseError::txn_begin(DB_TXN_NAME, e))?;

    let updater = UpdateVpcVirtualization::try_from(request.into_inner())?;

    let instances = db::instance::find_ids(
        &mut txn,
        rpc::InstanceSearchFilter {
            label: None,
            tenant_org_id: None,
            vpc_id: Some(updater.id.to_string()),
            instance_type_id: None,
        },
    )
    .await?;

    if !instances.is_empty() {
        return Err(CarbideError::internal(format!(
            "cannot modify VPC virtualization type in VPC with existing instances (found: {})",
            instances.len()
        ))
        .into());
    }
    db::vpc::update_virtualization(&updater, &mut txn).await?;

    txn.commit()
        .await
        .map_err(|e| DatabaseError::txn_commit(DB_TXN_NAME, e))?;

    Ok(Response::new(rpc::VpcUpdateVirtualizationResult {}))
}

pub(crate) async fn delete(
    api: &Api,
    request: Request<rpc::VpcDeletionRequest>,
) -> Result<Response<rpc::VpcDeletionResult>, Status> {
    log_request_data(&request);

    const DB_TXN_NAME: &str = "delete_vpc";

    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| DatabaseError::txn_begin(DB_TXN_NAME, e))?;

    // TODO: This needs to validate that nothing references the VPC anymore
    // (like NetworkSegments)
    let vpc_id: VpcId = request
        .into_inner()
        .id
        .ok_or(CarbideError::MissingArgument("id"))?;

    let vpc = match db::vpc::try_delete(&mut txn, vpc_id).await? {
        Some(vpc) => vpc,
        None => {
            // VPC didn't exist or was deleted in the past. We are not allowed
            // to free the VNI again
            return Err(CarbideError::NotFoundError {
                kind: "vpc",
                id: vpc_id.to_string(),
            }
            .into());
        }
    };

    if let Some(vni) = vpc.vni {
        db::resource_pool::release(&api.common_pools.ethernet.pool_vpc_vni, &mut txn, vni)
            .await
            .map_err(CarbideError::from)?;
    }

    if let Some(dpa_vni) = vpc.dpa_vni {
        db::resource_pool::release(&api.common_pools.dpa.pool_dpa_vni, &mut txn, dpa_vni)
            .await
            .map_err(CarbideError::from)?;
    }

    // Delete associated VPC peerings
    db::vpc_peering::delete_by_vpc_id(&mut txn, vpc_id).await?;

    txn.commit()
        .await
        .map_err(|e| DatabaseError::txn_commit(DB_TXN_NAME, e))?;

    Ok(Response::new(rpc::VpcDeletionResult {}))
}

pub(crate) async fn find_ids(
    api: &Api,
    request: Request<rpc::VpcSearchFilter>,
) -> Result<Response<rpc::VpcIdList>, Status> {
    log_request_data(&request);

    const DB_TXN_NAME: &str = "vpc::find_ids";

    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| DatabaseError::txn_begin(DB_TXN_NAME, e))?;

    let filter: rpc::VpcSearchFilter = request.into_inner();

    let vpc_ids = db::vpc::find_ids(&mut txn, filter).await?;

    Ok(Response::new(rpc::VpcIdList { vpc_ids }))
}

pub(crate) async fn find_by_ids(
    api: &Api,
    request: Request<rpc::VpcsByIdsRequest>,
) -> Result<Response<rpc::VpcList>, Status> {
    log_request_data(&request);
    const DB_TXN_NAME: &str = "vpc::find_by_ids";

    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| DatabaseError::txn_begin(DB_TXN_NAME, e))?;

    let vpc_ids = request.into_inner().vpc_ids;

    let max_find_by_ids = api.runtime_config.max_find_by_ids as usize;
    if vpc_ids.len() > max_find_by_ids {
        return Err(CarbideError::InvalidArgument(format!(
            "no more than {max_find_by_ids} IDs can be accepted"
        ))
        .into());
    } else if vpc_ids.is_empty() {
        return Err(
            CarbideError::InvalidArgument("at least one ID must be provided".to_string()).into(),
        );
    }

    let db_vpcs =
        db::vpc::find_by(&mut txn, ObjectColumnFilter::List(vpc::IdColumn, &vpc_ids)).await;

    let result = db_vpcs
        .map(|vpc| rpc::VpcList {
            vpcs: vpc.into_iter().map(rpc::Vpc::from).collect(),
        })
        .map(Response::new)?;

    Ok(result)
}

// DEPRECATED: use find_ids and find_by_ids instead
pub(crate) async fn find(
    api: &Api,
    request: Request<rpc::VpcSearchQuery>,
) -> Result<Response<rpc::VpcList>, Status> {
    log_request_data(&request);

    const DB_TXN_NAME: &str = "find_vpcs";

    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| DatabaseError::txn_begin(DB_TXN_NAME, e))?;

    let rpc::VpcSearchQuery { id, name, .. } = request.into_inner();

    let vpcs = match (id, name) {
        (Some(id), _) => {
            db::vpc::find_by(&mut txn, ObjectColumnFilter::One(vpc::IdColumn, &id)).await
        }
        (None, Some(name)) => db::vpc::find_by_name(&mut txn, &name).await,
        (None, None) => db::vpc::find_by(&mut txn, ObjectColumnFilter::<vpc::IdColumn>::All).await,
    };

    let result = vpcs
        .map(|vpc| rpc::VpcList {
            vpcs: vpc.into_iter().map(rpc::Vpc::from).collect(),
        })
        .map(Response::new)?;

    Ok(result)
}
