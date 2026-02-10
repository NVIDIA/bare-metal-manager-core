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
use ::rpc::errors::RpcDataConversionError;
use ::rpc::forge as rpc;
use carbide_uuid::network_security_group::NetworkSecurityGroupId;
use carbide_uuid::vpc::VpcId;
use db::resource_pool::ResourcePoolDatabaseError;
use db::vpc::{self};
use db::{self, ObjectColumnFilter, network_security_group};
use model::resource_pool;
use model::tenant::{InvalidTenantOrg, RoutingProfileType};
use model::vpc::{NewVpc, UpdateVpc, UpdateVpcVirtualization};
use sqlx::PgConnection;
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

    let mut txn = api.txn_begin().await?;

    // Grab the tenant details and a row-lock if found so we can coordinate around the tenant record.
    // If we're still allowing VPC creation for tenant org IDs that don't actually exist
    // in the DB, we're limited with the coordinating we can do, but it also doesn't matter
    // because those VPCs are going to default to external and force us to deal with the missing,
    // tenant records.
    let tenant =
        db::tenant::find(&vpc_creation_request.tenant_organization_id, true, &mut txn).await?;

    // A lot of tests seem to still allow tenant IDs for tenants that don't
    // exist.  We should audit and see if there are still sites with missing tenants
    // if we expect Carbide-core to have knowledge of tenants.  Otherwise, this would just go away
    // when we _remove_ any expectation of tenant knowledge from Carbide-core, and the details we
    // need from tenant would just come in from the VPC creation request.
    if tenant.is_none() {
        tracing::warn!(
            tenant_organization_id = vpc_creation_request.tenant_organization_id.clone(),
            "Database record for tenant ID in VPC creation request not found"
        );
    };

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

    let mut new_vpc = NewVpc::try_from(request.into_inner())?;

    // Default to the tenant's routing-profile.
    // If we choose to allow the gRPC consumer to control routing profiles
    // at the VPC-level, this would be the spot after updating the
    // VpcCreationRequest proto.
    new_vpc.routing_profile_type = tenant.and_then(|t| t.routing_profile_type);

    let mut vpc = db::vpc::persist(new_vpc, &mut txn).await?;

    vpc.vni = Some(
        allocate_vpc_vni(
            api,
            &mut txn,
            &vpc.id.to_string(),
            vpc.routing_profile_type.clone(),
        )
        .await?,
    );

    // We will allocate an dpa_vni for this VPC when the first instance with DPA NICs gets added
    // to this VPC.
    db::vpc::set_vni(&mut txn, vpc.id, vpc.vni.unwrap()).await?;

    let rpc_out: rpc::Vpc = vpc.into();

    txn.commit().await?;

    Ok(Response::new(rpc_out))
}

pub(crate) async fn update(
    api: &Api,
    request: Request<rpc::VpcUpdateRequest>,
) -> Result<Response<rpc::VpcUpdateResult>, Status> {
    log_request_data(&request);

    let vpc_update_request = request.get_ref();

    let mut txn = api.txn_begin().await?;

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

    // Note: Because VNI allocation happens on creation and depends on the routing profile type,
    // we can't allow VPCs to change routing profiles unless we also release and re-allocate their VNIs.
    // It's better to keep the property immutable.

    let vpc = db::vpc::update(&UpdateVpc::try_from(request.into_inner())?, &mut txn).await?;

    txn.commit().await?;

    Ok(Response::new(rpc::VpcUpdateResult {
        vpc: Some(vpc.into()),
    }))
}

pub(crate) async fn update_virtualization(
    api: &Api,
    request: Request<rpc::VpcUpdateVirtualizationRequest>,
) -> Result<Response<rpc::VpcUpdateVirtualizationResult>, Status> {
    log_request_data(&request);

    let mut txn = api.txn_begin().await?;

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

    txn.commit().await?;

    Ok(Response::new(rpc::VpcUpdateVirtualizationResult {}))
}

pub(crate) async fn delete(
    api: &Api,
    request: Request<rpc::VpcDeletionRequest>,
) -> Result<Response<rpc::VpcDeletionResult>, Status> {
    log_request_data(&request);

    let mut txn = api.txn_begin().await?;

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
        // We can just keep deriving int/ext from the routing profile
        // because a VPC is not allowed to change its profile after
        // creation.
        let internal = api.runtime_config.fnn.is_none()
            || api
                .runtime_config
                .fnn
                .as_ref()
                .map(|f| {
                    let Some(profile_type) = vpc.routing_profile_type.map(|t| t.to_string()) else {
                        return Err(CarbideError::MissingArgument("routing_profile_type"));
                    };

                    let Some(profile) = f.routing_profiles.get(&profile_type) else {
                        return Err(CarbideError::NotFoundError {
                            kind: "routing_profile_type",
                            id: profile_type,
                        });
                    };

                    Ok(profile.internal)
                })
                .transpose()?
                .unwrap_or_default();

        if internal {
            db::resource_pool::release(&api.common_pools.ethernet.pool_vpc_vni, &mut txn, vni)
                .await
                .map_err(CarbideError::from)?;
        } else {
            db::resource_pool::release(
                &api.common_pools.ethernet.pool_external_vpc_vni,
                &mut txn,
                vni,
            )
            .await
            .map_err(CarbideError::from)?;
        }
    }

    if let Some(dpa_vni) = vpc.dpa_vni {
        db::resource_pool::release(&api.common_pools.dpa.pool_dpa_vni, &mut txn, dpa_vni)
            .await
            .map_err(CarbideError::from)?;
    }

    // Delete associated VPC peerings
    db::vpc_peering::delete_by_vpc_id(&mut txn, vpc_id).await?;

    txn.commit().await?;

    Ok(Response::new(rpc::VpcDeletionResult {}))
}

pub(crate) async fn find_ids(
    api: &Api,
    request: Request<rpc::VpcSearchFilter>,
) -> Result<Response<rpc::VpcIdList>, Status> {
    log_request_data(&request);

    let filter: rpc::VpcSearchFilter = request.into_inner();

    let vpc_ids = db::vpc::find_ids(&api.database_connection, filter).await?;

    Ok(Response::new(rpc::VpcIdList { vpc_ids }))
}

pub(crate) async fn find_by_ids(
    api: &Api,
    request: Request<rpc::VpcsByIdsRequest>,
) -> Result<Response<rpc::VpcList>, Status> {
    log_request_data(&request);

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

    let db_vpcs = db::vpc::find_by(
        &api.database_connection,
        ObjectColumnFilter::List(vpc::IdColumn, &vpc_ids),
    )
    .await;

    let result = db_vpcs
        .map(|vpc| rpc::VpcList {
            vpcs: vpc.into_iter().map(rpc::Vpc::from).collect(),
        })
        .map(Response::new)?;

    Ok(result)
}

/// Allocate a value from the vpc vni resource pool.
///
/// If the pool exists but is empty or has en error, return that.
async fn allocate_vpc_vni(
    api: &Api,
    txn: &mut PgConnection,
    owner_id: &str,
    routing_profile_type: Option<RoutingProfileType>,
) -> Result<i32, CarbideError> {
    // If FNN is not configured, then there is no distinction between internal
    // and external tenants: they're all internal.  This matches how things are
    // deployed today.
    let internal = api.runtime_config.fnn.is_none()
        || api
            .runtime_config
            .fnn
            .as_ref()
            .map(|f| {
                let Some(profile_type) = routing_profile_type.map(|t| t.to_string()) else {
                    return Err(CarbideError::MissingArgument("routing_profile_type"));
                };

                let Some(profile) = f.routing_profiles.get(&profile_type) else {
                    return Err(CarbideError::NotFoundError {
                        kind: "routing_profile_type",
                        id: profile_type,
                    });
                };

                Ok(profile.internal)
            })
            .transpose()?
            .unwrap_or_default();

    let source_pool = if internal {
        &api.common_pools.ethernet.pool_vpc_vni
    } else {
        &api.common_pools.ethernet.pool_external_vpc_vni
    };

    match db::resource_pool::allocate(source_pool, txn, resource_pool::OwnerType::Vpc, owner_id)
        .await
    {
        Ok(val) => Ok(val),
        Err(ResourcePoolDatabaseError::ResourcePool(resource_pool::ResourcePoolError::Empty)) => {
            tracing::error!(
                owner_id,
                pool = source_pool.name(),
                "Pool exhausted, cannot allocate"
            );
            Err(CarbideError::ResourceExhausted(format!(
                "pool {}",
                source_pool.name
            )))
        }
        Err(err) => {
            tracing::error!(owner_id, error = %err, pool = source_pool.name, "Error allocating from resource pool");
            Err(err.into())
        }
    }
}
