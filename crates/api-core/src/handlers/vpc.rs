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
use ::rpc::network::vpc_virtualization_type_try_from_rpc;
use carbide_network::virtualization::{DEFAULT_NETWORK_VIRTUALIZATION_TYPE, VpcVirtualizationType};
use carbide_uuid::network_security_group::NetworkSecurityGroupId;
use carbide_uuid::vpc::VpcId;
use db::resource_pool::ResourcePoolDatabaseError;
use db::vpc::{self};
use db::{self, ObjectColumnFilter, network_security_group};
use model::resource_pool;
use model::tenant::{InvalidTenantOrg, Tenant};
use model::vpc::{
    NewVpc, UpdateVpc, UpdateVpcVirtualization, VpcStatus, VpcVirtualizationTypeCapabilities,
};
use sqlx::PgConnection;
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::{Api, log_request_data};
use crate::cfg::file::FnnConfig;

pub(crate) async fn create(
    api: &Api,
    request: Request<rpc::VpcCreationRequest>,
) -> Result<Response<rpc::Vpc>, Status> {
    log_request_data(&request);
    let vpc_creation_request = request.get_ref();

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
    // if we expect NICo-core to have knowledge of tenants.  Otherwise, this would just go away
    // when we _remove_ any expectation of tenant knowledge from NICo-core, and the details we
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

    // Resolve the virtualization type up front. Flat VPCs short-circuit
    // most of the FNN-flavored routing-profile validation below: Flat doesn't
    // have a NICo-managed data plane, so routing-profile semantics don't
    // apply. We still allocate a VNI and persist the VPC like any other type.
    let requested_virtualization_type = match vpc_creation_request.network_virtualization_type {
        None => DEFAULT_NETWORK_VIRTUALIZATION_TYPE,
        Some(v) => vpc_virtualization_type_try_from_rpc(v).map_err(CarbideError::from)?,
    };

    if vpc_creation_request.routing_profile_type.is_some() {
        requested_virtualization_type
            .ensure_supports_routing_profiles()
            .map_err(CarbideError::from)?;
    }

    let ResolvedVpcRouting {
        profile_type: requested_profile_type,
        internal,
    } = resolve_vpc_routing(
        requested_virtualization_type,
        vpc_creation_request.routing_profile_type.as_deref(),
        tenant.as_ref(),
        api.runtime_config.fnn.as_ref(),
        &vpc_creation_request.tenant_organization_id,
    )?;

    let mut new_vpc = NewVpc::try_from(request.into_inner())?;

    let vni = Some(
        allocate_vpc_vni(
            api,
            &mut txn,
            &new_vpc.id.to_string(),
            internal,
            new_vpc.vni,
        )
        .await?,
    );

    new_vpc.routing_profile_type = requested_profile_type;

    let vpc = db::vpc::persist(new_vpc, VpcStatus { vni }, &mut txn).await?;

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
                &vpc.config
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
                id, vpc.config.tenant_organization_id
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
        model::instance::InstanceSearchFilter {
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

    let vpcs = db::vpc::find_by_with_lock(
        txn.as_mut(),
        ObjectColumnFilter::One(db::vpc::IdColumn, &vpc_id),
        db::vpc::VpcRowLock::Mutation,
    )
    .await?;
    if vpcs.is_empty() {
        return Err(CarbideError::NotFoundError {
            kind: "vpc",
            id: vpc_id.to_string(),
        }
        .into());
    }

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

    if let Some(vni) = vpc.status.vni {
        // We can just keep deriving int/ext from the routing profile
        // because a VPC is not allowed to change its profile after
        // creation. VPC types that don't carry a routing profile
        // (ETV, Flat) land in the internal pool on create -- mirror
        // that here so the VNI is released back to the same pool.
        let internal = match (
            api.runtime_config.fnn.as_ref(),
            vpc.config.routing_profile_type,
        ) {
            (None, _) | (Some(_), None) => true,
            (Some(f), Some(profile_type)) => {
                let Some(profile) = f.routing_profiles.get(&profile_type) else {
                    return Err(CarbideError::NotFoundError {
                        kind: "routing_profile_type",
                        id: profile_type,
                    }
                    .into());
                };
                profile.internal
            }
        };

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

    let filter: model::vpc::VpcSearchFilter = request.into_inner().into();

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
    internal: bool,
    requested_vni: Option<i32>,
) -> Result<i32, CarbideError> {
    // If FNN is not configured, then there is no distinction between internal
    // and external tenants: they're all internal.  This matches how things are
    // deployed today.

    let source_pool = if internal {
        &api.common_pools.ethernet.pool_vpc_vni
    } else {
        &api.common_pools.ethernet.pool_external_vpc_vni
    };

    match db::resource_pool::allocate(
        source_pool,
        txn,
        resource_pool::OwnerType::Vpc,
        owner_id,
        requested_vni,
    )
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
        Err(ResourcePoolDatabaseError::Database(e)) if requested_vni.is_some() => Err(match *e {
            db::DatabaseError::FailedPrecondition(_s) => {
                tracing::error!(
                    owner_id,
                    pool = source_pool.name(),
                    requested_vni,
                    "invalid pool value requested, cannot allocate"
                );
                CarbideError::FailedPrecondition(format!(
                    "VNI `{}` cannot be requested or is already allocated",
                    requested_vni.unwrap_or_default()
                ))
            }
            e => e.into(),
        }),
        Err(err) => {
            tracing::error!(owner_id, error = %err, pool = source_pool.name, "Error allocating from resource pool");
            Err(err.into())
        }
    }
}

/// Resolution of routing-related state for a VPC at create time. The
/// `internal` flag isn't strictly part of the routing profile, but it
/// gets decided together with `profile_type` from the same inputs
/// (request + tenant + site FNN config), so we return both as one
/// value.
#[derive(Debug)]
pub(crate) struct ResolvedVpcRouting {
    /// The routing-profile-type name to persist on the VPC. `None`
    /// for VPC types without a NICo-managed data plane, or when
    /// neither the request nor the tenant supplies one.
    pub profile_type: Option<String>,

    /// Whether the VPC is "internal" -- drives VNI pool selection
    /// (`vpc-vni` internal pool vs `external-vpc-vni` external pool)
    /// and a couple of downstream behaviors.
    pub internal: bool,
}

impl Default for ResolvedVpcRouting {
    /// Default resolution for VPC types that don't accept a
    /// `routing_profile_type` field (Flat today). `profile_type` is
    /// `None` because there's nothing to resolve. `internal` carries
    /// the default value the VNI allocator should pool from -- it IS
    /// part of the routing-profile concept (every profile has an
    /// `internal: bool`), but in the no-profile case we pick a
    /// conservative default since the field still has to flow
    /// downstream to the VNI pool selector.
    ///
    /// TODO(chet): Consider switching callers to
    /// `Option<ResolvedVpcRouting>` so the no-profile case doesn't
    /// silently masquerade as "internal."
    fn default() -> Self {
        Self {
            profile_type: None,
            internal: true,
        }
    }
}

/// Resolves the routing-profile and `internal` flag for a VPC create
/// request from (1) the VPC's virtualization type's capabilities,
/// (2) the request's `routing_profile_type`, (3) the tenant's
/// `routing_profile_type`, and (4) the site's FNN config. Surfaces
/// any contradictions as [`CarbideError`].
///
/// This exists as a function so that resolution rules can be
/// more easily unit-tested directly, vs. as part of a wider
/// flow.
pub(crate) fn resolve_vpc_routing(
    virt_type: VpcVirtualizationType,
    requested_profile_type: Option<&str>,
    tenant: Option<&Tenant>,
    fnn_config: Option<&FnnConfig>,
    organization_id: &str,
) -> Result<ResolvedVpcRouting, CarbideError> {
    // Only VPC types that use routing profiles (FNN today) run the
    // full resolution. ETV and Flat short-circuit to the default --
    // no profile stored, `internal: true` so VNI allocation lands in
    // the internal pool. The REST API at
    // `infra-controller-rest/api/pkg/api/handler/vpc.go` rejects
    // `routingProfile` on non-FNN creates upstream; this short-circuit
    // is the defense-in-depth gate at the carbide-core layer.
    if !virt_type.supports_routing_profiles() {
        return Ok(ResolvedVpcRouting::default());
    }

    let tenant_profile_type = tenant.and_then(|t| t.routing_profile_type.as_deref());

    match (requested_profile_type, tenant_profile_type) {
        // No VPC routing profile requested and no tenant profile.
        // Falling back to a default. With FNN disabled, assume
        // internal (legacy/pre-FNN behavior); with FNN enabled,
        // external must be assumed.
        (None, None) => Ok(ResolvedVpcRouting {
            profile_type: None,
            internal: fnn_config.is_none(),
        }),

        // Request asks for a routing profile but no tenant context
        // exists to validate it against -- reject.
        (Some(_), None) => Err(CarbideError::FailedPrecondition(format!(
            "VPC routing-profile type requested but no tenant or routing profile-type found for organization id `{organization_id}`"
        ))),

        // Tenant has a routing profile; resolve the request against it.
        (request_profile_type, Some(tenant_profile_type)) => {
            match (fnn_config, request_profile_type) {
                // FNN disabled but the request named a profile -- reject.
                (None, Some(_)) => Err(CarbideError::FailedPrecondition(
                    "FNN configuration required to request routing-profile for VPCs".to_string(),
                )),

                // FNN disabled with no explicit request: inherit the
                // tenant's profile name; force `internal=true` (legacy
                // pre-FNN behavior).
                (None, None) => Ok(ResolvedVpcRouting {
                    profile_type: Some(tenant_profile_type.to_owned()),
                    internal: true,
                }),

                // FNN enabled with no explicit request: inherit the
                // tenant's profile name and its `internal` flag.
                (Some(fnn), None) => {
                    let tenant_profile =
                        fnn.routing_profiles
                            .get(tenant_profile_type)
                            .ok_or_else(|| CarbideError::NotFoundError {
                                kind: "routing_profile",
                                id: tenant_profile_type.to_owned(),
                            })?;
                    Ok(ResolvedVpcRouting {
                        profile_type: Some(tenant_profile_type.to_owned()),
                        internal: tenant_profile.internal,
                    })
                }

                // FNN enabled and the request named a profile: use the
                // request's profile, but check that its access tier
                // isn't broader than the tenant's. Higher tier value =
                // more restricted; lower = broader.
                (Some(fnn), Some(profile_type)) => {
                    let routing_profile =
                        fnn.routing_profiles.get(profile_type).ok_or_else(|| {
                            CarbideError::NotFoundError {
                                kind: "routing_profile",
                                id: profile_type.to_owned(),
                            }
                        })?;
                    let tenant_profile =
                        fnn.routing_profiles
                            .get(tenant_profile_type)
                            .ok_or_else(|| CarbideError::NotFoundError {
                                kind: "routing_profile",
                                id: tenant_profile_type.to_owned(),
                            })?;
                    if routing_profile.access_tier < tenant_profile.access_tier {
                        return Err(CarbideError::FailedPrecondition(
                            "requested VPC routing-profile access tier is broader than associated tenant routing-profile access tier"
                                .to_string(),
                        ));
                    }
                    Ok(ResolvedVpcRouting {
                        profile_type: Some(profile_type.to_owned()),
                        internal: routing_profile.internal,
                    })
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use config_version::ConfigVersion;
    use model::metadata::Metadata;

    use super::*;
    use crate::cfg::file::FnnRoutingProfileConfig;

    fn tenant_with_profile(profile: Option<&str>) -> Tenant {
        Tenant {
            organization_id: "test-org".parse().unwrap(),
            routing_profile_type: profile.map(|s| s.to_string()),
            metadata: Metadata::new_with_default_name(),
            version: ConfigVersion::initial(),
        }
    }

    fn fnn_with_profiles(profiles: &[(&str, FnnRoutingProfileConfig)]) -> FnnConfig {
        FnnConfig {
            admin_vpc: None,
            common_internal_route_target: None,
            additional_route_target_imports: vec![],
            routing_profiles: profiles
                .iter()
                .map(|(name, profile)| ((*name).to_string(), profile.clone()))
                .collect::<HashMap<_, _>>(),
            use_vpc_vrf_loopback: false,
        }
    }

    fn profile(internal: bool, access_tier: u32) -> FnnRoutingProfileConfig {
        FnnRoutingProfileConfig {
            internal,
            access_tier,
            ..Default::default()
        }
    }

    #[test]
    fn flat_short_circuits_regardless_of_inputs() {
        let resolved = resolve_vpc_routing(
            VpcVirtualizationType::Flat,
            Some("EXTERNAL"),
            Some(&tenant_with_profile(Some("INTERNAL"))),
            Some(&fnn_with_profiles(&[
                ("EXTERNAL", profile(false, 2)),
                ("INTERNAL", profile(true, 1)),
            ])),
            "test-org",
        )
        .expect("Flat must short-circuit cleanly");
        assert_eq!(resolved.profile_type, None);
        assert!(resolved.internal);
    }

    #[test]
    fn no_request_no_tenant_no_fnn_defaults_to_internal() {
        let resolved =
            resolve_vpc_routing(VpcVirtualizationType::Fnn, None, None, None, "test-org")
                .expect("no-request no-tenant no-fnn is the legacy pre-FNN default");
        assert_eq!(resolved.profile_type, None);
        assert!(
            resolved.internal,
            "FNN disabled means we default to internal"
        );
    }

    #[test]
    fn no_request_no_tenant_with_fnn_defaults_to_external() {
        let fnn = fnn_with_profiles(&[]);
        let resolved = resolve_vpc_routing(
            VpcVirtualizationType::Fnn,
            None,
            None,
            Some(&fnn),
            "test-org",
        )
        .expect("no-request no-tenant with-fnn must succeed");
        assert_eq!(resolved.profile_type, None);
        assert!(
            !resolved.internal,
            "FNN enabled means we default to external"
        );
    }

    #[test]
    fn request_but_no_tenant_is_rejected() {
        let err = resolve_vpc_routing(
            VpcVirtualizationType::Fnn,
            Some("EXTERNAL"),
            None,
            None,
            "test-org",
        )
        .expect_err("request without tenant must be rejected");
        assert!(matches!(err, CarbideError::FailedPrecondition(_)));
    }

    #[test]
    fn fnn_disabled_with_request_is_rejected() {
        let tenant = tenant_with_profile(Some("INTERNAL"));
        let err = resolve_vpc_routing(
            VpcVirtualizationType::Fnn,
            Some("EXTERNAL"),
            Some(&tenant),
            None,
            "test-org",
        )
        .expect_err("FNN-disabled + explicit request must be rejected");
        assert!(matches!(err, CarbideError::FailedPrecondition(_)));
    }

    #[test]
    fn fnn_disabled_no_request_inherits_tenant_profile() {
        let tenant = tenant_with_profile(Some("INTERNAL"));
        let resolved = resolve_vpc_routing(
            VpcVirtualizationType::Fnn,
            None,
            Some(&tenant),
            None,
            "test-org",
        )
        .expect("FNN-disabled + tenant profile must inherit");
        assert_eq!(resolved.profile_type.as_deref(), Some("INTERNAL"));
        assert!(
            resolved.internal,
            "legacy pre-FNN behavior forces internal=true"
        );
    }

    #[test]
    fn fnn_enabled_no_request_inherits_tenant_profile_internal_flag() {
        let tenant = tenant_with_profile(Some("EXTERNAL"));
        let fnn = fnn_with_profiles(&[("EXTERNAL", profile(false, 2))]);
        let resolved = resolve_vpc_routing(
            VpcVirtualizationType::Fnn,
            None,
            Some(&tenant),
            Some(&fnn),
            "test-org",
        )
        .expect("FNN-enabled + tenant profile must inherit name + internal flag");
        assert_eq!(resolved.profile_type.as_deref(), Some("EXTERNAL"));
        assert!(!resolved.internal);
    }

    #[test]
    fn fnn_enabled_request_overrides_when_access_tier_permits() {
        // tenant tier 0 (broad); request tier 2 (narrower) -- allowed
        let tenant = tenant_with_profile(Some("ADMIN"));
        let fnn =
            fnn_with_profiles(&[("ADMIN", profile(true, 0)), ("EXTERNAL", profile(false, 2))]);
        let resolved = resolve_vpc_routing(
            VpcVirtualizationType::Fnn,
            Some("EXTERNAL"),
            Some(&tenant),
            Some(&fnn),
            "test-org",
        )
        .expect("narrower request than tenant access tier must succeed");
        assert_eq!(resolved.profile_type.as_deref(), Some("EXTERNAL"));
        assert!(!resolved.internal);
    }

    #[test]
    fn fnn_enabled_request_broader_than_tenant_is_rejected() {
        // tenant tier 2 (narrow); request tier 0 (broader) -- rejected
        let tenant = tenant_with_profile(Some("EXTERNAL"));
        let fnn =
            fnn_with_profiles(&[("EXTERNAL", profile(false, 2)), ("ADMIN", profile(true, 0))]);
        let err = resolve_vpc_routing(
            VpcVirtualizationType::Fnn,
            Some("ADMIN"),
            Some(&tenant),
            Some(&fnn),
            "test-org",
        )
        .expect_err("broader request than tenant access tier must be rejected");
        assert!(matches!(err, CarbideError::FailedPrecondition(_)));
    }

    #[test]
    fn unknown_requested_profile_yields_not_found() {
        let tenant = tenant_with_profile(Some("EXTERNAL"));
        let fnn = fnn_with_profiles(&[("EXTERNAL", profile(false, 2))]);
        let err = resolve_vpc_routing(
            VpcVirtualizationType::Fnn,
            Some("DOES_NOT_EXIST"),
            Some(&tenant),
            Some(&fnn),
            "test-org",
        )
        .expect_err("request naming an undefined routing profile must error");
        assert!(
            matches!(err, CarbideError::NotFoundError { kind, .. } if kind == "routing_profile")
        );
    }

    #[test]
    fn unknown_tenant_profile_yields_not_found() {
        let tenant = tenant_with_profile(Some("UNDEFINED"));
        let fnn = fnn_with_profiles(&[("EXTERNAL", profile(false, 2))]);
        let err = resolve_vpc_routing(
            VpcVirtualizationType::Fnn,
            None,
            Some(&tenant),
            Some(&fnn),
            "test-org",
        )
        .expect_err("tenant naming an undefined routing profile must error");
        assert!(
            matches!(err, CarbideError::NotFoundError { kind, .. } if kind == "routing_profile")
        );
    }
}
