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

use carbide_uuid::vpc::VpcId;
use carbide_uuid::vpc_routing_profile_transition::VpcRoutingProfileTransitionId;
use config_version::ConfigVersion;
use db::resource_pool::ResourcePoolDatabaseError;
use model::resource_pool::{OwnerType, ResourcePool};
use model::vpc::{
    NewVpcRoutingProfileTransition, UpdateVpcRoutingProfileTransitionState, Vpc,
    VpcRoutingProfileOverrides, VpcRoutingProfileTransition, VpcRoutingProfileTransitionState,
    VpcVirtualizationTypeCapabilities,
};
use sqlx::PgConnection;
use tonic::{Request, Response, Status};

use super::vpc::{ResolvedVpcRouting, resolve_vpc_routing, vpc_to_rpc};
use crate::api::{Api, log_request_data};
use crate::{CarbideError, CarbideResult};

fn parse_version(value: &str, field: &'static str) -> Result<ConfigVersion, CarbideError> {
    if value.is_empty() {
        return Err(CarbideError::MissingArgument(field));
    }
    value.parse().map_err(|_| {
        CarbideError::InvalidArgument(format!("`{field}` is not a valid config version"))
    })
}

fn parse_vni(value: Option<u32>, field: &'static str) -> Result<Option<i32>, CarbideError> {
    value
        .map(|value| {
            i32::try_from(value).map_err(|_| {
                CarbideError::InvalidArgument(format!("`{field}` is outside the supported range"))
            })
        })
        .transpose()
}

fn pool_error(error: ResourcePoolDatabaseError) -> CarbideError {
    match error {
        ResourcePoolDatabaseError::Database(error) => (*error).into(),
        ResourcePoolDatabaseError::ResourcePool(error) => error.into(),
    }
}

fn configured_pool(api: &Api, internal: bool) -> &ResourcePool<i32> {
    if internal {
        &api.common_pools.ethernet.pool_vpc_vni
    } else {
        &api.common_pools.ethernet.pool_external_vpc_vni
    }
}

fn configured_pool_by_name<'a>(
    api: &'a Api,
    pool_name: &str,
) -> Result<&'a ResourcePool<i32>, CarbideError> {
    let internal = &api.common_pools.ethernet.pool_vpc_vni;
    let external = &api.common_pools.ethernet.pool_external_vpc_vni;
    if internal.name() == pool_name {
        Ok(internal)
    } else if external.name() == pool_name {
        Ok(external)
    } else {
        Err(CarbideError::FailedPrecondition(format!(
            "transition references VNI pool `{pool_name}`, which is not a configured VPC pool"
        )))
    }
}

async fn resolve_endpoint(
    api: &Api,
    txn: &mut PgConnection,
    vpc: &Vpc,
    routing_profile_type: &str,
    routing_profile_overrides: Option<&VpcRoutingProfileOverrides>,
) -> CarbideResult<ResolvedVpcRouting> {
    vpc.config
        .network_virtualization_type
        .ensure_supports_routing_profiles()
        .map_err(CarbideError::from)?;
    let fnn = api.runtime_config.fnn.as_ref().ok_or_else(|| {
        CarbideError::FailedPrecondition(
            "FNN configuration is required for a VPC routing-profile transition".to_string(),
        )
    })?;
    let tenant = db::tenant::find(&vpc.config.tenant_organization_id, false, txn).await?;
    let resolved = resolve_vpc_routing(
        vpc.config.network_virtualization_type,
        Some(routing_profile_type),
        routing_profile_overrides,
        tenant.as_ref(),
        Some(fnn),
        &vpc.config.tenant_organization_id,
    )?;

    // Resolve the full policy too. The selection helper validates the named
    // profile and access tier; this additionally validates the exact override
    // snapshot that will be rendered to agents.
    let mut candidate = vpc.config.clone();
    candidate.routing_profile_type = Some(routing_profile_type.to_string());
    candidate.routing_profile_overrides = routing_profile_overrides.cloned();
    fnn.resolve_vpc_routing_profile(&candidate)?;

    Ok(resolved)
}

async fn require_owned_vni(
    txn: &mut PgConnection,
    pool: &ResourcePool<i32>,
    owner_id: &str,
    expected_vni: i32,
) -> CarbideResult<()> {
    let allocation = db::resource_pool::find_owned_allocation(pool, txn, OwnerType::Vpc, owner_id)
        .await
        .map_err(pool_error)?;
    if allocation != Some(expected_vni) {
        return Err(CarbideError::FailedPrecondition(format!(
            "VPC `{owner_id}` does not own expected VNI `{expected_vni}` in pool `{}`",
            pool.name()
        )));
    }
    Ok(())
}

async fn reserve_target_vni(
    api: &Api,
    txn: &mut PgConnection,
    pool: &ResourcePool<i32>,
    target_internal: bool,
    owner_id: &str,
    requested_vni: Option<i32>,
    adopt_existing: bool,
) -> CarbideResult<i32> {
    if let Some(existing) =
        db::resource_pool::find_owned_allocation(pool, txn, OwnerType::Vpc, owner_id)
            .await
            .map_err(pool_error)?
    {
        if !adopt_existing {
            return Err(CarbideError::FailedPrecondition(format!(
                "VPC `{owner_id}` already owns VNI `{existing}` in target pool `{}`; explicitly request adoption to use that manually prepared lease",
                pool.name()
            )));
        }
        let requested_vni = requested_vni.ok_or_else(|| {
            CarbideError::FailedPrecondition(
                "adopting an existing target allocation requires its exact target VNI".to_string(),
            )
        })?;
        if requested_vni != existing {
            return Err(CarbideError::FailedPrecondition(format!(
                "requested target VNI `{requested_vni}` does not match existing VPC-owned target lease `{existing}`"
            )));
        }
        return Ok(existing);
    }

    if let Some(requested_vni) = requested_vni {
        return db::resource_pool::allocate_exact(
            pool,
            txn,
            OwnerType::Vpc,
            owner_id,
            requested_vni,
        )
        .await
        .map_err(pool_error);
    }

    // Keep automatic-allocation error mapping and diagnostics identical to VPC
    // creation while selecting from the target profile's pool.
    super::vpc::allocate_vpc_vni(api, txn, owner_id, target_internal, None).await
}

struct PoolEndpointReservation<'a> {
    source_pool: &'a ResourcePool<i32>,
    source_vni: i32,
    target_pool: &'a ResourcePool<i32>,
    target_internal: bool,
    owner_id: &'a str,
    requested_target_vni: Option<i32>,
    adopt_existing: bool,
}

async fn reserve_and_validate_pool_endpoints(
    api: &Api,
    txn: &mut PgConnection,
    reservation: PoolEndpointReservation<'_>,
) -> CarbideResult<i32> {
    let PoolEndpointReservation {
        source_pool,
        source_vni,
        target_pool,
        target_internal,
        owner_id,
        requested_target_vni,
        adopt_existing,
    } = reservation;
    // Transitions in opposite directions acquire the two pool namespaces in a
    // stable order. This avoids an INTERNAL->EXTERNAL operation deadlocking an
    // EXTERNAL->INTERNAL operation when exact values happen to overlap.
    if source_pool.name() <= target_pool.name() {
        require_owned_vni(txn, source_pool, owner_id, source_vni).await?;
        reserve_target_vni(
            api,
            txn,
            target_pool,
            target_internal,
            owner_id,
            requested_target_vni,
            adopt_existing,
        )
        .await
    } else {
        let target_vni = reserve_target_vni(
            api,
            txn,
            target_pool,
            target_internal,
            owner_id,
            requested_target_vni,
            adopt_existing,
        )
        .await?;
        require_owned_vni(txn, source_pool, owner_id, source_vni).await?;
        Ok(target_vni)
    }
}

async fn require_both_leases(
    api: &Api,
    txn: &mut PgConnection,
    transition: &VpcRoutingProfileTransition,
) -> CarbideResult<()> {
    let source_pool = configured_pool_by_name(api, &transition.source_pool_name)?;
    let target_pool = configured_pool_by_name(api, &transition.target_pool_name)?;
    let owner_id = transition.vpc_id.to_string();
    if source_pool.name() <= target_pool.name() {
        require_owned_vni(txn, source_pool, &owner_id, transition.source_vni).await?;
        require_owned_vni(txn, target_pool, &owner_id, transition.target_vni).await?;
    } else {
        require_owned_vni(txn, target_pool, &owner_id, transition.target_vni).await?;
        require_owned_vni(txn, source_pool, &owner_id, transition.source_vni).await?;
    }
    Ok(())
}

fn endpoint_matches(
    vpc: &Vpc,
    routing_profile_type: &str,
    routing_profile_overrides: Option<&VpcRoutingProfileOverrides>,
    requested_vni: Option<i32>,
    allocated_vni: i32,
) -> bool {
    vpc.config.routing_profile_type.as_deref() == Some(routing_profile_type)
        && vpc.config.routing_profile_overrides.as_ref() == routing_profile_overrides
        && vpc.config.vni == requested_vni
        && vpc.status.vni == Some(allocated_vni)
}

fn vpc_at_endpoint(
    vpc: &Vpc,
    routing_profile_type: &str,
    routing_profile_overrides: Option<&VpcRoutingProfileOverrides>,
    requested_vni: Option<i32>,
    allocated_vni: i32,
) -> Vpc {
    let mut candidate = vpc.clone();
    candidate.config.routing_profile_type = Some(routing_profile_type.to_string());
    candidate.config.routing_profile_overrides = routing_profile_overrides.cloned();
    candidate.config.vni = requested_vni;
    candidate.status.vni = Some(allocated_vni);
    candidate
}

fn require_endpoint(
    vpc: &Vpc,
    routing_profile_type: &str,
    routing_profile_overrides: Option<&VpcRoutingProfileOverrides>,
    requested_vni: Option<i32>,
    allocated_vni: i32,
    endpoint: &str,
) -> CarbideResult<()> {
    if !endpoint_matches(
        vpc,
        routing_profile_type,
        routing_profile_overrides,
        requested_vni,
        allocated_vni,
    ) {
        return Err(CarbideError::FailedPrecondition(format!(
            "VPC state no longer matches the transition's {endpoint} endpoint"
        )));
    }
    Ok(())
}

async fn validate_current_transition_state(
    api: &Api,
    txn: &mut PgConnection,
    vpc: &Vpc,
    transition: &VpcRoutingProfileTransition,
) -> CarbideResult<()> {
    let (profile, overrides, requested_vni, allocated_vni, pool_name, endpoint) =
        match transition.state {
            VpcRoutingProfileTransitionState::CutoverPendingFinalize
            | VpcRoutingProfileTransitionState::Finalized => (
                &transition.target_routing_profile_type,
                transition.target_routing_profile_overrides.as_ref(),
                transition.target_requested_vni,
                transition.target_vni,
                &transition.target_pool_name,
                "target",
            ),
            VpcRoutingProfileTransitionState::RollbackPendingFinalize
            | VpcRoutingProfileTransitionState::RolledBack => (
                &transition.source_routing_profile_type,
                transition.source_routing_profile_overrides.as_ref(),
                transition.source_requested_vni,
                transition.source_vni,
                &transition.source_pool_name,
                "source",
            ),
        };
    require_endpoint(
        vpc,
        profile,
        overrides,
        requested_vni,
        allocated_vni,
        endpoint,
    )?;
    validate_persisted_endpoint(api, txn, vpc, profile, overrides, pool_name).await?;
    if transition.state.is_terminal() {
        let active_pool = configured_pool_by_name(api, pool_name)?;
        require_owned_vni(
            txn,
            active_pool,
            &transition.vpc_id.to_string(),
            allocated_vni,
        )
        .await
    } else {
        require_both_leases(api, txn, transition).await
    }
}

fn result(
    api: &Api,
    transition: VpcRoutingProfileTransition,
    vpc: Vpc,
) -> rpc::forge::VpcRoutingProfileTransitionResult {
    rpc::forge::VpcRoutingProfileTransitionResult {
        transition: Some(transition.into()),
        vpc: Some(vpc_to_rpc(vpc, api.runtime_config.fnn.as_ref())),
    }
}

fn begin_intent_matches(
    transition: &VpcRoutingProfileTransition,
    vpc_id: VpcId,
    source_vpc_version: ConfigVersion,
    target_profile: &str,
    target_vni: Option<i32>,
    target_overrides: Option<&VpcRoutingProfileOverrides>,
    reason: &str,
) -> bool {
    transition.vpc_id == vpc_id
        && transition.source_vpc_version == source_vpc_version
        && transition.target_routing_profile_type == target_profile
        && transition.target_requested_vni == target_vni
        && transition.target_routing_profile_overrides.as_ref() == target_overrides
        && transition.reason == reason
}

pub(crate) async fn begin(
    api: &Api,
    request: Request<rpc::forge::BeginVpcRoutingProfileTransitionRequest>,
) -> Result<Response<rpc::forge::VpcRoutingProfileTransitionResult>, Status> {
    log_request_data(&request);
    let request = request.into_inner();
    let id = request.id.ok_or(CarbideError::MissingArgument("id"))?;
    let vpc_id = request
        .vpc_id
        .ok_or(CarbideError::MissingArgument("vpc_id"))?;
    let expected_vpc_version =
        parse_version(&request.if_vpc_version_match, "if_vpc_version_match")?;
    if request.target_routing_profile_type.is_empty() {
        return Err(CarbideError::MissingArgument("target_routing_profile_type").into());
    }
    if request.reason.trim().is_empty() {
        return Err(CarbideError::InvalidArgument("`reason` must not be empty".to_string()).into());
    }
    let requested_target_vni = parse_vni(request.target_vni, "target_vni")?;
    if request.adopt_existing_target_allocation && requested_target_vni.is_none() {
        return Err(CarbideError::InvalidArgument(
            "`target_vni` is required when adopting an existing target allocation".to_string(),
        )
        .into());
    }
    let target_overrides = request
        .target_routing_profile_overrides
        .map(TryInto::try_into)
        .transpose()?;

    let mut txn = api.txn_begin().await?;
    db::tenant_prefix_overlap::lock_checks(txn.as_mut()).await?;
    let overlap_snapshot =
        super::tenant_prefix_overlap::snapshot_existing_vpc_prefixes(txn.as_mut(), vpc_id).await?;
    let vpc = db::vpc::find_by_with_lock(
        txn.as_mut(),
        db::ObjectColumnFilter::One(db::vpc::IdColumn, &vpc_id),
        db::vpc::VpcRowLock::Mutation,
    )
    .await?
    .pop()
    .ok_or_else(|| CarbideError::NotFoundError {
        kind: "VPC",
        id: vpc_id.to_string(),
    })?;

    if let Some(existing) = db::vpc_routing_profile_transition::find(&mut txn, id).await? {
        if !begin_intent_matches(
            &existing,
            vpc_id,
            expected_vpc_version,
            &request.target_routing_profile_type,
            requested_target_vni,
            target_overrides.as_ref(),
            &request.reason,
        ) {
            return Err(CarbideError::AlreadyFoundError {
                kind: "VPC routing-profile transition with different intent",
                id: id.to_string(),
            }
            .into());
        }
        if !existing.state.is_terminal() {
            validate_current_transition_state(api, txn.as_mut(), &vpc, &existing).await?;
            super::tenant_prefix_overlap::validate_vpc_candidate(
                &api.runtime_config,
                txn.as_mut(),
                &vpc,
                &overlap_snapshot,
            )
            .await?;
        }
        txn.commit().await?;
        return Ok(Response::new(result(api, existing, vpc)));
    }

    if vpc.version != expected_vpc_version {
        return Err(CarbideError::ConcurrentModificationError(
            "VPC",
            expected_vpc_version.to_string(),
        )
        .into());
    }
    if let Some(active) =
        db::vpc_routing_profile_transition::find_active_by_vpc(&mut txn, vpc_id).await?
    {
        return Err(CarbideError::FailedPrecondition(format!(
            "VPC `{vpc_id}` already has active routing-profile transition `{}`",
            active.id
        ))
        .into());
    }

    let source_profile = vpc.config.routing_profile_type.as_deref().ok_or_else(|| {
        CarbideError::FailedPrecondition(
            "VPC does not have a named routing profile to transition from".to_string(),
        )
    })?;
    let source_routing = resolve_endpoint(
        api,
        txn.as_mut(),
        &vpc,
        source_profile,
        vpc.config.routing_profile_overrides.as_ref(),
    )
    .await?;
    let target_routing = resolve_endpoint(
        api,
        txn.as_mut(),
        &vpc,
        &request.target_routing_profile_type,
        target_overrides.as_ref(),
    )
    .await?;
    if source_routing.internal == target_routing.internal {
        return Err(CarbideError::FailedPrecondition(
            "source and target routing profiles use the same VNI pool; this operation only supports INTERNAL-to-EXTERNAL or EXTERNAL-to-INTERNAL transitions"
                .to_string(),
        )
        .into());
    }

    let source_vni = vpc.status.vni.ok_or_else(|| {
        CarbideError::FailedPrecondition("VPC does not have an allocated VNI".to_string())
    })?;
    if vpc
        .config
        .vni
        .is_some_and(|requested| requested != source_vni)
    {
        return Err(CarbideError::FailedPrecondition(
            "VPC requested VNI does not match its allocated VNI".to_string(),
        )
        .into());
    }
    let source_pool = configured_pool(api, source_routing.internal);
    let target_pool = configured_pool(api, target_routing.internal);
    let owner_id = vpc_id.to_string();
    let target_vni = reserve_and_validate_pool_endpoints(
        api,
        txn.as_mut(),
        PoolEndpointReservation {
            source_pool,
            source_vni,
            target_pool,
            target_internal: target_routing.internal,
            owner_id: &owner_id,
            requested_target_vni,
            adopt_existing: request.adopt_existing_target_allocation,
        },
    )
    .await?;
    if target_vni == source_vni {
        return Err(CarbideError::FailedPrecondition(
            "source and target VNI values must differ".to_string(),
        )
        .into());
    }

    let target_candidate = vpc_at_endpoint(
        &vpc,
        &request.target_routing_profile_type,
        target_overrides.as_ref(),
        requested_target_vni,
        target_vni,
    );
    super::tenant_prefix_overlap::validate_vpc_candidate(
        &api.runtime_config,
        txn.as_mut(),
        &target_candidate,
        &overlap_snapshot,
    )
    .await?;

    let updated_vpc = db::vpc::update_routing_profile_and_vni(
        txn.as_mut(),
        vpc_id,
        vpc.version,
        &request.target_routing_profile_type,
        target_overrides.as_ref(),
        requested_target_vni,
        target_vni,
    )
    .await?;
    let transition = db::vpc_routing_profile_transition::create(
        &NewVpcRoutingProfileTransition {
            id,
            vpc_id,
            source_routing_profile_type: source_profile.to_string(),
            target_routing_profile_type: request.target_routing_profile_type,
            source_pool_name: source_pool.name().to_string(),
            target_pool_name: target_pool.name().to_string(),
            source_vni,
            target_vni,
            source_requested_vni: vpc.config.vni,
            target_requested_vni: requested_target_vni,
            source_routing_profile_overrides: vpc.config.routing_profile_overrides,
            target_routing_profile_overrides: target_overrides,
            source_vpc_version: vpc.version,
            cutover_vpc_version: updated_vpc.version,
            reason: request.reason,
        },
        txn.as_mut(),
    )
    .await?;

    txn.commit().await?;
    Ok(Response::new(result(api, transition, updated_vpc)))
}

async fn lock_transition_and_vpc(
    txn: &mut PgConnection,
    id: VpcRoutingProfileTransitionId,
) -> CarbideResult<(Vpc, VpcRoutingProfileTransition)> {
    let lookup = db::vpc_routing_profile_transition::find(&mut *txn, id)
        .await?
        .ok_or_else(|| CarbideError::NotFoundError {
            kind: "VPC routing-profile transition",
            id: id.to_string(),
        })?;
    let vpc = db::vpc::find_by_with_lock(
        txn,
        db::ObjectColumnFilter::One(db::vpc::IdColumn, &lookup.vpc_id),
        db::vpc::VpcRowLock::Mutation,
    )
    .await?
    .pop()
    .ok_or_else(|| CarbideError::NotFoundError {
        kind: "VPC",
        id: lookup.vpc_id.to_string(),
    })?;
    let transition = db::vpc_routing_profile_transition::lock_by_id_after_vpc_lock(txn, id)
        .await?
        .ok_or_else(|| CarbideError::NotFoundError {
            kind: "VPC routing-profile transition",
            id: id.to_string(),
        })?;
    Ok((vpc, transition))
}

async fn validate_persisted_endpoint(
    api: &Api,
    txn: &mut PgConnection,
    vpc: &Vpc,
    routing_profile_type: &str,
    routing_profile_overrides: Option<&VpcRoutingProfileOverrides>,
    expected_pool_name: &str,
) -> CarbideResult<()> {
    let resolved = resolve_endpoint(
        api,
        txn,
        vpc,
        routing_profile_type,
        routing_profile_overrides,
    )
    .await?;
    let configured = configured_pool(api, resolved.internal);
    if configured.name() != expected_pool_name {
        return Err(CarbideError::FailedPrecondition(format!(
            "routing profile `{routing_profile_type}` no longer maps to recorded VNI pool `{expected_pool_name}`"
        )));
    }
    Ok(())
}

async fn switch_endpoint(
    api: &Api,
    id: VpcRoutingProfileTransitionId,
    if_version_match: ConfigVersion,
    destination: VpcRoutingProfileTransitionState,
) -> Result<rpc::forge::VpcRoutingProfileTransitionResult, Status> {
    let mut txn = api.txn_begin().await?;
    let lookup = db::vpc_routing_profile_transition::find(&mut txn, id)
        .await?
        .ok_or_else(|| CarbideError::NotFoundError {
            kind: "VPC routing-profile transition",
            id: id.to_string(),
        })?;
    db::tenant_prefix_overlap::lock_checks(txn.as_mut()).await?;
    let overlap_snapshot =
        super::tenant_prefix_overlap::snapshot_existing_vpc_prefixes(txn.as_mut(), lookup.vpc_id)
            .await?;
    let (vpc, transition) = lock_transition_and_vpc(txn.as_mut(), id).await?;

    let (
        already_active,
        required_state,
        profile,
        overrides,
        requested_vni,
        allocated_vni,
        pool_name,
    ) = match destination {
        VpcRoutingProfileTransitionState::RollbackPendingFinalize => (
            transition.state == VpcRoutingProfileTransitionState::RollbackPendingFinalize,
            VpcRoutingProfileTransitionState::CutoverPendingFinalize,
            &transition.source_routing_profile_type,
            transition.source_routing_profile_overrides.as_ref(),
            transition.source_requested_vni,
            transition.source_vni,
            &transition.source_pool_name,
        ),
        VpcRoutingProfileTransitionState::CutoverPendingFinalize => (
            transition.state == VpcRoutingProfileTransitionState::CutoverPendingFinalize,
            VpcRoutingProfileTransitionState::RollbackPendingFinalize,
            &transition.target_routing_profile_type,
            transition.target_routing_profile_overrides.as_ref(),
            transition.target_requested_vni,
            transition.target_vni,
            &transition.target_pool_name,
        ),
        _ => {
            return Err(CarbideError::Internal {
                message: "invalid pending transition destination".to_string(),
            }
            .into());
        }
    };

    if already_active {
        validate_current_transition_state(api, txn.as_mut(), &vpc, &transition).await?;
        super::tenant_prefix_overlap::validate_vpc_candidate(
            &api.runtime_config,
            txn.as_mut(),
            &vpc,
            &overlap_snapshot,
        )
        .await?;
        txn.commit().await?;
        return Ok(result(api, transition, vpc));
    }
    if transition.state != required_state {
        return Err(CarbideError::FailedPrecondition(format!(
            "transition `{id}` cannot move from {:?} to {:?}",
            transition.state, destination
        ))
        .into());
    }
    if transition.version != if_version_match {
        return Err(CarbideError::ConcurrentModificationError(
            "VPC routing-profile transition",
            if_version_match.to_string(),
        )
        .into());
    }

    match transition.state {
        VpcRoutingProfileTransitionState::CutoverPendingFinalize => require_endpoint(
            &vpc,
            &transition.target_routing_profile_type,
            transition.target_routing_profile_overrides.as_ref(),
            transition.target_requested_vni,
            transition.target_vni,
            "target",
        )?,
        VpcRoutingProfileTransitionState::RollbackPendingFinalize => require_endpoint(
            &vpc,
            &transition.source_routing_profile_type,
            transition.source_routing_profile_overrides.as_ref(),
            transition.source_requested_vni,
            transition.source_vni,
            "source",
        )?,
        _ => unreachable!("required_state admits only pending states"),
    }
    validate_persisted_endpoint(api, txn.as_mut(), &vpc, profile, overrides, pool_name).await?;
    require_both_leases(api, txn.as_mut(), &transition).await?;

    let destination_candidate =
        vpc_at_endpoint(&vpc, profile, overrides, requested_vni, allocated_vni);
    super::tenant_prefix_overlap::validate_vpc_candidate(
        &api.runtime_config,
        txn.as_mut(),
        &destination_candidate,
        &overlap_snapshot,
    )
    .await?;

    let updated_vpc = db::vpc::update_routing_profile_and_vni(
        txn.as_mut(),
        transition.vpc_id,
        vpc.version,
        profile,
        overrides,
        requested_vni,
        allocated_vni,
    )
    .await?;
    let updated_transition = db::vpc_routing_profile_transition::update_state(
        &UpdateVpcRoutingProfileTransitionState {
            id,
            if_version_match,
            expected_state: transition.state,
            state: destination,
            cutover_vpc_version: (destination
                == VpcRoutingProfileTransitionState::CutoverPendingFinalize)
                .then_some(updated_vpc.version),
            rollback_vpc_version: (destination
                == VpcRoutingProfileTransitionState::RollbackPendingFinalize)
                .then_some(updated_vpc.version),
        },
        txn.as_mut(),
    )
    .await?;

    txn.commit().await?;
    Ok(result(api, updated_transition, updated_vpc))
}

pub(crate) async fn rollback(
    api: &Api,
    request: Request<rpc::forge::RollbackVpcRoutingProfileTransitionRequest>,
) -> Result<Response<rpc::forge::VpcRoutingProfileTransitionResult>, Status> {
    log_request_data(&request);
    let request = request.into_inner();
    let id = request.id.ok_or(CarbideError::MissingArgument("id"))?;
    let version = parse_version(&request.if_version_match, "if_version_match")?;
    switch_endpoint(
        api,
        id,
        version,
        VpcRoutingProfileTransitionState::RollbackPendingFinalize,
    )
    .await
    .map(Response::new)
}

pub(crate) async fn recutover(
    api: &Api,
    request: Request<rpc::forge::RecutoverVpcRoutingProfileTransitionRequest>,
) -> Result<Response<rpc::forge::VpcRoutingProfileTransitionResult>, Status> {
    log_request_data(&request);
    let request = request.into_inner();
    let id = request.id.ok_or(CarbideError::MissingArgument("id"))?;
    let version = parse_version(&request.if_version_match, "if_version_match")?;
    switch_endpoint(
        api,
        id,
        version,
        VpcRoutingProfileTransitionState::CutoverPendingFinalize,
    )
    .await
    .map(Response::new)
}

pub(crate) async fn finalize(
    api: &Api,
    request: Request<rpc::forge::FinalizeVpcRoutingProfileTransitionRequest>,
) -> Result<Response<rpc::forge::VpcRoutingProfileTransitionResult>, Status> {
    log_request_data(&request);
    let request = request.into_inner();
    if !request.convergence_confirmed {
        return Err(CarbideError::InvalidArgument(
            "`convergence_confirmed` must be true before releasing the rollback lease".to_string(),
        )
        .into());
    }
    let id = request.id.ok_or(CarbideError::MissingArgument("id"))?;
    let expected_version = parse_version(&request.if_version_match, "if_version_match")?;
    let mut txn = api.txn_begin().await?;
    let (vpc, transition) = lock_transition_and_vpc(txn.as_mut(), id).await?;

    if transition.state.is_terminal() {
        txn.commit().await?;
        return Ok(Response::new(result(api, transition, vpc)));
    }
    if transition.version != expected_version {
        return Err(CarbideError::ConcurrentModificationError(
            "VPC routing-profile transition",
            expected_version.to_string(),
        )
        .into());
    }
    require_both_leases(api, txn.as_mut(), &transition).await?;

    let (inactive_pool_name, inactive_vni, terminal_state) = match transition.state {
        VpcRoutingProfileTransitionState::CutoverPendingFinalize => {
            require_endpoint(
                &vpc,
                &transition.target_routing_profile_type,
                transition.target_routing_profile_overrides.as_ref(),
                transition.target_requested_vni,
                transition.target_vni,
                "target",
            )?;
            validate_persisted_endpoint(
                api,
                txn.as_mut(),
                &vpc,
                &transition.target_routing_profile_type,
                transition.target_routing_profile_overrides.as_ref(),
                &transition.target_pool_name,
            )
            .await?;
            (
                &transition.source_pool_name,
                transition.source_vni,
                VpcRoutingProfileTransitionState::Finalized,
            )
        }
        VpcRoutingProfileTransitionState::RollbackPendingFinalize => {
            require_endpoint(
                &vpc,
                &transition.source_routing_profile_type,
                transition.source_routing_profile_overrides.as_ref(),
                transition.source_requested_vni,
                transition.source_vni,
                "source",
            )?;
            validate_persisted_endpoint(
                api,
                txn.as_mut(),
                &vpc,
                &transition.source_routing_profile_type,
                transition.source_routing_profile_overrides.as_ref(),
                &transition.source_pool_name,
            )
            .await?;
            (
                &transition.target_pool_name,
                transition.target_vni,
                VpcRoutingProfileTransitionState::RolledBack,
            )
        }
        _ => unreachable!("terminal states returned above"),
    };

    let inactive_pool = configured_pool_by_name(api, inactive_pool_name)?;
    db::resource_pool::release_owned(
        inactive_pool,
        txn.as_mut(),
        inactive_vni,
        OwnerType::Vpc,
        &transition.vpc_id.to_string(),
    )
    .await?;
    let transition = db::vpc_routing_profile_transition::update_state(
        &UpdateVpcRoutingProfileTransitionState {
            id,
            if_version_match: expected_version,
            expected_state: transition.state,
            state: terminal_state,
            cutover_vpc_version: None,
            rollback_vpc_version: None,
        },
        txn.as_mut(),
    )
    .await?;

    txn.commit().await?;
    Ok(Response::new(result(api, transition, vpc)))
}

pub(crate) async fn find(
    api: &Api,
    request: Request<rpc::forge::VpcRoutingProfileTransitionSearchFilter>,
) -> Result<Response<rpc::forge::VpcRoutingProfileTransitionList>, Status> {
    log_request_data(&request);
    let request = request.into_inner();
    let mut transitions = if let Some(id) = request.id {
        db::vpc_routing_profile_transition::find(&api.database_connection, id)
            .await?
            .into_iter()
            .collect()
    } else if let Some(vpc_id) = request.vpc_id {
        db::vpc_routing_profile_transition::find_by_vpc(&api.database_connection, vpc_id).await?
    } else {
        db::vpc_routing_profile_transition::list(&api.database_connection).await?
    };
    if request.active_only == Some(true) {
        transitions.retain(|transition| !transition.state.is_terminal());
    }
    Ok(Response::new(rpc::forge::VpcRoutingProfileTransitionList {
        transitions: transitions.into_iter().map(Into::into).collect(),
    }))
}
