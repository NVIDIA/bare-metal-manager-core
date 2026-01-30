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

use ::db::{ObjectColumnFilter, vpc_prefix as db};
use ::rpc::forge as rpc;
use ::rpc::forge::PrefixMatchType;
use ipnetwork::IpNetwork;
use model::network_prefix::NetworkPrefix;
use model::vpc_prefix;
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::{Api, log_request_data};
pub async fn create(
    api: &Api,
    request: Request<rpc::VpcPrefixCreationRequest>,
) -> Result<Response<rpc::VpcPrefix>, Status> {
    log_request_data(&request);

    let new_prefix = vpc_prefix::NewVpcPrefix::try_from(request.into_inner())?;

    // Validate that the new VPC prefix is in canonical form (no bits set to
    // 1 after the prefix).
    let canonical_address = new_prefix.config.prefix.network();
    let prefix_address = new_prefix.config.prefix.ip();
    if canonical_address != prefix_address {
        let prefix_len = new_prefix.config.prefix.prefix();
        let msg = format!(
            "IP prefixes must be in canonical format. This prefix should be \
            specified as {canonical_address}/{prefix_len} and not \
            {prefix_address}/{prefix_len}."
        );
        return Err(CarbideError::InvalidArgument(msg).into());
    }

    // Validate that the new VPC prefix is contained within the site prefixes
    // address space. This will also reject any IPv6 prefixes, since site
    // prefixes cannot contain any IPv6 address space at the moment.
    if let Some(ref site_prefixes) = api.eth_data.site_fabric_prefixes {
        let prefix = new_prefix.config.prefix;
        if !site_prefixes.contains(prefix) {
            return Err(CarbideError::InvalidArgument(format!(
                "The VPC prefix {prefix} is not contained within the site fabric prefixes"
            ))
            .into());
        }
    }

    let mut txn = api.txn_begin().await?;

    let conflicting_vpc_prefixes = db::probe(new_prefix.config.prefix, &mut txn).await?;
    if !conflicting_vpc_prefixes.is_empty() {
        let conflicting_vpc_prefixes = conflicting_vpc_prefixes
            .into_iter()
            .map(|p| p.config.prefix);
        let conflicting_vpc_prefixes = itertools::join(conflicting_vpc_prefixes, ", ");
        let msg = format!(
            "The requested VPC prefix ({vpc_prefix}) overlaps at least one \
            existing VPC prefix ({conflicting_vpc_prefixes})",
            vpc_prefix = new_prefix.config.prefix,
        );
        return Err(CarbideError::InvalidArgument(msg).into());
    }

    let segment_prefixes = db::probe_segment_prefixes(new_prefix.config.prefix, &mut txn).await?;

    // Check that all the prefixes we found are on segments that belong to our
    // own VPC.
    let segment_prefixes: Vec<NetworkPrefix> = {
        let (own_segment_prefixes, foreign_segment_prefixes) = segment_prefixes
            .into_iter()
            .partition::<Vec<_>, _>(|(segment_vpc_id, _)| segment_vpc_id == &new_prefix.vpc_id);

        if !foreign_segment_prefixes.is_empty() {
            let foreign_segment_prefixes = foreign_segment_prefixes
                .into_iter()
                .map(|(_, np)| np.prefix);
            let foreign_segment_prefixes = itertools::join(foreign_segment_prefixes, ", ");
            let msg = format!(
                "The requested VPC prefix of {vpc_prefix} conflicts with at \
                least one network segment prefix ({foreign_segment_prefixes}) \
                owned by another VPC",
                vpc_prefix = new_prefix.config.prefix,
            );
            return Err(CarbideError::InvalidArgument(msg).into());
        }
        // We don't need the associated VpcIds anymore, get rid of them.
        own_segment_prefixes
            .into_iter()
            .map(|(_, segment_prefix)| segment_prefix)
            .collect()
    };

    // Check that the network segment prefixes we found can actually fit into
    // this new VPC prefix container.
    if let Some(larger_segment_prefix) = segment_prefixes.iter().find(|segment_prefix| {
        let segment_prefix_len = segment_prefix.prefix.prefix();
        let vpc_prefix_len = new_prefix.config.prefix.prefix();
        segment_prefix_len < vpc_prefix_len
    }) {
        let msg = format!(
            "The requested VPC prefix ({vpc_prefix}) is too small to contain \
            an existing network segment prefix ({larger_segment_prefix})",
            vpc_prefix = new_prefix.config.prefix,
            larger_segment_prefix = larger_segment_prefix.prefix,
        );
        return Err(CarbideError::InvalidArgument(msg).into());
    }

    // Check that the network segment prefixes aren't already tied to a VPC
    // prefix. This is probably impossible at this point if the DB constraints
    // and transactional isolation are working as intended, but better safe
    // than sorry.
    if let Some((associated_vpc_prefix, segment_prefix)) = segment_prefixes
        .iter()
        .find_map(|segment_prefix| segment_prefix.vpc_prefix.map(|p| (p, segment_prefix)))
    {
        let msg = format!(
            "The requested VPC prefix ({vpc_prefix}) contains a network \
            segment prefix ({segment_prefix}) which is already associated with \
            another VPC prefix ({associated_vpc_prefix}). If you see this \
            error message, please file a bug!",
            vpc_prefix = new_prefix.config.prefix,
            segment_prefix = segment_prefix.prefix,
        );
        return Err(CarbideError::InvalidArgument(msg).into());
    }

    new_prefix
        .metadata
        .validate(true)
        .map_err(CarbideError::from)?;

    let vpc_prefix = db::persist(new_prefix, &mut txn).await?;

    // Associate all of the network segment prefixes with the new VPC prefix.
    for mut segment_prefix in segment_prefixes {
        ::db::network_prefix::set_vpc_prefix(
            &mut segment_prefix,
            &mut txn,
            &vpc_prefix.id,
            &vpc_prefix.config.prefix,
        )
        .await?;
    }

    txn.commit().await?;

    Ok(tonic::Response::new(vpc_prefix.into()))
}

pub async fn search(
    api: &Api,
    request: Request<rpc::VpcPrefixSearchQuery>,
) -> Result<Response<rpc::VpcPrefixIdList>, Status> {
    log_request_data(&request);
    let rpc::VpcPrefixSearchQuery {
        vpc_id,
        tenant_prefix_id,
        name,
        prefix_match,
        prefix_match_type,
    } = request.into_inner();

    // We don't have tenant prefixes in this version, so searching against them
    // isn't allowed.
    tenant_prefix_id
        .map(|_| -> Result<(), CarbideError> {
            Err(CarbideError::InvalidArgument(
                "Searching on tenant_prefix_id is currently unsupported".to_owned(),
            ))
        })
        .transpose()?;

    // If prefix_match was specified, we'll combine it with prefix_match_type to
    // determine the match semantics.
    let prefix_match = prefix_match
        .map(|prefix| -> Result<_, CarbideError> {
            let prefix =
                IpNetwork::try_from(prefix.as_str()).map_err(CarbideError::NetworkParseError)?;
            let prefix_match_type = prefix_match_type
                .ok_or_else(|| CarbideError::MissingArgument("prefix_match_type"))?;
            let prefix_match_type = PrefixMatchType::try_from(prefix_match_type).map_err(|_e| {
                CarbideError::InvalidArgument(format!(
                    "Unknown PrefixMatchType value: {prefix_match_type}"
                ))
            })?;
            use model::vpc_prefix::PrefixMatch;
            let prefix_match = match prefix_match_type {
                PrefixMatchType::PrefixExact => PrefixMatch::Exact(prefix),
                PrefixMatchType::PrefixContains => PrefixMatch::Contains(prefix),
                PrefixMatchType::PrefixContainedBy => PrefixMatch::ContainedBy(prefix),
            };
            Ok(prefix_match)
        })
        .transpose()?;

    let mut txn = api.txn_begin().await?;

    let vpc_prefix_ids = db::search(&mut txn, vpc_id, name, prefix_match).await?;

    txn.commit().await?;

    Ok(tonic::Response::new(rpc::VpcPrefixIdList {
        vpc_prefix_ids,
    }))
}

pub async fn get(
    api: &Api,
    request: Request<rpc::VpcPrefixGetRequest>,
) -> Result<Response<rpc::VpcPrefixList>, Status> {
    log_request_data(&request);

    let rpc::VpcPrefixGetRequest { vpc_prefix_ids } = request.into_inner();
    if vpc_prefix_ids.len() > (api.runtime_config.max_find_by_ids as usize) {
        let msg = format!(
            "Too many VPC prefix IDs were specified (the limit is {maximum})",
            maximum = api.runtime_config.max_find_by_ids,
        );
        return Err(CarbideError::InvalidArgument(msg).into());
    }

    let mut txn = api.txn_begin().await?;

    let vpc_prefixes = db::get_by_id(
        &mut txn,
        ObjectColumnFilter::List(db::IdColumn, vpc_prefix_ids.as_slice()),
    )
    .await?;

    txn.commit().await?;

    let vpc_prefixes: Vec<_> = vpc_prefixes.into_iter().map(rpc::VpcPrefix::from).collect();
    Ok(tonic::Response::new(rpc::VpcPrefixList { vpc_prefixes }))
}

pub async fn update(
    api: &Api,
    request: Request<rpc::VpcPrefixUpdateRequest>,
) -> Result<Response<rpc::VpcPrefix>, Status> {
    log_request_data(&request);

    let update_prefix = vpc_prefix::UpdateVpcPrefix::try_from(request.into_inner())?;

    let mut txn = api.txn_begin().await?;

    update_prefix
        .metadata
        .validate(true)
        .map_err(CarbideError::from)?;

    let updated = db::update(&update_prefix, &mut txn).await?;

    txn.commit().await?;

    Ok(tonic::Response::new(updated.into()))
}

pub async fn delete(
    api: &Api,
    request: Request<rpc::VpcPrefixDeletionRequest>,
) -> Result<Response<rpc::VpcPrefixDeletionResult>, Status> {
    log_request_data(&request);

    let delete_prefix = vpc_prefix::DeleteVpcPrefix::try_from(request.into_inner())?;

    let mut txn = api.txn_begin().await?;

    // TODO: We could probably produce some nicer errors here when trying
    // to delete prefixes that are still being used by network segments, or
    // whatever else might be pointing at them. For now we're just relying on
    // the DB constraints and returning whatever error that results in.

    db::delete(&delete_prefix, &mut txn).await?;

    txn.commit().await?;

    Ok(tonic::Response::new(rpc::VpcPrefixDeletionResult {}))
}
