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

use model::dpa_interface::{DpaInterfaceNetworkStatusObservation, NewDpaInterface};
use tonic::{Request, Response};

use crate::api::{Api, log_request_data};
use crate::{CarbideError, CarbideResult};

pub(crate) async fn create(
    api: &Api,
    request: Request<::rpc::forge::DpaInterfaceCreationRequest>,
) -> CarbideResult<Response<::rpc::forge::DpaInterface>> {
    log_request_data(&request);

    let mut txn = api.txn_begin("create dpa").await?;

    let new_dpa =
        db::dpa_interface::persist(NewDpaInterface::try_from(request.into_inner())?, &mut txn)
            .await?;

    let dpa_out: rpc::forge::DpaInterface = new_dpa.into();

    txn.commit().await?;

    Ok(Response::new(dpa_out))
}

pub(crate) async fn delete(
    api: &Api,
    request: Request<::rpc::forge::DpaInterfaceDeletionRequest>,
) -> CarbideResult<Response<::rpc::forge::DpaInterfaceDeletionResult>> {
    log_request_data(&request);

    let req = request.into_inner();

    let id = req.id.ok_or(CarbideError::InvalidArgument(
        "at least one ID must be provided to delete dpa interface".to_string(),
    ))?;

    // Prepare our txn to grab the NetworkSecurityGroups from the DB
    let mut txn = api.txn_begin("delete dpa interface").await?;

    let dpa_ifs_int = db::dpa_interface::find_by_ids(&mut txn, &[id], false).await?;

    let dpa_if_int = match dpa_ifs_int.len() {
        1 => dpa_ifs_int[0].clone(),
        _ => {
            return Err(CarbideError::InvalidArgument(
                "ID could not be used to locate interface".to_string(),
            ));
        }
    };

    db::dpa_interface::delete(dpa_if_int, &mut txn).await?;

    txn.commit().await?;

    Ok(Response::new(::rpc::forge::DpaInterfaceDeletionResult {}))
}

pub(crate) async fn get_all_ids(
    api: &Api,
    request: Request<()>,
) -> CarbideResult<Response<::rpc::forge::DpaInterfaceIdList>> {
    log_request_data(&request);

    let mut txn = api.txn_begin("dpa get_all_ids").await?;

    let ids = db::dpa_interface::find_ids(&mut txn).await?;

    Ok(Response::new(::rpc::forge::DpaInterfaceIdList { ids }))
}

pub(crate) async fn find_dpa_interfaces_by_ids(
    api: &Api,
    request: Request<::rpc::forge::DpaInterfacesByIdsRequest>,
) -> CarbideResult<Response<::rpc::forge::DpaInterfaceList>> {
    log_request_data(&request);

    let req = request.into_inner();

    let max_find_by_ids = api.runtime_config.max_find_by_ids as usize;
    if req.ids.len() > max_find_by_ids {
        return Err(CarbideError::InvalidArgument(format!(
            "no more than {max_find_by_ids} IDs can be submitted to find_dpa_interfaces_by_ids"
        )));
    }

    if req.ids.is_empty() {
        return Err(CarbideError::InvalidArgument(
            "at least one ID must be provided to find_dpa_interfaces_by_ids".to_string(),
        ));
    }

    // Prepare our txn to grab the NetworkSecurityGroups from the DB
    let mut txn = api.txn_begin("find_dpa_interfaces_by_ids").await?;

    let dpa_ifs_int =
        db::dpa_interface::find_by_ids(&mut txn, &req.ids, req.include_history).await?;

    let rpc_dpa_ifs = dpa_ifs_int
        .into_iter()
        .map(|i| i.into())
        .collect::<Vec<rpc::forge::DpaInterface>>();

    // Commit if nothing has gone wrong up to now
    txn.commit().await?;

    Ok(Response::new(rpc::forge::DpaInterfaceList {
        interfaces: rpc_dpa_ifs,
    }))
}

// XXX TODO XXX
// Remove before final commit
// XXX TODO XXX
pub(crate) async fn set_dpa_network_observation_status(
    api: &Api,
    request: Request<::rpc::forge::DpaNetworkObservationSetRequest>,
) -> CarbideResult<Response<::rpc::forge::DpaInterface>> {
    log_request_data(&request);

    let req = request.into_inner();

    let id = req.id.ok_or(CarbideError::InvalidArgument(
        "at least one ID must be provided to find_dpa_interfaces_by_ids".to_string(),
    ))?;

    // Prepare our txn to grab the NetworkSecurityGroups from the DB
    let mut txn = api.txn_begin("set_dpa_network_observation_status").await?;

    let dpa_ifs_int = db::dpa_interface::find_by_ids(&mut txn, &[id], false).await?;

    if dpa_ifs_int.len() != 1 {
        return Err(CarbideError::InvalidArgument(
            "ID could not be used to locate interface".to_string(),
        ));
    }

    let dpa_if_int = dpa_ifs_int[0].clone();

    let observation = DpaInterfaceNetworkStatusObservation {
        observed_at: chrono::Utc::now(),
        network_config_version: Some(dpa_if_int.network_config.version),
    };

    db::dpa_interface::update_network_observation(&dpa_if_int, &mut txn, &observation).await?;

    txn.commit().await?;

    Ok(Response::new(dpa_if_int.into()))
}
