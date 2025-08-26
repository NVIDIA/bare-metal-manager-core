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

use crate::{
    CarbideError, CarbideResult,
    api::{Api, log_request_data},
    db::dpa_interface::DpaInterface,
};

use crate::db::{DatabaseError, dpa_interface::NewDpaInterface};
use ::rpc::errors::RpcDataConversionError;
use forge_uuid::dpa_interface::DpaInterfaceId;
use tonic::{Request, Response};

pub(crate) async fn create(
    api: &Api,
    request: Request<::rpc::forge::DpaInterfaceCreationRequest>,
) -> CarbideResult<Response<::rpc::forge::DpaInterface>> {
    log_request_data(&request);

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(file!(), line!(), "begin create dpa", e))
    })?;

    let new_dpa = NewDpaInterface::try_from(request.into_inner())?
        .persist(&mut txn)
        .await
        .map_err(CarbideError::from)?;

    let dpa_out: rpc::forge::DpaInterface = new_dpa.into();

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(file!(), line!(), "commit create_dpa", e))
    })?;

    Ok(Response::new(dpa_out))
}

pub(crate) async fn delete(
    api: &Api,
    request: Request<::rpc::forge::DpaInterfaceDeletionRequest>,
) -> CarbideResult<Response<::rpc::forge::DpaInterfaceDeletionResult>> {
    log_request_data(&request);

    let req = request.into_inner();

    let rpc_id = match req.id {
        Some(id) => id,
        None => {
            return Err(CarbideError::InvalidArgument(
                "at least one ID must be provided to delete dpa interface".to_string(),
            ));
        }
    };

    let id = DpaInterfaceId::try_from(&rpc_id)?;

    // Prepare our txn to grab the NetworkSecurityGroups from the DB
    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin delete dpa interface",
            e,
        ))
    })?;

    let dpa_ifs_int = DpaInterface::find_by_ids(&mut txn, &[id], false).await?;

    let dpa_if_int = match dpa_ifs_int.len() {
        1 => dpa_ifs_int[0].clone(),
        _ => {
            return Err(CarbideError::InvalidArgument(
                "ID could not be used to locate interface".to_string(),
            ));
        }
    };

    dpa_if_int.delete(&mut txn).await?;

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(file!(), line!(), "commit delete dpa", e))
    })?;

    Ok(Response::new(::rpc::forge::DpaInterfaceDeletionResult {}))
}

pub(crate) async fn get_all_ids(
    api: &Api,
    request: Request<()>,
) -> CarbideResult<Response<::rpc::forge::DpaInterfaceIdList>> {
    log_request_data(&request);

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin dpa get_all_ids",
            e,
        ))
    })?;

    let dpa_ids = DpaInterface::find_ids(&mut txn).await?;

    Ok(Response::new(::rpc::forge::DpaInterfaceIdList {
        ids: dpa_ids
            .into_iter()
            .map(|id| ::rpc::common::Uuid {
                value: id.to_string(),
            })
            .collect(),
    }))
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

    // Convert the IDs in the request to a list of DpaInterfaceId
    // we can send to the DB.
    let dpa_ids = req
        .ids
        .iter()
        .map(|id| {
            DpaInterfaceId::try_from(id).map_err(|_| {
                CarbideError::from(RpcDataConversionError::InvalidNetworkSegmentId(
                    id.value.to_string(),
                ))
            })
        })
        .collect::<Result<Vec<DpaInterfaceId>, CarbideError>>()?;

    // Prepare our txn to grab the NetworkSecurityGroups from the DB
    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin find_dpa_interfaces_by_ids",
            e,
        ))
    })?;

    let dpa_ifs_int = DpaInterface::find_by_ids(&mut txn, &dpa_ids, req.include_history).await?;

    let rpc_dpa_ifs = dpa_ifs_int
        .into_iter()
        .map(|i| i.into())
        .collect::<Vec<rpc::forge::DpaInterface>>();

    // Commit if nothing has gone wrong up to now
    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit find_dpa_interfaces_by_ids",
            e,
        ))
    })?;

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

    let rpc_id = match req.id {
        Some(id) => id,
        None => {
            return Err(CarbideError::InvalidArgument(
                "at least one ID must be provided to find_dpa_interfaces_by_ids".to_string(),
            ));
        }
    };

    let id = DpaInterfaceId::try_from(&rpc_id)?;

    // Prepare our txn to grab the NetworkSecurityGroups from the DB
    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin find_dpa_interfaces_by_ids",
            e,
        ))
    })?;

    let dpa_ifs_int = DpaInterface::find_by_ids(&mut txn, &[id], false).await?;

    if dpa_ifs_int.len() != 1 {
        return Err(CarbideError::InvalidArgument(
            "ID could not be used to locate interface".to_string(),
        ));
    }

    let mut dpa_if_int = dpa_ifs_int[0].clone();

    dpa_if_int.update_network_observation(&mut txn).await?;

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(file!(), line!(), "commit create_dpa", e))
    })?;

    Ok(Response::new(dpa_if_int.into()))
}
