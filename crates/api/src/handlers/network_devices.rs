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
use ::rpc::forge as rpc;
use db::network_devices::NetworkDeviceSearchConfig;
use db::{ObjectFilter, WithTransaction};
use futures_util::FutureExt;
use itertools::Itertools;
use tonic::{Request, Response, Status};

use crate::api::{Api, log_request_data};

pub(crate) async fn get_network_topology(
    api: &Api,
    request: Request<rpc::NetworkTopologyRequest>,
) -> Result<Response<rpc::NetworkTopologyData>, Status> {
    log_request_data(&request);
    let req = request.into_inner();

    let mut txn = api.txn_begin().await?;

    let query = match &req.id {
        Some(x) => ObjectFilter::One(x.as_str()),
        None => ObjectFilter::All,
    };

    let data = db::network_devices::get_topology(&mut txn, query).await?;

    txn.commit().await?;

    Ok(Response::new(data.into()))
}

pub(crate) async fn find_network_devices_by_device_ids(
    api: &Api,
    request: Request<rpc::NetworkDeviceIdList>,
) -> Result<Response<rpc::NetworkTopologyData>, Status> {
    log_request_data(&request);

    let request = request.into_inner(); // keep lifetime for this scope
    let network_device_ids: Vec<&str> = request
        .network_device_ids
        .iter()
        .map(|d| d.as_str())
        .collect();
    let search_config = NetworkDeviceSearchConfig::new(false);
    let network_devices = api
        .with_txn(|txn| {
            db::network_devices::find(txn, ObjectFilter::List(&network_device_ids), &search_config)
                .boxed()
        })
        .await??;

    Ok(Response::new(rpc::NetworkTopologyData {
        network_devices: network_devices.into_iter().map_into().collect(),
    }))
}

pub(crate) async fn find_connected_devices_by_dpu_machine_ids(
    api: &Api,
    request: Request<::rpc::common::MachineIdList>,
) -> Result<Response<rpc::ConnectedDeviceList>, Status> {
    log_request_data(&request);

    let dpu_ids = request.into_inner().machine_ids;

    let connected_devices = api
        .with_txn(|txn| {
            db::network_devices::dpu_to_network_device_map::find_by_dpu_ids(txn, &dpu_ids).boxed()
        })
        .await??;

    Ok(Response::new(rpc::ConnectedDeviceList {
        connected_devices: connected_devices.into_iter().map_into().collect(),
    }))
}
