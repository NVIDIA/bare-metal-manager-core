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

use std::collections::HashMap;

use ::rpc::forge as rpc;
use libnmxc::nmxc_model::{GetComputeNodeInfoListRequest, GetGpuInfoListRequest, GpuAttr};
use libnmxc::{Endpoint, NMX_C_GATEWAY_ID, Nmxc};
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::{Api, log_request_data};

async fn compute_node_info_list_json(
    nmxc: &mut dyn Nmxc,
) -> Result<(String, i32, HashMap<String, String>), CarbideError> {
    let resp = nmxc
        .get_compute_node_info_list(GetComputeNodeInfoListRequest {
            context: Some(Default::default()),
            loc_list: vec![],
            gateway_id: NMX_C_GATEWAY_ID.to_string(),
        })
        .await?;

    let body = serde_json::to_string(&resp).map_err(|e| {
        CarbideError::internal(format!("serialize GetComputeNodeInfoListResponse: {e}"))
    })?;
    Ok((body, 200, HashMap::new()))
}

async fn gpu_info_json(
    nmxc: &mut dyn Nmxc,
    uid: u64,
) -> Result<(String, i32, HashMap<String, String>), CarbideError> {
    let gresp = nmxc
        .get_gpu_info_list(GetGpuInfoListRequest {
            context: Some(Default::default()),
            attr: GpuAttr::NmxGpuAttrAll as i32,
            num_gpus: 0,
            loc: None,
            partition_id: None,
            gateway_id: NMX_C_GATEWAY_ID.to_string(),
            gpu_health: 0,
        })
        .await?;

    let Some(gpu) = gresp.gpu_info_list.iter().find(|g| g.gpu_uid == uid) else {
        return Err(CarbideError::NotFoundError {
            kind: "nmxc_gpu",
            id: uid.to_string(),
        });
    };

    let body = serde_json::to_string(gpu)
        .map_err(|e| CarbideError::internal(format!("serialize GpuInfo: {e}")))?;
    Ok((body, 200, HashMap::new()))
}

async fn gpu_info_list_json(
    nmxc: &mut dyn Nmxc,
) -> Result<(String, i32, HashMap<String, String>), CarbideError> {
    let resp = nmxc
        .get_gpu_info_list(GetGpuInfoListRequest {
            context: Some(Default::default()),
            attr: GpuAttr::NmxGpuAttrAll as i32,
            num_gpus: 0,
            loc: None,
            partition_id: None,
            gateway_id: NMX_C_GATEWAY_ID.to_string(),
            gpu_health: 0,
        })
        .await?;

    let body = serde_json::to_string(&resp)
        .map_err(|e| CarbideError::internal(format!("serialize GetGpuInfoListResponse: {e}")))?;
    Ok((body, 200, HashMap::new()))
}

pub(crate) async fn nmxc_browse(
    api: &Api,
    request: Request<rpc::NmxcBrowseRequest>,
) -> Result<Response<rpc::NmxcBrowseResponse>, Status> {
    log_request_data(&request);

    let request = request.into_inner();

    let chassis_serial = request.chassis_serial.trim();
    if chassis_serial.is_empty() {
        return Err(CarbideError::MissingArgument("chassis_serial").into());
    }

    let op = rpc::NmxcBrowseOperation::try_from(request.operation)
        .unwrap_or(rpc::NmxcBrowseOperation::Unspecified);

    if let Some(nvlink_config) = api.runtime_config.nvlink_config.as_ref()
        && nvlink_config.enabled
    {
        let endpoint_row = db::nvlink_nmxc_endpoints::find_by_chassis_serial(
            &api.database_connection,
            chassis_serial,
        )
        .await?;

        let Some(row) = endpoint_row else {
            return Err(CarbideError::NotFoundError {
                kind: "nvlink_nmxc_endpoint",
                id: chassis_serial.to_string(),
            }
            .into());
        };

        let mut nmxc = api
            .nmxc_client_pool
            .create_client(Endpoint::new(row.endpoint.clone()).map_err(CarbideError::from)?)
            .await
            .map_err(CarbideError::from)?;

        nmxc.hello(NMX_C_GATEWAY_ID)
            .await
            .map_err(|e| CarbideError::internal(format!("Failed to call NMX-C hello: {e}")))?;

        let result = match op {
            rpc::NmxcBrowseOperation::Unspecified => Err(CarbideError::InvalidArgument(
                "operation must be set to a supported NmxcBrowseOperation".to_string(),
            )),
            rpc::NmxcBrowseOperation::ComputeNodeInfoList => {
                compute_node_info_list_json(nmxc.as_mut()).await
            }
            rpc::NmxcBrowseOperation::GpuInfo => {
                if request.gpu_uid == 0 {
                    Err(CarbideError::InvalidArgument(
                        "gpu_uid is required for GPU_INFO operation".to_string(),
                    ))
                } else {
                    gpu_info_json(nmxc.as_mut(), request.gpu_uid).await
                }
            }
            rpc::NmxcBrowseOperation::GpuInfoList => gpu_info_list_json(nmxc.as_mut()).await,
        };

        match result {
            Ok((body, code, headers)) => Ok(Response::new(rpc::NmxcBrowseResponse {
                body,
                code,
                headers,
            })),
            Err(CarbideError::NotFoundError {
                kind: "nmxc_gpu",
                id,
            }) => Ok(Response::new(rpc::NmxcBrowseResponse {
                body: format!("GPU not found: {id}"),
                code: 404,
                headers: HashMap::new(),
            })),
            Err(CarbideError::InvalidArgument(msg)) => Ok(Response::new(rpc::NmxcBrowseResponse {
                body: msg,
                code: 400,
                headers: HashMap::new(),
            })),
            Err(e) => Err(e.into()),
        }
    } else {
        Err(CarbideError::internal("nvlink config not enabled".to_string()).into())
    }
}
