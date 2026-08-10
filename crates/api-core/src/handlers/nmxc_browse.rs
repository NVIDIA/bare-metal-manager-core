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
use carbide_nvlink_manager::nmx_c_endpoint::{ManagedHostGroupType, resolve_nmx_c_endpoint_url};
use libnmxc::nmxc_model::{
    GetComputeNodeInfoListRequest, GetGpuInfoListRequest, GetPartitionInfoListRequest,
    GetSwitchNodeInfoListRequest, GpuAttr,
};
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

/// Calls NMX-C `GetSwitchNodeInfoList` and returns the JSON response for the NMX-C browser.
async fn switch_node_info_list_json(
    nmxc: &mut dyn Nmxc,
) -> Result<(String, i32, HashMap<String, String>), CarbideError> {
    let resp = nmxc
        .get_switch_node_info_list(GetSwitchNodeInfoListRequest {
            context: Some(Default::default()),
            loc_list: vec![],
            gateway_id: NMX_C_GATEWAY_ID.to_string(),
        })
        .await?;

    let body = serde_json::to_string(&resp).map_err(|e| {
        CarbideError::internal(format!("serialize GetSwitchNodeInfoListResponse: {e}"))
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

/// Calls NMX-C `GetPartitionInfoList` and returns the JSON response for the NMX-C browser.
async fn partition_info_list_json(
    nmxc: &mut dyn Nmxc,
) -> Result<(String, i32, HashMap<String, String>), CarbideError> {
    let resp = nmxc
        .get_partition_info_list(GetPartitionInfoListRequest {
            context: Some(Default::default()),
            partition_id_list: vec![],
            partition_name_list: vec![],
            gateway_id: NMX_C_GATEWAY_ID.into(),
        })
        .await?;

    let body = serde_json::to_string(&resp).map_err(|e| {
        CarbideError::internal(format!("serialize GetPartitionInfoListResponse: {e}"))
    })?;
    Ok((body, 200, HashMap::new()))
}

/// Calls NMX-C `GetDomainProperties` and returns the JSON response for the NMX-C browser.
async fn get_domain_properties_json(
    nmxc: &mut dyn Nmxc,
) -> Result<(String, i32, HashMap<String, String>), CarbideError> {
    let resp = nmxc
        .get_domain_properties(Some(Default::default()), NMX_C_GATEWAY_ID)
        .await?;

    let body = serde_json::to_string(&resp)
        .map_err(|e| CarbideError::internal(format!("serialize DomainProperties: {e}")))?;
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

    let rack_id = request.rack_id.as_ref();
    let group_type = resolve_group_type(&request.chassis_serial, rack_id)?;
    let chassis_serial = request.chassis_serial.trim();

    let op = rpc::NmxcBrowseOperation::try_from(request.operation)
        .unwrap_or(rpc::NmxcBrowseOperation::Unspecified);

    if let Some(nvlink_config) = api.runtime_config.nvlink_config.as_ref()
        && nvlink_config.enabled
    {
        let mut db = api.db_reader();
        let endpoint_url = resolve_nmx_c_endpoint_url(
            &mut db,
            group_type,
            rack_id,
            if chassis_serial.is_empty() {
                None
            } else {
                Some(chassis_serial)
            },
            nvlink_config,
        )
        .await?;

        let Some(url) = endpoint_url else {
            let endpoint_id = rack_id
                .map(|r| r.to_string())
                .unwrap_or_else(|| chassis_serial.to_string());
            return Err(CarbideError::NotFoundError {
                kind: "nvlink_nmxc_endpoint",
                id: endpoint_id,
            }
            .into());
        };

        let mut nmxc = api
            .nmxc_client_pool
            .create_client(Endpoint::new(url).map_err(CarbideError::from)?)
            .await
            .map_err(CarbideError::from)?;

        nmxc.hello(NMX_C_GATEWAY_ID)
            .await
            .map_err(|e| CarbideError::internal(format!("failed to call NMX-C hello: {e}")))?;

        let result = match op {
            rpc::NmxcBrowseOperation::Unspecified => Err(CarbideError::InvalidArgument(
                "operation must be set to a supported NmxcBrowseOperation".to_string(),
            )),
            rpc::NmxcBrowseOperation::ComputeNodeInfoList => {
                compute_node_info_list_json(nmxc.as_mut()).await
            }
            rpc::NmxcBrowseOperation::SwitchNodeInfoList => {
                switch_node_info_list_json(nmxc.as_mut()).await
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
            rpc::NmxcBrowseOperation::PartitionInfoList => {
                partition_info_list_json(nmxc.as_mut()).await
            }
            rpc::NmxcBrowseOperation::GetDomainProperties => {
                get_domain_properties_json(nmxc.as_mut()).await
            }
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

/// Determines the `ManagedHostGroupType` from a browse request's selector fields.
///
/// The two selectors are mutually exclusive: providing both is an `InvalidArgument` error;
/// providing neither is a `MissingArgument` error.
fn resolve_group_type(
    chassis_serial: &str,
    rack_id: Option<&carbide_uuid::rack::RackId>,
) -> Result<ManagedHostGroupType, CarbideError> {
    let chassis_serial = chassis_serial.trim();
    if rack_id.is_some() && !chassis_serial.is_empty() {
        return Err(CarbideError::InvalidArgument(
            "chassis_serial and rack_id are mutually exclusive".to_string(),
        ));
    }
    if rack_id.is_some() {
        Ok(ManagedHostGroupType::Rack)
    } else if !chassis_serial.is_empty() {
        Ok(ManagedHostGroupType::Chassis)
    } else {
        Err(CarbideError::MissingArgument("chassis_serial or rack_id"))
    }
}

#[cfg(test)]
mod tests {
    use carbide_test_support::Outcome::{FailsWith, Yields};
    use carbide_test_support::scenarios;
    use carbide_uuid::rack::RackId;

    use super::*;

    /// Mapped error discriminant so table rows can assert which validation rule fired.
    #[derive(Debug, PartialEq)]
    enum SelectionError {
        Both,
        Neither,
    }

    #[test]
    fn selector_validation_resolves_group_type_or_rejects_invalid_inputs() {
        scenarios!(run = |(chassis_serial, rack_id_str): (&str, Option<&str>)| {
            let rack_id = rack_id_str.map(RackId::new);
            resolve_group_type(chassis_serial, rack_id.as_ref()).map_err(|e| match e {
                CarbideError::InvalidArgument(_) => SelectionError::Both,
                _ => SelectionError::Neither,
            })
        };
            "rack-only" {
                ("", Some("rack-a")) => Yields(ManagedHostGroupType::Rack),
            }

            "chassis-only" {
                ("SN-123", None) => Yields(ManagedHostGroupType::Chassis),
                ("  SN-123  ", None) => Yields(ManagedHostGroupType::Chassis),
            }

            "both provided" {
                ("SN-123", Some("rack-a")) => FailsWith(SelectionError::Both),
            }

            "neither provided" {
                ("", None) => FailsWith(SelectionError::Neither),
                ("   ", None) => FailsWith(SelectionError::Neither),
            }
        );
    }
}
