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

use ::rpc::protos::mlx_device::{
    MlxDeviceReport as MlxDeviceReportPb, PublishMlxDeviceReportRequest,
    PublishMlxDeviceReportResponse, PublishMlxObservationReportRequest,
    PublishMlxObservationReportResponse,
};
use carbide_uuid::machine::MachineId;
use mlxconfig_device::discovery;
use mlxconfig_device::report::MlxDeviceReport;
use mlxconfig_lockdown::{LockStatus, LockdownManager, MlxResult, StatusReport};
use mlxconfig_profile::MlxProfileError;
use mlxconfig_profile::serialization::SerializableProfile;
use mlxconfig_registry::registries;
use mlxconfig_runner::{ComparisonResult, MlxConfigRunner, SyncResult};
use rpc::protos::mlx_device as mlx_device_pb;
use scout::CarbideClientResult;

use crate::cfg::Options;
use crate::client;

// create_device_report_request is a one stop shop to collect
// Mellanox device data from the machine, create a report, convert
// it into the underlying protobuf type, and then return a request
// instance to publish to carbide-api.
pub fn create_device_report_request(
    machine_id: MachineId,
) -> Result<PublishMlxDeviceReportRequest, String> {
    tracing::info!("creating PublishMlxDeviceReportRequest");
    let mut report = MlxDeviceReport::new().collect()?;
    report.machine_id = Some(machine_id);
    let report_pb: MlxDeviceReportPb = report.into();
    Ok(PublishMlxDeviceReportRequest {
        report: Some(report_pb),
    })
}

// publish_mlx_device_report is used to publish an MlxDeviceReport for the current
// machine, which will collect the hardware + firmware/version details of all Mellanox
// devices on the machine, including DPUs and DPAs. This is then published to carbide-api,
// which leverages this data for ensuring devices are synced with the correct mlxconfig
// settings, and have been (or will be instructed to) updated to the correct firmware version.
//
// When called from scout on a host, a report will contain *all* Mellanox devices on the host.
// When called from the agent on a DPU, a report will contain *only* the DPU its being called from.
pub async fn publish_mlx_device_report(
    config: &Options,
    req: PublishMlxDeviceReportRequest,
) -> CarbideClientResult<PublishMlxDeviceReportResponse> {
    tracing::info!("sending PublishMlxDeviceReportRequest: {req:?}");
    let request = tonic::Request::new(req);
    let mut client = client::create_forge_client(config).await?;
    let response = client
        .publish_mlx_device_report(request)
        .await?
        .into_inner();
    Ok(response)
}

pub async fn publish_mlx_observation_report(
    config: &Options,
    req: PublishMlxObservationReportRequest,
) -> CarbideClientResult<PublishMlxObservationReportResponse> {
    tracing::info!("sending PublishMlxObservationReportRequest: {req:?}");
    let request = tonic::Request::new(req);
    let mut client = client::create_forge_client(config).await?;
    let response = client
        .publish_mlx_observation_report(request)
        .await?
        .into_inner();
    Ok(response)
}

// lock_device locks a device with a provided key. The device_address
// can either be a PCI address, or a /dev/mst/* path. Generally when
// going through the automation, we'll end up using whatever comes in
// via the mlx device reports, with the device info coming from
// mlxfwmanager, so if mst is running, it will probably be an mst path.
// BUT, even if mst is running, you can still provide a PCI address.
pub fn lock_device(device_address: &str, key: &str) -> MlxResult<()> {
    let manager = LockdownManager::new()?;
    manager.lock_device(device_address, key)?;
    Ok(())
}

// unlock_device unlocks a device with a provided key. See above comments
// in lock_device about the device_address argument formatting options.
pub fn unlock_device(device_address: &str, key: &str) -> MlxResult<()> {
    let manager = LockdownManager::new()?;
    manager.unlock_device(device_address, key)?;
    Ok(())
}

// device_lockdown_status returns the current lockdown status of
// a device (locked or unlocked). See above comments in lock_device
// about the device_address argument formatting options.
#[allow(dead_code)]
pub fn device_lockdown_status(device_address: &str) -> MlxResult<LockStatus> {
    let manager = LockdownManager::new()?;
    let status = manager.get_status(device_address)?;
    Ok(status)
}

pub fn handle_profile_sync(
    request: mlx_device_pb::MlxDeviceProfileSyncRequest,
) -> mlx_device_pb::MlxDeviceProfileSyncResponse {
    tracing::info!(
        "[scout_stream::mlx_device] profile sync to device requested (device_id:{}, profile_name:{})",
        request.device_id,
        request.profile_name
    );

    let Some(serializable_profile_pb) = request.serializable_profile else {
        return mlx_device_pb::MlxDeviceProfileSyncResponse {
            reply: Some(
                mlx_device_pb::mlx_device_profile_sync_response::Reply::Error(
                    mlx_device_pb::MlxDeviceStreamError {
                        status: mlx_device_pb::MlxDeviceStreamErrorStatus::Internal.into(),
                        message: "no serializable profile data in message".into(),
                    },
                ),
            ),
        };
    };

    let serializable_profile: SerializableProfile = match serializable_profile_pb.try_into() {
        Ok(profile) => profile,
        Err(e) => {
            tracing::error!("[scout_stream::mlx_device] failed to parse profile: {e}");
            return mlx_device_pb::MlxDeviceProfileSyncResponse {
                reply: Some(
                    mlx_device_pb::mlx_device_profile_sync_response::Reply::Error(
                        mlx_device_pb::MlxDeviceStreamError {
                            status: mlx_device_pb::MlxDeviceStreamErrorStatus::Internal.into(),
                            message: format!("failed to parse profile: {e}"),
                        },
                    ),
                ),
            };
        }
    };

    match load_and_sync_profile(&request.device_id, serializable_profile) {
        Ok(sync_result) => {
            tracing::info!(
                "[scout_stream::mlx_device] profile sync to device successful (device_id:{}, profile_name:{})",
                request.device_id,
                request.profile_name
            );

            match sync_result.try_into() {
                Ok(sync_result_pb) => mlx_device_pb::MlxDeviceProfileSyncResponse {
                    reply: Some(
                        mlx_device_pb::mlx_device_profile_sync_response::Reply::SyncResult(
                            sync_result_pb,
                        ),
                    ),
                },
                Err(e) => {
                    tracing::error!(
                        "[scout_stream::mlx_device] profile sync result failed to serialize: {e}"
                    );
                    mlx_device_pb::MlxDeviceProfileSyncResponse {
                        reply: Some(
                            mlx_device_pb::mlx_device_profile_sync_response::Reply::Error(
                                mlx_device_pb::MlxDeviceStreamError {
                                    status: mlx_device_pb::MlxDeviceStreamErrorStatus::Internal
                                        .into(),
                                    message: format!("failed to serialize sync result: {e}"),
                                },
                            ),
                        ),
                    }
                }
            }
        }
        Err(e) => {
            tracing::error!(
                "[scout_stream::mlx_device] profile sync to device failed (device_id:{}, profile_name:{}): {e}",
                request.device_id,
                request.profile_name
            );
            mlx_device_pb::MlxDeviceProfileSyncResponse {
                reply: Some(
                    mlx_device_pb::mlx_device_profile_sync_response::Reply::Error(
                        mlx_device_pb::MlxDeviceStreamError {
                            status: mlx_device_pb::MlxDeviceStreamErrorStatus::Internal.into(),
                            message: format!("sync to device failed: {e}"),
                        },
                    ),
                ),
            }
        }
    }
}

pub fn handle_profile_compare(
    request: mlx_device_pb::MlxDeviceProfileCompareRequest,
) -> mlx_device_pb::MlxDeviceProfileCompareResponse {
    tracing::info!(
        "[scout_stream::mlx_device] profile compare against device requested (device_id:{}, profile_name:{})",
        request.device_id,
        request.profile_name
    );

    let Some(serializable_profile_pb) = request.serializable_profile else {
        return mlx_device_pb::MlxDeviceProfileCompareResponse {
            reply: Some(
                mlx_device_pb::mlx_device_profile_compare_response::Reply::Error(
                    mlx_device_pb::MlxDeviceStreamError {
                        status: mlx_device_pb::MlxDeviceStreamErrorStatus::Internal.into(),
                        message: "no serializable profile data in message".into(),
                    },
                ),
            ),
        };
    };

    let serializable_profile: SerializableProfile = match serializable_profile_pb.try_into() {
        Ok(profile) => profile,
        Err(e) => {
            tracing::error!("[scout_stream::mlx_device] failed to parse profile: {e}");
            return mlx_device_pb::MlxDeviceProfileCompareResponse {
                reply: Some(
                    mlx_device_pb::mlx_device_profile_compare_response::Reply::Error(
                        mlx_device_pb::MlxDeviceStreamError {
                            status: mlx_device_pb::MlxDeviceStreamErrorStatus::Internal.into(),
                            message: format!("failed to parse profile: {e}"),
                        },
                    ),
                ),
            };
        }
    };

    match load_and_compare_profile(&request.device_id, serializable_profile) {
        Ok(comparison_result) => {
            tracing::info!(
                "[scout_stream::mlx_device] profile compare against device successful (device_id:{}, profile_name:{})",
                request.device_id,
                request.profile_name
            );

            match comparison_result.try_into() {
                Ok(comparison_result_pb) => mlx_device_pb::MlxDeviceProfileCompareResponse {
                    reply: Some(
                        mlx_device_pb::mlx_device_profile_compare_response::Reply::ComparisonResult(
                            comparison_result_pb,
                        ),
                    ),
                },
                Err(e) => {
                    tracing::error!(
                        "[scout_stream::mlx_device] profile compare result failed to serialize: {e}"
                    );
                    mlx_device_pb::MlxDeviceProfileCompareResponse {
                        reply: Some(
                            mlx_device_pb::mlx_device_profile_compare_response::Reply::Error(
                                mlx_device_pb::MlxDeviceStreamError {
                                    status: mlx_device_pb::MlxDeviceStreamErrorStatus::Internal
                                        .into(),
                                    message: format!("failed to serialize compare result: {e}"),
                                },
                            ),
                        ),
                    }
                }
            }
        }
        Err(e) => {
            tracing::error!(
                "[scout_stream::mlx_device] profile compare against device failed (device_id:{}, profile_name:{}): {e}",
                request.device_id,
                request.profile_name
            );
            mlx_device_pb::MlxDeviceProfileCompareResponse {
                reply: Some(
                    mlx_device_pb::mlx_device_profile_compare_response::Reply::Error(
                        mlx_device_pb::MlxDeviceStreamError {
                            status: mlx_device_pb::MlxDeviceStreamErrorStatus::Internal.into(),
                            message: format!("compare against device failed: {e}"),
                        },
                    ),
                ),
            }
        }
    }
}

// handle_lockdown_lock locks a device.
pub fn handle_lockdown_lock(
    request: mlx_device_pb::MlxDeviceLockdownLockRequest,
) -> mlx_device_pb::MlxDeviceLockdownResponse {
    tracing::info!(
        "[scout_stream::mlx_device] lockdown lock requested (device_id:{})",
        request.device_id
    );

    let manager = match LockdownManager::new() {
        Ok(m) => m,
        Err(e) => {
            tracing::error!(
                "[scout_stream::mlx_device] lockdown manager initialization failed: {e}"
            );
            return mlx_device_pb::MlxDeviceLockdownResponse {
                reply: Some(mlx_device_pb::mlx_device_lockdown_response::Reply::Error(
                    mlx_device_pb::MlxDeviceStreamError {
                        status: mlx_device_pb::MlxDeviceStreamErrorStatus::Internal.into(),
                        message: e.to_string(),
                    },
                )),
            };
        }
    };

    match manager.lock_device(&request.device_id, &request.key) {
        Ok(status) => {
            tracing::info!(
                "[scout_stream::mlx_device] lockdown lock successful (device_id:{}, status:{status})",
                request.device_id
            );
            let report = StatusReport::new(request.device_id.clone(), status);
            mlx_device_pb::MlxDeviceLockdownResponse {
                reply: Some(
                    mlx_device_pb::mlx_device_lockdown_response::Reply::StatusReport(report.into()),
                ),
            }
        }
        Err(e) => {
            tracing::error!(
                "[scout_stream::mlx_device] lockdown lock failed (device_id:{}): {e}",
                request.device_id
            );
            mlx_device_pb::MlxDeviceLockdownResponse {
                reply: Some(mlx_device_pb::mlx_device_lockdown_response::Reply::Error(
                    mlx_device_pb::MlxDeviceStreamError {
                        status: mlx_device_pb::MlxDeviceStreamErrorStatus::Internal.into(),
                        message: format!("lockdown lock failed: {e}"),
                    },
                )),
            }
        }
    }
}

// handle_lockdown_unlock unlocks a device.
pub fn handle_lockdown_unlock(
    request: mlx_device_pb::MlxDeviceLockdownUnlockRequest,
) -> mlx_device_pb::MlxDeviceLockdownResponse {
    tracing::info!(
        "[scout_stream::mlx_device] lockdown unlock requested (device_id:{})",
        request.device_id
    );

    let manager = match LockdownManager::new() {
        Ok(m) => m,
        Err(e) => {
            tracing::error!(
                "[scout_stream::mlx_device] lockdown manager initialization failed: {e}"
            );
            return mlx_device_pb::MlxDeviceLockdownResponse {
                reply: Some(mlx_device_pb::mlx_device_lockdown_response::Reply::Error(
                    mlx_device_pb::MlxDeviceStreamError {
                        status: mlx_device_pb::MlxDeviceStreamErrorStatus::Internal.into(),
                        message: format!("lockdown manager init failed: {e}"),
                    },
                )),
            };
        }
    };

    match manager.unlock_device(&request.device_id, &request.key) {
        Ok(status) => {
            tracing::info!(
                "[scout_stream::mlx_device] lockdown unlock successful (device_id:{}, status:{status})",
                request.device_id
            );
            let report = StatusReport::new(request.device_id.clone(), status);
            mlx_device_pb::MlxDeviceLockdownResponse {
                reply: Some(
                    mlx_device_pb::mlx_device_lockdown_response::Reply::StatusReport(report.into()),
                ),
            }
        }
        Err(e) => {
            tracing::error!(
                "[scout_stream::mlx_device] lockdown unlock failed (device_id:{}): {e}",
                request.device_id
            );
            mlx_device_pb::MlxDeviceLockdownResponse {
                reply: Some(mlx_device_pb::mlx_device_lockdown_response::Reply::Error(
                    mlx_device_pb::MlxDeviceStreamError {
                        status: mlx_device_pb::MlxDeviceStreamErrorStatus::Internal.into(),
                        message: format!("lockdown unlock failed: {e}"),
                    },
                )),
            }
        }
    }
}

// handle_lockdown_status gets the lockdown status of a device.
pub fn handle_lockdown_status(
    request: mlx_device_pb::MlxDeviceLockdownStatusRequest,
) -> mlx_device_pb::MlxDeviceLockdownResponse {
    tracing::info!(
        "[scout_stream::mlx_device] lockdown status check requested (device_id:{})",
        request.device_id
    );

    let manager = match LockdownManager::new() {
        Ok(m) => m,
        Err(e) => {
            tracing::error!(
                "[scout_stream::mlx_device] lockdown manager initialization failed: {e}"
            );
            return mlx_device_pb::MlxDeviceLockdownResponse {
                reply: Some(mlx_device_pb::mlx_device_lockdown_response::Reply::Error(
                    mlx_device_pb::MlxDeviceStreamError {
                        status: mlx_device_pb::MlxDeviceStreamErrorStatus::Internal.into(),
                        message: format!("lockdown manager init failed: {e}"),
                    },
                )),
            };
        }
    };

    match manager.get_status(&request.device_id) {
        Ok(status) => {
            tracing::info!(
                "[scout_stream::mlx_device] lockdown status check successful (device_id:{}, status: {status})",
                request.device_id
            );
            let report = StatusReport::new(request.device_id.clone(), status);
            mlx_device_pb::MlxDeviceLockdownResponse {
                reply: Some(
                    mlx_device_pb::mlx_device_lockdown_response::Reply::StatusReport(report.into()),
                ),
            }
        }
        Err(e) => {
            tracing::error!(
                "[scout_stream::mlx_device] lockdown status check failed (device_id:{}): {e}",
                request.device_id
            );
            mlx_device_pb::MlxDeviceLockdownResponse {
                reply: Some(mlx_device_pb::mlx_device_lockdown_response::Reply::Error(
                    mlx_device_pb::MlxDeviceStreamError {
                        status: mlx_device_pb::MlxDeviceStreamErrorStatus::Internal.into(),
                        message: e.to_string(),
                    },
                )),
            }
        }
    }
}

pub fn handle_info_device(
    request: mlx_device_pb::MlxDeviceInfoDeviceRequest,
) -> mlx_device_pb::MlxDeviceInfoDeviceResponse {
    tracing::info!(
        "[scout_stream::mlx_device] device info request (device_id:{})",
        request.device_id
    );

    match discovery::discover_device(&request.device_id) {
        Ok(device_info) => {
            tracing::info!(
                "[scout_stream::mlx_device] device info retrieved successfully (device_id:{})",
                request.device_id
            );
            mlx_device_pb::MlxDeviceInfoDeviceResponse {
                reply: Some(
                    mlx_device_pb::mlx_device_info_device_response::Reply::DeviceInfo(
                        device_info.into(),
                    ),
                ),
            }
        }
        Err(e) => {
            tracing::error!(
                "[scout_stream::mlx_device] device info request failed (device_id:{}): {e}",
                request.device_id
            );
            mlx_device_pb::MlxDeviceInfoDeviceResponse {
                reply: Some(
                    mlx_device_pb::mlx_device_info_device_response::Reply::Error(
                        mlx_device_pb::MlxDeviceStreamError {
                            status: mlx_device_pb::MlxDeviceStreamErrorStatus::Internal.into(),
                            message: e,
                        },
                    ),
                ),
            }
        }
    }
}

pub fn handle_info_report(
    request: mlx_device_pb::MlxDeviceInfoReportRequest,
) -> mlx_device_pb::MlxDeviceInfoReportResponse {
    tracing::info!("[scout_stream::mlx_device] device report requested");

    let report = if let Some(filter_set_pb) = request.filters {
        match mlxconfig_device::filters::DeviceFilterSet::try_from(filter_set_pb) {
            Ok(filters) => MlxDeviceReport::new().with_filter_set(filters),
            Err(e) => {
                tracing::error!(
                    "[scout_stream::mlx_device] device report request failed to parse filters: {e}"
                );
                return mlx_device_pb::MlxDeviceInfoReportResponse {
                    reply: Some(
                        mlx_device_pb::mlx_device_info_report_response::Reply::Error(
                            mlx_device_pb::MlxDeviceStreamError {
                                status: mlx_device_pb::MlxDeviceStreamErrorStatus::Internal.into(),
                                message: format!("failed to parse filters: {e}"),
                            },
                        ),
                    ),
                };
            }
        }
    } else {
        MlxDeviceReport::new()
    };

    match report.collect() {
        Ok(report) => {
            tracing::info!(
                "[scout_stream::mlx_device] device report generated (device_count:{})",
                report.devices.len()
            );
            mlx_device_pb::MlxDeviceInfoReportResponse {
                reply: Some(
                    mlx_device_pb::mlx_device_info_report_response::Reply::DeviceReport(
                        report.into(),
                    ),
                ),
            }
        }
        Err(e) => {
            tracing::error!("[scout_stream::mlx_device] device report generation failed: {e}");
            mlx_device_pb::MlxDeviceInfoReportResponse {
                reply: Some(
                    mlx_device_pb::mlx_device_info_report_response::Reply::Error(
                        mlx_device_pb::MlxDeviceStreamError {
                            status: mlx_device_pb::MlxDeviceStreamErrorStatus::Internal.into(),
                            message: e,
                        },
                    ),
                ),
            }
        }
    }
}

// handle_registry_list lists all available variable registries.
pub fn handle_registry_list(
    _request: mlx_device_pb::MlxDeviceRegistryListRequest,
) -> mlx_device_pb::MlxDeviceRegistryListResponse {
    tracing::info!("[scout_stream::mlx_device] variable registry listing requested");

    let registry_names = registries::list().iter().map(|s| s.to_string()).collect();
    mlx_device_pb::MlxDeviceRegistryListResponse {
        reply: Some(
            mlx_device_pb::mlx_device_registry_list_response::Reply::RegistryListing(
                mlx_device_pb::RegistryListing { registry_names },
            ),
        ),
    }
}

// handle_registry_show returns a specific registry as JSON.
pub fn handle_registry_show(
    request: mlx_device_pb::MlxDeviceRegistryShowRequest,
) -> mlx_device_pb::MlxDeviceRegistryShowResponse {
    tracing::info!(
        "[scout_stream::mlx_device] variable registry details requested (registry_name:{})",
        request.registry_name
    );

    match registries::get(&request.registry_name) {
        Some(registry) => {
            let registry_pb = registry.clone().into();
            tracing::info!(
                "[scout_stream::mlx_device] variable registry details generated (registry_name:{})",
                request.registry_name
            );
            mlx_device_pb::MlxDeviceRegistryShowResponse {
                reply: Some(
                    mlx_device_pb::mlx_device_registry_show_response::Reply::VariableRegistry(
                        registry_pb,
                    ),
                ),
            }
        }
        None => {
            tracing::error!(
                "[scout_stream::mlx_device] variable registry not found (registry_name:{})",
                request.registry_name
            );
            mlx_device_pb::MlxDeviceRegistryShowResponse {
                reply: Some(
                    mlx_device_pb::mlx_device_registry_show_response::Reply::Error(
                        mlx_device_pb::MlxDeviceStreamError {
                            status: mlx_device_pb::MlxDeviceStreamErrorStatus::Internal.into(),
                            message: format!("registry not found: {}", request.registry_name),
                        },
                    ),
                ),
            }
        }
    }
}

// handle_config_query queries one or more device variables against
// a given variable registry.
pub fn handle_config_query(
    request: mlx_device_pb::MlxDeviceConfigQueryRequest,
) -> mlx_device_pb::MlxDeviceConfigQueryResponse {
    tracing::info!(
        "[scout_stream::mlx_device] config query requested (device_id:{}, registry_name:{}): {:?}",
        request.device_id,
        request.registry_name,
        request.variables,
    );

    let registry = match registries::get(&request.registry_name) {
        Some(r) => r.clone(),
        None => {
            tracing::warn!(
                "[scout_stream::mlx_device] config registry not found (device_id:{}, registry_name:{})",
                request.device_id,
                request.registry_name,
            );
            return mlx_device_pb::MlxDeviceConfigQueryResponse {
                reply: Some(
                    mlx_device_pb::mlx_device_config_query_response::Reply::Error(
                        mlx_device_pb::MlxDeviceStreamError {
                            status: mlx_device_pb::MlxDeviceStreamErrorStatus::Internal.into(),
                            message: format!(
                                "config registry not found (device_id:{}, registry_name:{})",
                                request.device_id, request.registry_name
                            ),
                        },
                    ),
                ),
            };
        }
    };

    // Now initialize a new mlxconfig runner and query for
    // either all, or some, variables, depending on what was
    // requested by the caller.
    let runner = MlxConfigRunner::new(request.device_id.clone(), registry);
    let result = if request.variables.is_empty() {
        runner.query_all()
    } else {
        runner.query(request.variables.as_slice())
    };

    match result {
        Ok(query_result) => {
            tracing::info!(
                "[scout_stream::mlx_device] config query against device successful (device_id:{}, registry_name:{})",
                request.device_id,
                request.registry_name,
            );

            match query_result.try_into() {
                Ok(query_result_pb) => mlx_device_pb::MlxDeviceConfigQueryResponse {
                    reply: Some(
                        mlx_device_pb::mlx_device_config_query_response::Reply::QueryResult(
                            query_result_pb,
                        ),
                    ),
                },
                Err(e) => {
                    tracing::error!(
                        "[scout_stream::mlx_device] config query result failed to serialize (device_id:{}, registry_name:{}): {e}",
                        request.device_id,
                        request.registry_name
                    );
                    mlx_device_pb::MlxDeviceConfigQueryResponse {
                        reply: Some(
                            mlx_device_pb::mlx_device_config_query_response::Reply::Error(
                                mlx_device_pb::MlxDeviceStreamError {
                                    status: mlx_device_pb::MlxDeviceStreamErrorStatus::Internal
                                        .into(),
                                    message: format!(
                                        "failed to serialize query result (device_id:{}, registry_name:{}): {e}",
                                        request.device_id, request.registry_name
                                    ),
                                },
                            ),
                        ),
                    }
                }
            }
        }
        Err(e) => {
            tracing::error!(
                "[scout_stream::mlx_device] config query against device failed (device_id:{}, registry_name:{}): {e}",
                request.device_id,
                request.registry_name
            );
            mlx_device_pb::MlxDeviceConfigQueryResponse {
                reply: Some(
                    mlx_device_pb::mlx_device_config_query_response::Reply::Error(
                        mlx_device_pb::MlxDeviceStreamError {
                            status: mlx_device_pb::MlxDeviceStreamErrorStatus::Internal.into(),
                            message: format!(
                                "config query against device failed (device_id:{}, registry_name:{}): {e}",
                                request.device_id, request.registry_name
                            ),
                        },
                    ),
                ),
            }
        }
    }
}

// handle_config_set sets device variables.
pub fn handle_config_set(
    request: mlx_device_pb::MlxDeviceConfigSetRequest,
) -> mlx_device_pb::MlxDeviceConfigSetResponse {
    tracing::info!(
        "[scout_stream::mlx_device] config set assignment requested (device_id:{}, registry_name:{}): {:?}",
        request.device_id,
        request.registry_name,
        request.assignments
    );

    let registry = match registries::get(&request.registry_name) {
        Some(r) => r.clone(),
        None => {
            tracing::warn!(
                "[scout_stream::mlx_device] config registry not found (device_id:{}, registry_name:{})",
                request.device_id,
                request.registry_name,
            );
            return mlx_device_pb::MlxDeviceConfigSetResponse {
                reply: Some(mlx_device_pb::mlx_device_config_set_response::Reply::Error(
                    mlx_device_pb::MlxDeviceStreamError {
                        status: mlx_device_pb::MlxDeviceStreamErrorStatus::Internal.into(),
                        message: format!(
                            "config registry not found (device_id:{}, registry_name:{})",
                            request.device_id, request.registry_name
                        ),
                    },
                )),
            };
        }
    };

    let runner = MlxConfigRunner::new(request.device_id.clone(), registry);

    // Convert "assignments" from the proto to (String, String) tuples,
    // which are natively handled by a bunch of from impls that exist
    // for the runner.
    let assignments: Vec<(String, String)> = request
        .assignments
        .into_iter()
        .map(|a| (a.variable_name, a.value))
        .collect();

    let total_applied = assignments.len() as u32;

    match runner.set(assignments) {
        Ok(_) => {
            tracing::info!(
                "[scout_stream::mlx_device] config set on device successfully (device_id:{}, registry_name:{})",
                request.device_id,
                request.registry_name,
            );
            mlx_device_pb::MlxDeviceConfigSetResponse {
                reply: Some(
                    mlx_device_pb::mlx_device_config_set_response::Reply::TotalApplied(
                        total_applied,
                    ),
                ),
            }
        }
        Err(e) => {
            tracing::error!(
                "[scout_stream::mlx_device] config set to device failed (device_id:{}, registry_name:{}): {e}",
                request.device_id,
                request.registry_name,
            );
            mlx_device_pb::MlxDeviceConfigSetResponse {
                reply: Some(mlx_device_pb::mlx_device_config_set_response::Reply::Error(
                    mlx_device_pb::MlxDeviceStreamError {
                        status: mlx_device_pb::MlxDeviceStreamErrorStatus::Internal.into(),
                        message: format!(
                            "config set to device failed (device_id:{}, registry_name:{}): {e}",
                            request.device_id, request.registry_name,
                        ),
                    },
                )),
            }
        }
    }
}

// handle_config_sync syncs device variables, only changing variables
// that differ from the observed values.
pub fn handle_config_sync(
    request: mlx_device_pb::MlxDeviceConfigSyncRequest,
) -> mlx_device_pb::MlxDeviceConfigSyncResponse {
    tracing::info!(
        "[scout_stream::mlx_device] config sync requested (device_id:{}, registry_name:{}): {:?}",
        request.device_id,
        request.registry_name,
        request.assignments
    );

    let registry = match registries::get(&request.registry_name) {
        Some(r) => r.clone(),
        None => {
            tracing::warn!(
                "[scout_stream::mlx_device] config registry not found (device_id:{}, registry_name:{})",
                request.device_id,
                request.registry_name,
            );
            return mlx_device_pb::MlxDeviceConfigSyncResponse {
                reply: Some(
                    mlx_device_pb::mlx_device_config_sync_response::Reply::Error(
                        mlx_device_pb::MlxDeviceStreamError {
                            status: mlx_device_pb::MlxDeviceStreamErrorStatus::Internal.into(),
                            message: format!(
                                "config registry not found (device_id:{}, registry_name:{})",
                                request.device_id, request.registry_name
                            ),
                        },
                    ),
                ),
            };
        }
    };

    let runner = MlxConfigRunner::new(request.device_id.clone(), registry);

    // Convert "assignments" from the proto to (String, String) tuples,
    // which are natively handled by a bunch of from impls that exist
    // for the runner.
    let assignments: Vec<(String, String)> = request
        .assignments
        .into_iter()
        .map(|a| (a.variable_name, a.value))
        .collect();

    match runner.sync(assignments) {
        Ok(sync_result) => {
            tracing::info!(
                "[scout_stream::mlx_device] config sync to device successful (device_id:{}, registry_name:{})",
                request.device_id,
                request.registry_name,
            );

            match sync_result.try_into() {
                Ok(sync_result_pb) => mlx_device_pb::MlxDeviceConfigSyncResponse {
                    reply: Some(
                        mlx_device_pb::mlx_device_config_sync_response::Reply::SyncResult(
                            sync_result_pb,
                        ),
                    ),
                },
                Err(e) => {
                    tracing::error!(
                        "[scout_stream::mlx_device] config sync result failed to serialize (device_id:{}, registry_name:{}): {e}",
                        request.device_id,
                        request.registry_name,
                    );
                    mlx_device_pb::MlxDeviceConfigSyncResponse {
                        reply: Some(
                            mlx_device_pb::mlx_device_config_sync_response::Reply::Error(
                                mlx_device_pb::MlxDeviceStreamError {
                                    status: mlx_device_pb::MlxDeviceStreamErrorStatus::Internal
                                        .into(),
                                    message: format!(
                                        "failed to serialize sync result (device_id:{}, registry_name:{}): {e}",
                                        request.device_id, request.registry_name,
                                    ),
                                },
                            ),
                        ),
                    }
                }
            }
        }
        Err(e) => {
            tracing::error!(
                "[scout_stream::mlx_device] config sync to device failed (device_id:{}, registry_name:{}): {e}",
                request.device_id,
                request.registry_name,
            );
            mlx_device_pb::MlxDeviceConfigSyncResponse {
                reply: Some(
                    mlx_device_pb::mlx_device_config_sync_response::Reply::Error(
                        mlx_device_pb::MlxDeviceStreamError {
                            status: mlx_device_pb::MlxDeviceStreamErrorStatus::Internal.into(),
                            message: format!(
                                "config sync to device failed (device_id:{}, registry_name:{}): {e}",
                                request.device_id, request.registry_name,
                            ),
                        },
                    ),
                ),
            }
        }
    }
}

// handle_config_compare compares requested variable assignments
// against the current assignments on the device.
pub fn handle_config_compare(
    request: mlx_device_pb::MlxDeviceConfigCompareRequest,
) -> mlx_device_pb::MlxDeviceConfigCompareResponse {
    tracing::info!(
        "[scout_stream::mlx_device] config compare requested (device_id:{}, registry_name:{}): {:?}",
        request.device_id,
        request.registry_name,
        request.assignments
    );

    let registry = match registries::get(&request.registry_name) {
        Some(r) => r.clone(),
        None => {
            tracing::warn!(
                "[scout_stream::mlx_device] config registry not found (device_id:{}, registry_name:{})",
                request.device_id,
                request.registry_name,
            );
            return mlx_device_pb::MlxDeviceConfigCompareResponse {
                reply: Some(
                    mlx_device_pb::mlx_device_config_compare_response::Reply::Error(
                        mlx_device_pb::MlxDeviceStreamError {
                            status: mlx_device_pb::MlxDeviceStreamErrorStatus::Internal.into(),
                            message: format!(
                                "config registry not found (device_id:{}, registry_name:{})",
                                request.device_id, request.registry_name
                            ),
                        },
                    ),
                ),
            };
        }
    };

    let runner = MlxConfigRunner::new(request.device_id.clone(), registry);

    // Convert "assignments" from the proto to (String, String) tuples,
    // which are natively handled by a bunch of from impls that exist
    // for the runner.
    let assignments: Vec<(String, String)> = request
        .assignments
        .into_iter()
        .map(|a| (a.variable_name, a.value))
        .collect();

    match runner.compare(assignments) {
        Ok(comparison_result) => {
            tracing::info!(
                "[scout_stream::mlx_device] config compare against device successful (device_id:{}, registry_name:{})",
                request.device_id,
                request.registry_name,
            );

            match comparison_result.try_into() {
                Ok(comparison_result_pb) => mlx_device_pb::MlxDeviceConfigCompareResponse {
                    reply: Some(
                        mlx_device_pb::mlx_device_config_compare_response::Reply::ComparisonResult(
                            comparison_result_pb,
                        ),
                    ),
                },
                Err(e) => {
                    tracing::error!(
                        "[scout_stream::mlx_device] config compare result failed to serialize (device_id:{}, registry_name:{}): {e}",
                        request.device_id,
                        request.registry_name
                    );
                    mlx_device_pb::MlxDeviceConfigCompareResponse {
                        reply: Some(
                            mlx_device_pb::mlx_device_config_compare_response::Reply::Error(
                                mlx_device_pb::MlxDeviceStreamError {
                                    status: mlx_device_pb::MlxDeviceStreamErrorStatus::Internal
                                        .into(),
                                    message: format!(
                                        "failed to serialize config compare result (device_id:{}, registry_name:{}): {e}",
                                        request.device_id, request.registry_name
                                    ),
                                },
                            ),
                        ),
                    }
                }
            }
        }
        Err(e) => {
            tracing::error!(
                "[scout_stream::mlx_device] config compare against device failed (device_id:{}, registry_name:{}): {e}",
                request.device_id,
                request.registry_name
            );
            mlx_device_pb::MlxDeviceConfigCompareResponse {
                reply: Some(
                    mlx_device_pb::mlx_device_config_compare_response::Reply::Error(
                        mlx_device_pb::MlxDeviceStreamError {
                            status: mlx_device_pb::MlxDeviceStreamErrorStatus::Internal.into(),
                            message: format!(
                                "config compare against device failed (device_id:{}, registry_name:{}): {e}",
                                request.device_id, request.registry_name
                            ),
                        },
                    ),
                ),
            }
        }
    }
}

// load_and_sync_profile loads a profile from data and syncs it to the device.
fn load_and_sync_profile(
    device_id: &str,
    serializable_profile: SerializableProfile,
) -> Result<SyncResult, MlxProfileError> {
    let profile = serializable_profile.into_profile()?;
    profile.sync(device_id, None)
}

// load_and_compare_profile is a helper function to load and compare a profile.
fn load_and_compare_profile(
    device_id: &str,
    serializable_profile: SerializableProfile,
) -> Result<ComparisonResult, Box<dyn std::error::Error>> {
    let profile = serializable_profile.into_profile()?;
    let comparison_result = profile.compare(device_id, None)?;
    Ok(comparison_result)
}
