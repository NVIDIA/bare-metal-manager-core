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

use std::sync::Arc;

use rpc::fmds::fmds_config_service_server::FmdsConfigService;
use rpc::fmds::{UpdateConfigRequest, UpdateConfigResponse};
use tonic::{Request, Response, Status};

use crate::state::{FmdsConfig, FmdsState, IBDeviceConfig, IBInstanceConfig};

pub struct FmdsGrpcServer {
    state: Arc<FmdsState>,
}

impl FmdsGrpcServer {
    pub fn new(state: Arc<FmdsState>) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl FmdsConfigService for FmdsGrpcServer {
    async fn update_config(
        &self,
        request: Request<UpdateConfigRequest>,
    ) -> Result<Response<UpdateConfigResponse>, Status> {
        let agent_address = request
            .remote_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let update = request
            .into_inner()
            .config_update
            .ok_or_else(|| Status::invalid_argument("missing config_update"))?;

        let ib_devices = if update.ib_devices.is_empty() {
            None
        } else {
            Some(
                update
                    .ib_devices
                    .into_iter()
                    .map(|dev| IBDeviceConfig {
                        pf_guid: dev.pf_guid,
                        instances: dev
                            .instances
                            .into_iter()
                            .map(|inst| IBInstanceConfig {
                                ib_partition_id: inst
                                    .ib_partition_id
                                    .and_then(|id| id.parse().ok()),
                                ib_guid: inst.ib_guid,
                                lid: inst.lid,
                            })
                            .collect(),
                    })
                    .collect(),
            )
        };

        let config = FmdsConfig {
            address: update.address,
            hostname: update.hostname,
            sitename: update.sitename,
            instance_id: update.instance_id,
            machine_id: update.machine_id,
            user_data: update.user_data,
            ib_devices,
            asn: update.asn,
        };

        self.state.update_config(config);

        tracing::info!(agent_address, "Received config update from agent");

        Ok(Response::new(UpdateConfigResponse {}))
    }
}

#[cfg(test)]
mod tests {
    use rpc::fmds::{FmdsConfigUpdate, IbDevice, IbInstance};

    use super::*;

    fn make_test_state() -> Arc<FmdsState> {
        Arc::new(FmdsState::new("https://api.test".to_string(), None))
    }

    fn make_test_update() -> FmdsConfigUpdate {
        FmdsConfigUpdate {
            address: "10.0.0.1".to_string(),
            hostname: "test-host".to_string(),
            sitename: Some("test-site".to_string()),
            instance_id: Some(uuid::uuid!("67e55044-10b1-426f-9247-bb680e5fe0c8").into()),
            machine_id: Some(
                "fm100ht6n80e7do39u8gmt7cvhm89pb32st9ngevgdolu542l1nfa4an0rg"
                    .parse()
                    .unwrap(),
            ),
            user_data: "cloud-init-data".to_string(),
            ib_devices: vec![],
            asn: 65000,
        }
    }

    #[tokio::test]
    async fn test_update_config_stores_data() {
        let state = make_test_state();
        let server = FmdsGrpcServer::new(state.clone());

        let request = Request::new(UpdateConfigRequest {
            config_update: Some(make_test_update()),
        });

        let response = server.update_config(request).await;
        assert!(response.is_ok());

        let config = state.config.load_full().unwrap();
        assert_eq!(config.address, "10.0.0.1");
        assert_eq!(config.hostname, "test-host");
        assert_eq!(config.sitename.as_deref(), Some("test-site"));
        assert_eq!(config.asn, 65000);
    }

    #[tokio::test]
    async fn test_update_config_missing_config_update() {
        let state = make_test_state();
        let server = FmdsGrpcServer::new(state);

        let request = Request::new(UpdateConfigRequest {
            config_update: None,
        });

        let response = server.update_config(request).await;
        assert!(response.is_err());
        assert_eq!(response.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn test_update_config_with_ib_devices() {
        let state = make_test_state();
        let server = FmdsGrpcServer::new(state.clone());

        let mut update = make_test_update();
        update.ib_devices = vec![IbDevice {
            pf_guid: "pfguid1".to_string(),
            instances: vec![
                IbInstance {
                    ib_partition_id: Some("67e55044-10b1-426f-9247-bb680e5fe0c8".to_string()),
                    ib_guid: Some("guid1".to_string()),
                    lid: 42,
                },
                IbInstance {
                    ib_partition_id: None,
                    ib_guid: Some("guid2".to_string()),
                    lid: 43,
                },
            ],
        }];

        let request = Request::new(UpdateConfigRequest {
            config_update: Some(update),
        });

        server.update_config(request).await.unwrap();

        let config = state.config.load_full().unwrap();
        let devices = config.ib_devices.as_ref().unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].pf_guid, "pfguid1");
        assert_eq!(devices[0].instances.len(), 2);
        assert_eq!(devices[0].instances[0].ib_guid.as_deref(), Some("guid1"));
        assert_eq!(devices[0].instances[0].lid, 42);
        assert!(devices[0].instances[0].ib_partition_id.is_some());
        assert!(devices[0].instances[1].ib_partition_id.is_none());
    }

    #[tokio::test]
    async fn test_update_config_empty_ib_devices_becomes_none() {
        let state = make_test_state();
        let server = FmdsGrpcServer::new(state.clone());

        let request = Request::new(UpdateConfigRequest {
            config_update: Some(make_test_update()),
        });

        server.update_config(request).await.unwrap();

        let config = state.config.load_full().unwrap();
        assert!(config.ib_devices.is_none());
    }
}
