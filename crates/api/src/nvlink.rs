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

use async_trait::async_trait;
use db::DatabaseError;
use forge_secrets::credentials::{CredentialKey, CredentialProvider, Credentials};
use libnmxm::{Nmxm, NmxmApiError};

use crate::handlers::credential::DEFAULT_NMX_M_NAME;

#[allow(dead_code)]
#[derive(thiserror::Error, Debug)]
pub enum NvLinkPartitionError {
    #[error("Failed to look up credentials {0}")]
    MissingCredentials(eyre::Report),
    #[error("Failed NMX-M api request {0}")]
    NmxmApiError(NmxmApiError),
    #[error("Database error {0}")]
    DbError(DatabaseError),
    #[error("{0}: {1} in use / busy")]
    ObjectInUse(String, String),
    #[error("Not found: {0}")]
    NotFound(String),
    #[error("Invalid arguments")]
    InvalidArguments,
    #[error("Invalid API response")]
    InvalidApiResponse,
}

#[async_trait]
pub trait NmxmClientPool: Send + Sync + 'static {
    async fn create_client(
        &self,
        endpoint: &str,
        nmxm_id: Option<String>,
    ) -> Result<Box<dyn Nmxm>, NvLinkPartitionError>;
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct NmxmClientPoolImpl<C> {
    pool: libnmxm::NmxmClientPool,
    credential_provider: Arc<C>,
}

impl<C: CredentialProvider + 'static> NmxmClientPoolImpl<C> {
    pub fn new(credential_provider: Arc<C>, pool: libnmxm::NmxmClientPool) -> Self {
        NmxmClientPoolImpl {
            credential_provider,
            pool,
        }
    }
}

#[async_trait]
impl<C: CredentialProvider + 'static> NmxmClientPool for NmxmClientPoolImpl<C> {
    async fn create_client(
        &self,
        endpoint: &str,
        nmxm_id: Option<String>,
    ) -> Result<Box<dyn Nmxm>, NvLinkPartitionError> {
        let id = nmxm_id.unwrap_or(DEFAULT_NMX_M_NAME.to_string());
        let credentials = self
            .credential_provider
            .get_credentials(&CredentialKey::NmxM { nmxm_id: id })
            .await
            .map_err(|e| NvLinkPartitionError::MissingCredentials(eyre::Report::from(e)))?
            .ok_or(NvLinkPartitionError::MissingCredentials(eyre::Report::msg(
                "NMX-M credentials not found",
            )))?;
        let (user, pass) = match credentials {
            Credentials::UsernamePassword { username, password } => (username, password),
        };
        if endpoint.parse::<http::Uri>().is_err() {
            return Err(NvLinkPartitionError::InvalidArguments);
        };
        let endpoint = libnmxm::Endpoint {
            host: endpoint.to_string(),
            username: Some(user),
            password: Some(pass),
        };

        self.pool
            .create_client(endpoint)
            .await
            .map_err(NvLinkPartitionError::NmxmApiError)
    }
}

#[cfg(test)]
pub mod test_support {
    use std::sync::{Arc, Mutex};

    use uuid::Uuid;

    use super::*;

    // mock similar to RedfishSim
    #[derive(Debug)]
    pub struct NmxmSimClient {
        _state: Arc<Mutex<u32>>,
        _partitions: Arc<Mutex<Vec<libnmxm::nmxm_model::Partition>>>,
        _gpus: Arc<Mutex<Vec<libnmxm::nmxm_model::Gpu>>>,
    }

    impl Default for NmxmSimClient {
        fn default() -> Self {
            NmxmSimClient {
                _state: Arc::new(Mutex::new(0)),
                _partitions: Arc::new(Mutex::new(Vec::new())),
                _gpus: Arc::new(Mutex::new(Self::default_gpus())),
            }
        }
    }

    impl NmxmSimClient {
        pub fn with_default_partition() -> Self {
            let client = NmxmSimClient::default();
            client.create_default_partition(
                client
                    ._gpus
                    .lock()
                    .unwrap()
                    .iter()
                    .filter_map(|gpu| gpu.id.clone())
                    .collect(),
            );
            client
        }

        /// Creates a default partition with partition_id 32766 containing the specified GPU IDs.
        fn create_default_partition(&self, gpu_ids: Vec<String>) {
            let partition = libnmxm::nmxm_model::Partition {
                id: "default-partition".to_string(),
                partition_id: 32766,
                name: "Default Partition".to_string(),
                r#type: libnmxm::nmxm_model::PartitionType::PartitionTypeIDBased,
                health: libnmxm::nmxm_model::PartitionHealth::PartitionHealthHealthy,
                members: Box::new(libnmxm::nmxm_model::PartitionMembers::Ids(gpu_ids)),
                created_at: "2021-01-01T12:00:00Z".to_string(),
                updated_at: "2021-01-01T12:00:00Z".to_string(),
            };
            self._partitions.lock().unwrap().push(partition);
        }

        fn default_gpus() -> Vec<libnmxm::nmxm_model::Gpu> {
            let all_ones_uuid = Uuid::from_bytes([
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF,
            ]);
            let all_ones_minus_one_uuid = Uuid::from_bytes([
                0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF,
            ]);

            let location1 = libnmxm::nmxm_model::LocationInfo {
                chassis_id: Some(101),
                chassis_serial_number: Some(String::from("SN_WHATISTHIS")),
                slot_id: Some(0),
                tray_index: Some(0),
                host_id: Some(1),
            };

            let location2 = libnmxm::nmxm_model::LocationInfo {
                chassis_id: Some(101),
                chassis_serial_number: Some(String::from("SN_WHATISTHIS1")),
                slot_id: Some(0),
                tray_index: Some(0),
                host_id: Some(1),
            };

            let location3 = libnmxm::nmxm_model::LocationInfo {
                chassis_id: Some(101),
                chassis_serial_number: Some(String::from("SN_WHATISTHIS2")),
                slot_id: Some(0),
                tray_index: Some(0),
                host_id: Some(1),
            };

            vec![
                libnmxm::nmxm_model::Gpu {
                    id: Some(String::from("gpu1")),
                    name: Some(String::from("NVIDIA GB200 NVL")),
                    description: Some(String::from("High-end gaming GPU")),
                    internal_description: Some(String::from("Internal description for GPU 1")),
                    created_at: Some(String::from("2021-01-01T12:00:00Z")),
                    updated_at: Some(String::from("2021-06-01T12:00:00Z")),
                    domain_uuid: Some(all_ones_uuid),
                    location_info: Some(Box::new(location1.clone())),
                    device_uid: 12345,
                    device_id: 1,
                    device_pcie_id: 1001,
                    system_uid: 10001,
                    vendor_id: 4318,
                    alid_list: vec![1111, 2222],
                    partition_id: None,
                    port_id_list: None,
                    health: None,
                },
                libnmxm::nmxm_model::Gpu {
                    id: Some(String::from("gpu2")),
                    name: Some(String::from("NVIDIA GB200 NVL")),
                    description: Some(String::from("High-end gaming GPU")),
                    internal_description: Some(String::from("Internal description for GPU 2")),
                    created_at: Some(String::from("2021-01-01T12:00:00Z")),
                    updated_at: Some(String::from("2021-06-01T12:00:00Z")),
                    domain_uuid: Some(all_ones_minus_one_uuid),
                    location_info: Some(Box::new(location1.clone())),
                    device_uid: 12346,
                    device_id: 2,
                    device_pcie_id: 1002,
                    system_uid: 10002,
                    vendor_id: 4318,
                    alid_list: vec![3333, 4444],
                    partition_id: None,
                    port_id_list: None,
                    health: None,
                },
                libnmxm::nmxm_model::Gpu {
                    id: Some(String::from("gpu3")),
                    name: Some(String::from("NVIDIA GB200 NVL")),
                    description: Some(String::from("High-end gaming GPU")),
                    internal_description: Some(String::from("Internal description for GPU 3")),
                    created_at: Some(String::from("2021-01-01T12:00:00Z")),
                    updated_at: Some(String::from("2021-06-01T12:00:00Z")),
                    domain_uuid: Some(all_ones_uuid),
                    location_info: Some(Box::new(location1.clone())),
                    device_uid: 12347,
                    device_id: 3,
                    device_pcie_id: 1003,
                    system_uid: 10003,
                    vendor_id: 4318,
                    alid_list: vec![5555, 6666],
                    partition_id: None,
                    port_id_list: None,
                    health: None,
                },
                libnmxm::nmxm_model::Gpu {
                    id: Some(String::from("gpu4")),
                    name: Some(String::from("NVIDIA GB200 NVL")),
                    description: Some(String::from("High-end gaming GPU")),
                    internal_description: Some(String::from("Internal description for GPU 4")),
                    created_at: Some(String::from("2021-01-01T12:00:00Z")),
                    updated_at: Some(String::from("2021-06-01T12:00:00Z")),
                    domain_uuid: Some(all_ones_uuid),
                    location_info: Some(Box::new(location1)),
                    device_uid: 12348,
                    device_id: 4,
                    device_pcie_id: 1004,
                    system_uid: 10004,
                    vendor_id: 4318,
                    alid_list: vec![7777, 8888],
                    partition_id: None,
                    port_id_list: None,
                    health: None,
                },
                libnmxm::nmxm_model::Gpu {
                    id: Some(String::from("gpu11")),
                    name: Some(String::from("NVIDIA GB200 NVL")),
                    description: Some(String::from("High-end gaming GPU")),
                    internal_description: Some(String::from("Internal description for GPU 11")),
                    created_at: Some(String::from("2021-01-01T12:00:00Z")),
                    updated_at: Some(String::from("2021-06-01T12:00:00Z")),
                    domain_uuid: Some(all_ones_uuid),
                    location_info: Some(Box::new(location2.clone())),
                    device_uid: 12345,
                    device_id: 1,
                    device_pcie_id: 1001,
                    system_uid: 10001,
                    vendor_id: 4318,
                    alid_list: vec![1111, 2222],
                    partition_id: None,
                    port_id_list: None,
                    health: None,
                },
                libnmxm::nmxm_model::Gpu {
                    id: Some(String::from("gpu12")),
                    name: Some(String::from("NVIDIA GB200 NVL")),
                    description: Some(String::from("High-end gaming GPU")),
                    internal_description: Some(String::from("Internal description for GPU 12")),
                    created_at: Some(String::from("2021-01-01T12:00:00Z")),
                    updated_at: Some(String::from("2021-06-01T12:00:00Z")),
                    domain_uuid: Some(all_ones_minus_one_uuid),
                    location_info: Some(Box::new(location2.clone())),
                    device_uid: 12346,
                    device_id: 2,
                    device_pcie_id: 1002,
                    system_uid: 10002,
                    vendor_id: 4318,
                    alid_list: vec![3333, 4444],
                    partition_id: None,
                    port_id_list: None,
                    health: None,
                },
                libnmxm::nmxm_model::Gpu {
                    id: Some(String::from("gpu13")),
                    name: Some(String::from("NVIDIA GB200 NVL")),
                    description: Some(String::from("High-end gaming GPU")),
                    internal_description: Some(String::from("Internal description for GPU 13")),
                    created_at: Some(String::from("2021-01-01T12:00:00Z")),
                    updated_at: Some(String::from("2021-06-01T12:00:00Z")),
                    domain_uuid: Some(all_ones_uuid),
                    location_info: Some(Box::new(location2.clone())),
                    device_uid: 12347,
                    device_id: 3,
                    device_pcie_id: 1003,
                    system_uid: 10003,
                    vendor_id: 4318,
                    alid_list: vec![5555, 6666],
                    partition_id: None,
                    port_id_list: None,
                    health: None,
                },
                libnmxm::nmxm_model::Gpu {
                    id: Some(String::from("gpu14")),
                    name: Some(String::from("NVIDIA GB200 NVL")),
                    description: Some(String::from("High-end gaming GPU")),
                    internal_description: Some(String::from("Internal description for GPU 14")),
                    created_at: Some(String::from("2021-01-01T12:00:00Z")),
                    updated_at: Some(String::from("2021-06-01T12:00:00Z")),
                    domain_uuid: Some(all_ones_uuid),
                    location_info: Some(Box::new(location2)),
                    device_uid: 12348,
                    device_id: 4,
                    device_pcie_id: 1004,
                    system_uid: 10004,
                    vendor_id: 4318,
                    alid_list: vec![7777, 8888],
                    partition_id: None,
                    port_id_list: None,
                    health: None,
                },
                libnmxm::nmxm_model::Gpu {
                    id: Some(String::from("gpu21")),
                    name: Some(String::from("NVIDIA GB200 NVL")),
                    description: Some(String::from("High-end gaming GPU")),
                    internal_description: Some(String::from("Internal description for GPU 21")),
                    created_at: Some(String::from("2021-01-01T12:00:00Z")),
                    updated_at: Some(String::from("2021-06-01T12:00:00Z")),
                    domain_uuid: Some(all_ones_minus_one_uuid),
                    location_info: Some(Box::new(location3.clone())),
                    device_uid: 12349,
                    device_id: 1,
                    device_pcie_id: 1005,
                    system_uid: 10005,
                    vendor_id: 4318,
                    alid_list: vec![9999, 9888],
                    partition_id: None,
                    port_id_list: None,
                    health: None,
                },
                libnmxm::nmxm_model::Gpu {
                    id: Some(String::from("gpu22")),
                    name: Some(String::from("NVIDIA GB200 NVL")),
                    description: Some(String::from("High-end gaming GPU")),
                    internal_description: Some(String::from("Internal description for GPU 22")),
                    created_at: Some(String::from("2021-01-01T12:00:00Z")),
                    updated_at: Some(String::from("2021-06-01T12:00:00Z")),
                    domain_uuid: Some(all_ones_minus_one_uuid),
                    location_info: Some(Box::new(location3.clone())),
                    device_uid: 12350,
                    device_id: 2,
                    device_pcie_id: 1006,
                    system_uid: 10006,
                    vendor_id: 4318,
                    alid_list: vec![1212, 2121],
                    partition_id: None,
                    port_id_list: None,
                    health: None,
                },
                libnmxm::nmxm_model::Gpu {
                    id: Some(String::from("gpu23")),
                    name: Some(String::from("NVIDIA GB200 NVL")),
                    description: Some(String::from("High-end gaming GPU")),
                    internal_description: Some(String::from("Internal description for GPU 23")),
                    created_at: Some(String::from("2021-01-01T12:00:00Z")),
                    updated_at: Some(String::from("2021-06-01T12:00:00Z")),
                    domain_uuid: Some(all_ones_minus_one_uuid),
                    location_info: Some(Box::new(location3.clone())),
                    device_uid: 12351,
                    device_id: 3,
                    device_pcie_id: 1007,
                    system_uid: 10007,
                    vendor_id: 4318,
                    alid_list: vec![1313, 1414],
                    partition_id: None,
                    port_id_list: None,
                    health: None,
                },
                libnmxm::nmxm_model::Gpu {
                    id: Some(String::from("gpu24")),
                    name: Some(String::from("NVIDIA GB200 NVL")),
                    description: Some(String::from("High-end gaming GPU")),
                    internal_description: Some(String::from("Internal description for GPU 24")),
                    created_at: Some(String::from("2021-01-01T12:00:00Z")),
                    updated_at: Some(String::from("2021-06-01T12:00:00Z")),
                    domain_uuid: Some(all_ones_minus_one_uuid),
                    location_info: Some(Box::new(location3)),
                    device_uid: 12352,
                    device_id: 4,
                    device_pcie_id: 1008,
                    system_uid: 10008,
                    vendor_id: 4318,
                    alid_list: vec![1515, 1616],
                    partition_id: None,
                    port_id_list: None,
                    health: None,
                },
            ]
        }
    }

    #[async_trait]
    impl Nmxm for NmxmSimClient {
        async fn create(
            &self,
            _endpoint: libnmxm::Endpoint,
        ) -> Result<Box<dyn Nmxm>, NmxmApiError> {
            todo!()
        }

        async fn raw_get(
            &self,
            _api: &str,
        ) -> Result<libnmxm::nmxm_model::RawResponse, NmxmApiError> {
            todo!()
        }

        async fn get_chassis(
            &self,
            _id: String,
        ) -> Result<Vec<libnmxm::nmxm_model::Chassis>, NmxmApiError> {
            todo!()
        }

        async fn get_chassis_count(
            &self,
            _domain: Option<Vec<uuid::Uuid>>,
        ) -> Result<i64, NmxmApiError> {
            todo!()
        }

        async fn get_gpu(
            &self,
            _id: Option<String>,
        ) -> Result<Vec<libnmxm::nmxm_model::Gpu>, NmxmApiError> {
            Ok(self._gpus.lock().unwrap().clone())
        }

        async fn get_gpu_count(
            &self,
            _domain: Option<Vec<uuid::Uuid>>,
        ) -> Result<i64, NmxmApiError> {
            todo!()
        }

        async fn get_partition(
            &self,
            _id: String,
        ) -> Result<libnmxm::nmxm_model::Partition, NmxmApiError> {
            todo!()
        }

        async fn get_partitions_list(
            &self,
        ) -> Result<Vec<libnmxm::nmxm_model::Partition>, NmxmApiError> {
            let mut _state = self._state.lock().unwrap();
            let mut _p = self._partitions.lock().unwrap();
            let partitions = _p.clone();

            Ok(partitions)
        }

        async fn get_compute_node(
            &self,
            _id: Option<String>,
        ) -> Result<Vec<libnmxm::nmxm_model::ComputeNode>, NmxmApiError> {
            todo!()
        }

        async fn get_compute_nodes_count(
            &self,
            _domain: Option<Vec<uuid::Uuid>>,
        ) -> Result<i64, NmxmApiError> {
            todo!()
        }

        async fn get_port(
            &self,
            _id: Option<String>,
        ) -> Result<Vec<libnmxm::nmxm_model::Port>, NmxmApiError> {
            todo!()
        }

        async fn get_ports_count(
            &self,
            _domain: Option<Vec<uuid::Uuid>>,
        ) -> Result<i64, NmxmApiError> {
            todo!()
        }

        async fn get_switch_node(
            &self,
            _id: Option<String>,
        ) -> Result<Vec<libnmxm::nmxm_model::SwitchNode>, NmxmApiError> {
            todo!()
        }

        async fn get_switch_nodes_count(
            &self,
            _domain: Option<Vec<uuid::Uuid>>,
        ) -> Result<i64, NmxmApiError> {
            todo!()
        }

        async fn create_partition(
            &self,
            _req: Option<libnmxm::nmxm_model::CreatePartitionRequest>,
        ) -> Result<libnmxm::nmxm_model::AsyncResponse, NmxmApiError> {
            let r = _req.unwrap();
            let mut _p = self._partitions.lock().unwrap();
            let partition = libnmxm::nmxm_model::Partition {
                id: uuid::Uuid::new_v4().into(),
                partition_id: 1,
                name: r.name,
                r#type: libnmxm::nmxm_model::PartitionType::PartitionTypeIDBased,
                health: libnmxm::nmxm_model::PartitionHealth::PartitionHealthHealthy,
                members: r.members,
                created_at: String::from("2023-03-01T12:00:00.000Z"),
                updated_at: String::from("2023-03-01T12:00:00.000Z"),
            };

            _p.push(partition);

            Ok(libnmxm::nmxm_model::AsyncResponse {
                operation_id: "5151515151".to_string(),
            })
        }

        async fn delete_partition(
            &self,
            _id: String,
        ) -> Result<libnmxm::nmxm_model::AsyncResponse, NmxmApiError> {
            let mut _p = self._partitions.lock().unwrap();
            _p.retain(|partition| partition.id != _id);
            Ok(libnmxm::nmxm_model::AsyncResponse {
                operation_id: "5151515151".to_string(),
            })
        }

        async fn update_partition(
            &self,
            _id: String,
            _req: libnmxm::nmxm_model::UpdatePartitionRequest,
        ) -> Result<libnmxm::nmxm_model::AsyncResponse, NmxmApiError> {
            let mut _p = self._partitions.lock().unwrap();
            if let Some(partition) = _p.iter_mut().find(|p| p.id == _id) {
                partition.members = _req.members;
            }
            Ok(libnmxm::nmxm_model::AsyncResponse {
                operation_id: "5151515151".to_string(),
            })
        }

        async fn get_operation(
            &self,
            _id: String,
        ) -> Result<libnmxm::nmxm_model::Operation, NmxmApiError> {
            let operation_request = libnmxm::nmxm_model::OperationRequest {
                method: libnmxm::nmxm_model::OperationRequestMethod::Post,
                uri: String::from("/nmx/v1/create_partition"),
                body: Some(Some(serde_json::json!({"key": "value"}))),
                cancellable: true,
            };
            let operation = libnmxm::nmxm_model::Operation {
                id: String::from("5151515151"),
                created_at: String::from("2025-10-10T10:00:00Z"),
                updated_at: String::from("2025-10-10T11:00:00Z"),
                status: libnmxm::nmxm_model::OperationStatus::Completed,
                percentage: 75.0,
                current_step: String::from("Done"),
                request: Box::new(operation_request),
                result: None,
            };

            Ok(operation)
        }

        async fn get_operations_list(
            &self,
        ) -> Result<Vec<libnmxm::nmxm_model::Operation>, NmxmApiError> {
            todo!()
        }

        async fn cancel_operation(
            &self,
            _id: String,
        ) -> Result<libnmxm::nmxm_model::AsyncResponse, NmxmApiError> {
            todo!()
        }
    }

    #[async_trait]
    impl NmxmClientPool for NmxmSimClient {
        async fn create_client(
            &self,
            _endpoint: &str,
            _nmxm_id: Option<String>,
        ) -> Result<Box<dyn Nmxm>, NvLinkPartitionError> {
            Ok(Box::new(NmxmSimClient {
                _state: self._state.clone(),
                _partitions: self._partitions.clone(),
                _gpus: self._gpus.clone(),
            }))
        }
    }
}
