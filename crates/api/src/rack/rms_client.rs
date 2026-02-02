/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::sync::Arc;

use carbide_uuid::rack::RackId;
use forge_tls::rms_client_config::{rms_client_cert_info, rms_root_ca_path};
use rpc::forge_tls_client::{ApiConfig, ForgeClientConfig};
use rpc::protos::rack_manager::{
    NewNodeInfo, PowerComplianceValue, PowerOnOrderItem, PowerOperation, RackPowerOperation,
};
use rpc::protos::rack_manager_client::RackManagerApiClient;

pub enum RmsNodeType {
    Compute = 0,
    PowerShelf = 1,
    Switch = 2,
    Unknown = 3,
}

impl From<RmsNodeType> for i32 {
    fn from(value: RmsNodeType) -> Self {
        match value {
            RmsNodeType::Compute => 0,
            RmsNodeType::PowerShelf => 1,
            RmsNodeType::Switch => 2,
            RmsNodeType::Unknown => 3,
        }
    }
}

// TODO: Add more error types for better error handling.
#[derive(thiserror::Error, Debug)]
pub enum RackManagerError {
    //    #[error("Unable to connect to Rack Manager service: {0}")]
    //    ApiConnectFailed(String),
    #[error("The connection or API call to the Rack Manager server returned {0}")]
    ApiInvocationError(#[from] tonic::Status),
    /*
    #[error("Generic Error: {0}")]
    GenericError(String),

    #[error("Error while handling json: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Tokio Task Join Error {0}")]
    TokioJoinError(#[from] tokio::task::JoinError),

    #[error("No results returned")]
    Empty,
     */
}

#[derive(Clone)]
pub struct RmsClientPool {
    pub client: Arc<RackManagerApi>,
}

impl RmsClientPool {
    pub fn new(rms_api_url: &str) -> Self {
        let client = RackManagerApi::new(None, None, None, rms_api_url).into();
        Self { client }
    }
}

#[async_trait::async_trait]
pub trait RackManagerClientPool: Send + Sync + 'static {
    async fn create_client(&self) -> Arc<dyn RmsApi>;
}

#[async_trait::async_trait]
impl RackManagerClientPool for RmsClientPool {
    async fn create_client(&self) -> Arc<dyn RmsApi> {
        self.client.clone()
    }
}

#[derive(Clone, Debug)]
pub struct RackManagerApi {
    pub client: RackManagerApiClient,
    #[allow(unused)]
    pub config: ForgeClientConfig,
    #[allow(unused)]
    pub api_url: String,
}

impl RackManagerApi {
    /// create a rack manager client that can be used in the api server
    pub fn new(
        root_ca_path: Option<String>,
        client_cert: Option<String>,
        client_key: Option<String>,
        api_url: &str,
    ) -> Self {
        let client_certs = rms_client_cert_info(client_cert, client_key);
        let root_ca = rms_root_ca_path(root_ca_path, None);
        let config = ForgeClientConfig::new(root_ca, client_certs);
        let api_config = ApiConfig::new(api_url, &config);

        let client = RackManagerApiClient::new(&api_config);
        Self {
            client,
            config,
            api_url: api_url.to_string(),
        }
    }
}

// declare the functions
#[allow(clippy::too_many_arguments, dead_code)]
#[async_trait::async_trait]
pub trait RmsApi: Send + Sync + 'static {
    async fn inventory_get(
        &self,
    ) -> Result<rpc::protos::rack_manager::InventoryResponse, RackManagerError>;
    async fn add_node(
        &self,
        new_nodes: Vec<NewNodeInfo>,
    ) -> Result<rpc::protos::rack_manager::InventoryResponse, RackManagerError>;
    async fn remove_node(
        &self,
        rack_id: RackId,
        node_id: String,
    ) -> Result<rpc::protos::rack_manager::InventoryResponse, RackManagerError>;
    async fn get_poweron_order(
        &self,
        rack_id: RackId,
    ) -> Result<rpc::protos::rack_manager::InventoryResponse, RackManagerError>;
    async fn set_poweron_order(
        &self,
        rack_id: RackId,
        poweron_order: Vec<PowerOnOrderItem>,
    ) -> Result<rpc::protos::rack_manager::InventoryResponse, RackManagerError>;
    async fn get_power_state(
        &self,
        rack_id: RackId,
        node_id: String,
    ) -> Result<rpc::protos::rack_manager::PowerControlResponse, RackManagerError>;
    async fn set_power_state(
        &self,
        rack_id: RackId,
        node_id: String,
        operation: PowerOperation,
    ) -> Result<rpc::protos::rack_manager::PowerControlResponse, RackManagerError>;
    async fn rack_power(
        &self,
        rack_id: RackId,
        operation: RackPowerOperation,
    ) -> Result<rpc::protos::rack_manager::PowerControlResponse, RackManagerError>;
    async fn get_firmware_inventory(
        &self,
        rack_id: RackId,
        node_id: String,
    ) -> Result<rpc::protos::rack_manager::FirmwareResponse, RackManagerError>;
    async fn update_firmware(
        &self,
        rack_id: RackId,
        node_id: String,
        filename: String,
        target: String,
        activate: bool,
    ) -> Result<rpc::protos::rack_manager::FirmwareResponse, RackManagerError>;
    async fn update_firmware_by_node_type(
        &self,
        rack_id: RackId,
        node_type: i32,
        filename: String,
        target: String,
    ) -> Result<rpc::protos::rack_manager::FirmwareResponse, RackManagerError>;
    async fn get_available_fw_images(
        &self,
        rack_id: RackId,
        node_id: String,
    ) -> Result<rpc::protos::rack_manager::FirmwareResponse, RackManagerError>;
    async fn get_bkc_files(
        &self,
    ) -> Result<rpc::protos::rack_manager::FirmwareResponse, RackManagerError>;
    async fn select_active_bkc_file(
        &self,
        filename: String,
    ) -> Result<rpc::protos::rack_manager::FirmwareResponse, RackManagerError>;
    async fn check_bkc_compliance(
        &self,
    ) -> Result<rpc::protos::rack_manager::FirmwareResponse, RackManagerError>;
    async fn get_power_compliance(
        &self,
        request_type: PowerComplianceValue,
    ) -> Result<rpc::protos::rack_manager::PowerComplianceResponse, RackManagerError>;
    async fn set_power_compliance(
        &self,
        request_type: PowerComplianceValue,
        power_value: i64,
    ) -> Result<rpc::protos::rack_manager::PowerComplianceResponse, RackManagerError>;
    async fn upload_file_metadata(
        &self,
        node_id: String,
        file_name: String,
        file_type: i32,
        target: String,
        total_size: i64,
        file_hash: String,
        total_chunks: i32,
    ) -> Result<rpc::protos::rack_manager::FileUploadResponse, RackManagerError>;
    async fn upload_file_chunk(
        &self,
        data: Vec<u8>,
        sequence_number: i32,
    ) -> Result<rpc::protos::rack_manager::FileUploadResponse, RackManagerError>;
}

#[async_trait::async_trait]
impl RmsApi for RackManagerApi {
    async fn inventory_get(
        &self,
    ) -> Result<rpc::protos::rack_manager::InventoryResponse, RackManagerError> {
        let cmd: rpc::protos::rack_manager::inventory_request::Command =
            rpc::protos::rack_manager::inventory_request::Command::GetInventory(Default::default());
        let message = rpc::protos::rack_manager::InventoryRequest {
            metadata: None,
            command: Some(cmd),
        };
        self.client
            .inventory_control(message)
            .await
            .map_err(RackManagerError::from)
    }

    async fn add_node(
        &self,
        new_nodes: Vec<NewNodeInfo>,
    ) -> Result<rpc::protos::rack_manager::InventoryResponse, RackManagerError> {
        let add_node_command = rpc::protos::rack_manager::AddNodeCommand {
            node_info: new_nodes,
        };
        let cmd = rpc::protos::rack_manager::inventory_request::Command::AddNode(add_node_command);
        let message = rpc::protos::rack_manager::InventoryRequest {
            metadata: None,
            command: Some(cmd),
        };
        self.client
            .inventory_control(message)
            .await
            .map_err(RackManagerError::from)
    }

    async fn remove_node(
        &self,
        rack_id: RackId,
        node_id: String,
    ) -> Result<rpc::protos::rack_manager::InventoryResponse, RackManagerError> {
        let remove_node_command = rpc::protos::rack_manager::RemoveNodeCommand {
            rack_id: rack_id.to_string(),
            node_id,
        };
        let cmd =
            rpc::protos::rack_manager::inventory_request::Command::RemoveNode(remove_node_command);
        let message = rpc::protos::rack_manager::InventoryRequest {
            metadata: None,
            command: Some(cmd),
        };
        self.client
            .inventory_control(message)
            .await
            .map_err(RackManagerError::from)
    }

    // POWER CONTROL

    async fn get_poweron_order(
        &self,
        rack_id: RackId,
    ) -> Result<rpc::protos::rack_manager::InventoryResponse, RackManagerError> {
        let get_poweron_order_command = rpc::protos::rack_manager::GetPowerOnOrderCommand {
            rack_id: rack_id.to_string(),
        };
        let cmd = rpc::protos::rack_manager::inventory_request::Command::GetPowerOnOrder(
            get_poweron_order_command,
        );
        let message = rpc::protos::rack_manager::InventoryRequest {
            metadata: None,
            command: Some(cmd),
        };
        self.client
            .inventory_control(message)
            .await
            .map_err(RackManagerError::from)
    }

    #[allow(dead_code)]
    async fn set_poweron_order(
        &self,
        rack_id: RackId,
        poweron_order: Vec<PowerOnOrderItem>,
    ) -> Result<rpc::protos::rack_manager::InventoryResponse, RackManagerError> {
        let set_poweron_order_command = rpc::protos::rack_manager::SetPowerOnOrderCommand {
            rack_id: rack_id.to_string(),
            power_on_order: poweron_order,
        };
        let cmd = rpc::protos::rack_manager::inventory_request::Command::SetPowerOnOrder(
            set_poweron_order_command,
        );
        let message = rpc::protos::rack_manager::InventoryRequest {
            metadata: None,
            command: Some(cmd),
        };
        self.client
            .inventory_control(message)
            .await
            .map_err(RackManagerError::from)
    }

    async fn get_power_state(
        &self,
        rack_id: RackId,
        node_id: String,
    ) -> Result<rpc::protos::rack_manager::PowerControlResponse, RackManagerError> {
        let get_power_state_command = rpc::protos::rack_manager::GetPowerStateCommand {
            rack_id: rack_id.to_string(),
            node_id,
        };
        let cmd = rpc::protos::rack_manager::power_control_request::Command::GetPowerState(
            get_power_state_command,
        );
        let message = rpc::protos::rack_manager::PowerControlRequest {
            metadata: None,
            command: Some(cmd),
        };
        self.client
            .power_control(message)
            .await
            .map_err(RackManagerError::from)
    }

    #[allow(dead_code)]
    async fn set_power_state(
        &self,
        rack_id: RackId,
        node_id: String,
        operation: PowerOperation,
    ) -> Result<rpc::protos::rack_manager::PowerControlResponse, RackManagerError> {
        let set_power_state_command = rpc::protos::rack_manager::SetPowerStateCommand {
            rack_id: rack_id.to_string(),
            node_id,
            operation: operation.into(),
        };
        let cmd = rpc::protos::rack_manager::power_control_request::Command::SetPowerState(
            set_power_state_command,
        );
        let message = rpc::protos::rack_manager::PowerControlRequest {
            metadata: None,
            command: Some(cmd),
        };
        self.client
            .power_control(message)
            .await
            .map_err(RackManagerError::from)
    }

    #[allow(dead_code)]
    async fn rack_power(
        &self,
        rack_id: RackId,
        operation: RackPowerOperation,
    ) -> Result<rpc::protos::rack_manager::PowerControlResponse, RackManagerError> {
        let rack_power_command = rpc::protos::rack_manager::RackPowerCommand {
            rack_id: rack_id.to_string(),
            operation: operation.into(),
        };
        let cmd = rpc::protos::rack_manager::power_control_request::Command::RackPower(
            rack_power_command,
        );
        let message = rpc::protos::rack_manager::PowerControlRequest {
            metadata: None,
            command: Some(cmd),
        };
        self.client
            .power_control(message)
            .await
            .map_err(RackManagerError::from)
    }

    // FIRMWARE CONTROL

    async fn get_firmware_inventory(
        &self,
        rack_id: RackId,
        node_id: String,
    ) -> Result<rpc::protos::rack_manager::FirmwareResponse, RackManagerError> {
        let get_firmware_inventory_command =
            rpc::protos::rack_manager::GetFirmwareInventoryCommand {
                rack_id: rack_id.to_string(),
                node_id,
            };
        let cmd = rpc::protos::rack_manager::firmware_request::Command::GetFirmwareInventory(
            get_firmware_inventory_command,
        );
        let message = rpc::protos::rack_manager::FirmwareRequest {
            metadata: None,
            command: Some(cmd),
        };
        self.client
            .firmware_control(message)
            .await
            .map_err(RackManagerError::from)
    }

    #[allow(dead_code)]
    async fn update_firmware(
        &self,
        rack_id: RackId,
        node_id: String,
        filename: String,
        target: String,
        activate: bool,
    ) -> Result<rpc::protos::rack_manager::FirmwareResponse, RackManagerError> {
        let update_firmware_command = rpc::protos::rack_manager::UpdateFirmwareCommand {
            rack_id: rack_id.to_string(),
            node_id,
            filename,
            target,
            activate,
        };
        let cmd = rpc::protos::rack_manager::firmware_request::Command::UpdateFirmware(
            update_firmware_command,
        );
        let message = rpc::protos::rack_manager::FirmwareRequest {
            metadata: None,
            command: Some(cmd),
        };
        self.client
            .firmware_control(message)
            .await
            .map_err(RackManagerError::from)
    }

    #[allow(dead_code)]
    async fn update_firmware_by_node_type(
        &self,
        rack_id: RackId,
        node_type: i32,
        filename: String,
        target: String,
    ) -> Result<rpc::protos::rack_manager::FirmwareResponse, RackManagerError> {
        let update_firmware_by_node_type_command =
            rpc::protos::rack_manager::UpdateFirmwareByNodeTypeCommand {
                rack_id: rack_id.to_string(),
                node_type,
                filename,
                target,
            };
        let cmd = rpc::protos::rack_manager::firmware_request::Command::UpdateFirmwareByNodeType(
            update_firmware_by_node_type_command,
        );
        let message = rpc::protos::rack_manager::FirmwareRequest {
            metadata: None,
            command: Some(cmd),
        };
        self.client
            .firmware_control(message)
            .await
            .map_err(RackManagerError::from)
    }

    async fn get_available_fw_images(
        &self,
        rack_id: RackId,
        node_id: String,
    ) -> Result<rpc::protos::rack_manager::FirmwareResponse, RackManagerError> {
        let get_available_fw_images_command =
            rpc::protos::rack_manager::GetAvailableFwImagesCommand {
                rack_id: Some(rack_id.to_string()),
                node_id: Some(node_id),
            };
        let cmd = rpc::protos::rack_manager::firmware_request::Command::GetAvailableFwImages(
            get_available_fw_images_command,
        );
        let message = rpc::protos::rack_manager::FirmwareRequest {
            metadata: None,
            command: Some(cmd),
        };
        self.client
            .firmware_control(message)
            .await
            .map_err(RackManagerError::from)
    }

    async fn get_bkc_files(
        &self,
    ) -> Result<rpc::protos::rack_manager::FirmwareResponse, RackManagerError> {
        let cmd =
            rpc::protos::rack_manager::firmware_request::Command::GetBkcFiles(Default::default());
        let message = rpc::protos::rack_manager::FirmwareRequest {
            metadata: None,
            command: Some(cmd),
        };
        self.client
            .firmware_control(message)
            .await
            .map_err(RackManagerError::from)
    }

    #[allow(dead_code)]
    async fn select_active_bkc_file(
        &self,
        filename: String,
    ) -> Result<rpc::protos::rack_manager::FirmwareResponse, RackManagerError> {
        let select_active_bkc_file_command =
            rpc::protos::rack_manager::SelectActiveBkcFileCommand { filename };
        let cmd = rpc::protos::rack_manager::firmware_request::Command::SelectActiveBkcFile(
            select_active_bkc_file_command,
        );
        let message = rpc::protos::rack_manager::FirmwareRequest {
            metadata: None,
            command: Some(cmd),
        };
        self.client
            .firmware_control(message)
            .await
            .map_err(RackManagerError::from)
    }

    async fn check_bkc_compliance(
        &self,
    ) -> Result<rpc::protos::rack_manager::FirmwareResponse, RackManagerError> {
        let cmd = rpc::protos::rack_manager::firmware_request::Command::CheckBkcCompliance(
            Default::default(),
        );
        let message = rpc::protos::rack_manager::FirmwareRequest {
            metadata: None,
            command: Some(cmd),
        };
        self.client
            .firmware_control(message)
            .await
            .map_err(RackManagerError::from)
    }

    // POWER COMPLIANCE CONTROL

    #[allow(dead_code)]
    async fn get_power_compliance(
        &self,
        request_type: PowerComplianceValue,
    ) -> Result<rpc::protos::rack_manager::PowerComplianceResponse, RackManagerError> {
        let get_power_compliance_command = rpc::protos::rack_manager::GetRackPowerCommand {
            request_type: request_type.into(),
        };
        let cmd = rpc::protos::rack_manager::power_compliance_request::Command::GetPowerLimit(
            get_power_compliance_command,
        );
        let message = rpc::protos::rack_manager::PowerComplianceRequest {
            metadata: None,
            command: Some(cmd),
        };
        self.client
            .power_compliance(message)
            .await
            .map_err(RackManagerError::from)
    }

    #[allow(dead_code)]
    async fn set_power_compliance(
        &self,
        request_type: PowerComplianceValue,
        power_value: i64,
    ) -> Result<rpc::protos::rack_manager::PowerComplianceResponse, RackManagerError> {
        let set_power_compliance_command = rpc::protos::rack_manager::SetRackPowerCommand {
            request_type: request_type.into(),
            power_value,
        };
        let cmd = rpc::protos::rack_manager::power_compliance_request::Command::SetPowerLimit(
            set_power_compliance_command,
        );
        let message = rpc::protos::rack_manager::PowerComplianceRequest {
            metadata: None,
            command: Some(cmd),
        };
        self.client
            .power_compliance(message)
            .await
            .map_err(RackManagerError::from)
    }

    // FILE UPLOAD

    #[allow(dead_code)]
    async fn upload_file_metadata(
        &self,
        node_id: String,
        file_name: String,
        file_type: i32,
        target: String,
        total_size: i64,
        file_hash: String,
        total_chunks: i32,
    ) -> Result<rpc::protos::rack_manager::FileUploadResponse, RackManagerError> {
        let upload_data = rpc::protos::rack_manager::FileUploadMetadata {
            node_id,
            file_name,
            file_type,
            target,
            total_size,
            file_hash,
            total_chunks,
        };
        let message = rpc::protos::rack_manager::FileUploadRequest {
            metadata: None,
            upload_data: Some(
                rpc::protos::rack_manager::file_upload_request::UploadData::UploadMetadata(
                    upload_data,
                ),
            ),
        };
        self.client
            .upload_file(message)
            .await
            .map_err(RackManagerError::from)
    }

    #[allow(dead_code)]
    async fn upload_file_chunk(
        &self,
        data: Vec<u8>,
        sequence_number: i32,
    ) -> Result<rpc::protos::rack_manager::FileUploadResponse, RackManagerError> {
        let upload_file_chunk_command = rpc::protos::rack_manager::FileChunk {
            data,
            sequence_number,
        };
        let message = rpc::protos::rack_manager::FileUploadRequest {
            metadata: None,
            upload_data: Some(
                rpc::protos::rack_manager::file_upload_request::UploadData::Chunk(
                    upload_file_chunk_command,
                ),
            ),
        };
        self.client
            .upload_file(message)
            .await
            .map_err(RackManagerError::from)
    }
}

#[cfg(test)]
pub mod test_support {
    use std::sync::Arc;

    use super::*;

    /// RMS simulation for testing, similar to RedfishSim
    #[derive(Default)]
    pub struct RmsSim;

    impl RmsSim {
        /// Convert RmsSim to the type expected by Api and StateHandlerServices
        pub fn as_rms_client(&self) -> Option<Arc<dyn RmsApi>> {
            Some(Arc::new(MockRmsClient))
        }
    }

    #[derive(Debug, Default, Clone)]
    pub struct MockRmsClient;

    #[async_trait::async_trait]
    impl RmsApi for MockRmsClient {
        async fn inventory_get(
            &self,
        ) -> Result<rpc::protos::rack_manager::InventoryResponse, RackManagerError> {
            Ok(rpc::protos::rack_manager::InventoryResponse::default())
        }

        async fn add_node(
            &self,
            _new_nodes: Vec<NewNodeInfo>,
        ) -> Result<rpc::protos::rack_manager::InventoryResponse, RackManagerError> {
            Ok(rpc::protos::rack_manager::InventoryResponse::default())
        }

        async fn remove_node(
            &self,
            _rack_id: RackId,
            _node_id: String,
        ) -> Result<rpc::protos::rack_manager::InventoryResponse, RackManagerError> {
            Ok(rpc::protos::rack_manager::InventoryResponse::default())
        }

        async fn get_poweron_order(
            &self,
            _rack_id: RackId,
        ) -> Result<rpc::protos::rack_manager::InventoryResponse, RackManagerError> {
            Ok(rpc::protos::rack_manager::InventoryResponse::default())
        }

        async fn set_poweron_order(
            &self,
            _rack_id: RackId,
            _poweron_order: Vec<PowerOnOrderItem>,
        ) -> Result<rpc::protos::rack_manager::InventoryResponse, RackManagerError> {
            Ok(rpc::protos::rack_manager::InventoryResponse::default())
        }

        async fn get_power_state(
            &self,
            _rack_id: RackId,
            _node_id: String,
        ) -> Result<rpc::protos::rack_manager::PowerControlResponse, RackManagerError> {
            Ok(rpc::protos::rack_manager::PowerControlResponse::default())
        }

        async fn set_power_state(
            &self,
            _rack_id: RackId,
            _node_id: String,
            _operation: PowerOperation,
        ) -> Result<rpc::protos::rack_manager::PowerControlResponse, RackManagerError> {
            Ok(rpc::protos::rack_manager::PowerControlResponse::default())
        }

        async fn rack_power(
            &self,
            _rack_id: RackId,
            _operation: RackPowerOperation,
        ) -> Result<rpc::protos::rack_manager::PowerControlResponse, RackManagerError> {
            Ok(rpc::protos::rack_manager::PowerControlResponse::default())
        }

        async fn get_firmware_inventory(
            &self,
            _rack_id: RackId,
            _node_id: String,
        ) -> Result<rpc::protos::rack_manager::FirmwareResponse, RackManagerError> {
            Ok(rpc::protos::rack_manager::FirmwareResponse::default())
        }

        async fn update_firmware(
            &self,
            _rack_id: RackId,
            _node_id: String,
            _filename: String,
            _target: String,
            _activate: bool,
        ) -> Result<rpc::protos::rack_manager::FirmwareResponse, RackManagerError> {
            Ok(rpc::protos::rack_manager::FirmwareResponse::default())
        }

        async fn update_firmware_by_node_type(
            &self,
            _rack_id: RackId,
            _node_type: i32,
            _filename: String,
            _target: String,
        ) -> Result<rpc::protos::rack_manager::FirmwareResponse, RackManagerError> {
            Ok(rpc::protos::rack_manager::FirmwareResponse::default())
        }

        async fn get_available_fw_images(
            &self,
            _rack_id: RackId,
            _node_id: String,
        ) -> Result<rpc::protos::rack_manager::FirmwareResponse, RackManagerError> {
            Ok(rpc::protos::rack_manager::FirmwareResponse::default())
        }

        async fn get_bkc_files(
            &self,
        ) -> Result<rpc::protos::rack_manager::FirmwareResponse, RackManagerError> {
            Ok(rpc::protos::rack_manager::FirmwareResponse::default())
        }

        async fn select_active_bkc_file(
            &self,
            _filename: String,
        ) -> Result<rpc::protos::rack_manager::FirmwareResponse, RackManagerError> {
            Ok(rpc::protos::rack_manager::FirmwareResponse::default())
        }

        async fn check_bkc_compliance(
            &self,
        ) -> Result<rpc::protos::rack_manager::FirmwareResponse, RackManagerError> {
            Ok(rpc::protos::rack_manager::FirmwareResponse::default())
        }

        async fn get_power_compliance(
            &self,
            _request_type: PowerComplianceValue,
        ) -> Result<rpc::protos::rack_manager::PowerComplianceResponse, RackManagerError> {
            Ok(rpc::protos::rack_manager::PowerComplianceResponse::default())
        }

        async fn set_power_compliance(
            &self,
            _request_type: PowerComplianceValue,
            _power_value: i64,
        ) -> Result<rpc::protos::rack_manager::PowerComplianceResponse, RackManagerError> {
            Ok(rpc::protos::rack_manager::PowerComplianceResponse::default())
        }

        async fn upload_file_metadata(
            &self,
            _node_id: String,
            _file_name: String,
            _file_type: i32,
            _target: String,
            _total_size: i64,
            _file_hash: String,
            _total_chunks: i32,
        ) -> Result<rpc::protos::rack_manager::FileUploadResponse, RackManagerError> {
            Ok(rpc::protos::rack_manager::FileUploadResponse::default())
        }

        async fn upload_file_chunk(
            &self,
            _data: Vec<u8>,
            _sequence_number: i32,
        ) -> Result<rpc::protos::rack_manager::FileUploadResponse, RackManagerError> {
            Ok(rpc::protos::rack_manager::FileUploadResponse::default())
        }
    }
}
