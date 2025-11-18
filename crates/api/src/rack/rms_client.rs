/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::path::Path;

use forge_tls::client_config::ClientCert;
use rpc::forge_tls_client::{ApiConfig, ForgeClientConfig};
use rpc::protos::rack_manager::{
    NewNodeInfo, PowerComplianceValue, PowerOnOrderItem, PowerOperation, RackPowerOperation,
};
use rpc::protos::rack_manager_client::RackManagerApiClient;

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

fn rms_client_cert_info(
    client_cert_path: Option<String>,
    client_key_path: Option<String>,
) -> Option<ClientCert> {
    if let (Some(client_key_path), Some(client_cert_path)) = (client_key_path, client_cert_path) {
        return Some(ClientCert {
            cert_path: client_cert_path,
            key_path: client_key_path,
        });
    }
    // this is the location for most k8s pods
    if Path::new("/var/run/secrets/spiffe.io/tls.crt").exists()
        && Path::new("/var/run/secrets/spiffe.io/tls.key").exists()
    {
        return Some(ClientCert {
            cert_path: "/var/run/secrets/spiffe.io/tls.crt".to_string(),
            key_path: "/var/run/secrets/spiffe.io/tls.key".to_string(),
        });
    }
    tracing::error!("Client cert and key not found at /var/run/secrets/spiffe.io");
    None
}

fn rms_root_ca_path(forge_root_ca_path: Option<String>) -> String {
    // First from command line, second env var.
    if let Some(forge_root_ca_path) = forge_root_ca_path {
        return forge_root_ca_path;
    }
    // this is the location for most k8s pods
    if Path::new("/var/run/secrets/spiffe.io/ca.crt").exists() {
        return "/var/run/secrets/spiffe.io/ca.crt".to_string();
    }
    tracing::error!("Root CA path not found at /var/run/secrets/spiffe.io");
    "".to_string()
}

pub struct RmsClientPool {
    pub client: RackManagerApi,
}

impl RmsClientPool {
    pub fn new(rms_api_url: &str) -> Self {
        let client = RackManagerApi::new(None, None, None, rms_api_url);
        Self { client }
    }
}

#[async_trait::async_trait]
pub trait RackManagerClientPool: Send + Sync + 'static {
    async fn create_client(self) -> Box<dyn RmsApi>;
}

#[async_trait::async_trait]
impl RackManagerClientPool for RmsClientPool {
    async fn create_client(self) -> Box<dyn RmsApi> {
        self.client.build().await
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
        let root_ca = rms_root_ca_path(root_ca_path);
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
    async fn build(&self) -> Box<dyn RmsApi>;
    async fn inventory_get(
        &self,
    ) -> Result<rpc::protos::rack_manager::InventoryResponse, RackManagerError>;
    async fn add_node(
        &self,
        new_nodes: Vec<NewNodeInfo>,
    ) -> Result<rpc::protos::rack_manager::InventoryResponse, RackManagerError>;
    async fn remove_node(
        &self,
        node_id: String,
    ) -> Result<rpc::protos::rack_manager::InventoryResponse, RackManagerError>;
    async fn get_poweron_order(
        &self,
    ) -> Result<rpc::protos::rack_manager::InventoryResponse, RackManagerError>;
    async fn set_poweron_order(
        &self,
        poweron_order: Vec<PowerOnOrderItem>,
    ) -> Result<rpc::protos::rack_manager::InventoryResponse, RackManagerError>;
    async fn get_power_state(
        &self,
        node_id: String,
    ) -> Result<rpc::protos::rack_manager::PowerControlResponse, RackManagerError>;
    async fn set_power_state(
        &self,
        node_id: String,
        operation: PowerOperation,
    ) -> Result<rpc::protos::rack_manager::PowerControlResponse, RackManagerError>;
    async fn rack_power(
        &self,
        operation: RackPowerOperation,
    ) -> Result<rpc::protos::rack_manager::PowerControlResponse, RackManagerError>;
    async fn get_firmware_inventory(
        &self,
        node_id: String,
    ) -> Result<rpc::protos::rack_manager::FirmwareResponse, RackManagerError>;
    async fn update_firmware(
        &self,
        node_id: String,
        filename: String,
        target: String,
    ) -> Result<rpc::protos::rack_manager::FirmwareResponse, RackManagerError>;
    async fn update_firmware_by_node_type(
        &self,
        node_type: i32,
        filename: String,
        target: String,
    ) -> Result<rpc::protos::rack_manager::FirmwareResponse, RackManagerError>;
    async fn get_available_fw_images(
        &self,
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
    async fn build(&self) -> Box<dyn RmsApi> {
        /*
        // Test the connection now, so that we don't do it N times in N different workers.
        self.client
            .connection()
            .await
            .map_err(RackManagerError::from)?;
            // returning an error will require having a sim client with a no error build
        */
        Box::new(self.clone())
    }

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

    #[allow(dead_code)]
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
        node_id: String,
    ) -> Result<rpc::protos::rack_manager::InventoryResponse, RackManagerError> {
        let remove_node_command = rpc::protos::rack_manager::RemoveNodeCommand { node_id };
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
    ) -> Result<rpc::protos::rack_manager::InventoryResponse, RackManagerError> {
        let cmd: rpc::protos::rack_manager::inventory_request::Command =
            rpc::protos::rack_manager::inventory_request::Command::GetPowerOnOrder(
                Default::default(),
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
        poweron_order: Vec<PowerOnOrderItem>,
    ) -> Result<rpc::protos::rack_manager::InventoryResponse, RackManagerError> {
        let set_poweron_order_command = rpc::protos::rack_manager::SetPowerOnOrderCommand {
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
        node_id: String,
    ) -> Result<rpc::protos::rack_manager::PowerControlResponse, RackManagerError> {
        let get_power_state_command =
            rpc::protos::rack_manager::GetPowerStateCommand { node: node_id };
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
        node_id: String,
        operation: PowerOperation,
    ) -> Result<rpc::protos::rack_manager::PowerControlResponse, RackManagerError> {
        let set_power_state_command = rpc::protos::rack_manager::SetPowerStateCommand {
            node: node_id,
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
        operation: RackPowerOperation,
    ) -> Result<rpc::protos::rack_manager::PowerControlResponse, RackManagerError> {
        let rack_power_command = rpc::protos::rack_manager::RackPowerCommand {
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
        node_id: String,
    ) -> Result<rpc::protos::rack_manager::FirmwareResponse, RackManagerError> {
        let get_firmware_inventory_command =
            rpc::protos::rack_manager::GetFirmwareInventoryCommand { node: node_id };
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
        node: String,
        filename: String,
        target: String,
    ) -> Result<rpc::protos::rack_manager::FirmwareResponse, RackManagerError> {
        let update_firmware_command = rpc::protos::rack_manager::UpdateFirmwareCommand {
            node,
            filename,
            target,
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
        node_type: i32,
        filename: String,
        target: String,
    ) -> Result<rpc::protos::rack_manager::FirmwareResponse, RackManagerError> {
        let update_firmware_by_node_type_command =
            rpc::protos::rack_manager::UpdateFirmwareByNodeTypeCommand {
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
        node_id: String,
    ) -> Result<rpc::protos::rack_manager::FirmwareResponse, RackManagerError> {
        let get_available_fw_images_command =
            rpc::protos::rack_manager::GetAvailableFwImagesCommand {
                node: Some(node_id),
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
