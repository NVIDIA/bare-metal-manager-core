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

use librms::protos::rack_manager as rms;

#[async_trait::async_trait]
pub trait SwitchSystemImageRmsClient: Send + Sync {
    async fn update_switch_system_image(
        &self,
        cmd: rms::UpdateSwitchSystemImageRequest,
    ) -> Result<rms::UpdateSwitchSystemImageResponse, tonic::Status>;

    async fn get_switch_system_image_job_status(
        &self,
        cmd: rms::GetSwitchSystemImageJobStatusRequest,
    ) -> Result<rms::GetSwitchSystemImageJobStatusResponse, tonic::Status>;
}

#[async_trait::async_trait]
impl SwitchSystemImageRmsClient for librms::RackManagerApi {
    async fn update_switch_system_image(
        &self,
        cmd: rms::UpdateSwitchSystemImageRequest,
    ) -> Result<rms::UpdateSwitchSystemImageResponse, tonic::Status> {
        self.client.update_switch_system_image(cmd).await
    }

    async fn get_switch_system_image_job_status(
        &self,
        cmd: rms::GetSwitchSystemImageJobStatusRequest,
    ) -> Result<rms::GetSwitchSystemImageJobStatusResponse, tonic::Status> {
        self.client.get_switch_system_image_job_status(cmd).await
    }
}

#[cfg(test)]
pub mod test_support {
    use std::collections::{HashMap, VecDeque};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use librms::{RackManagerError, RmsApi};
    use tokio::sync::Mutex;

    use super::{SwitchSystemImageRmsClient, rms};

    /// RMS simulation for testing, similar to RedfishSim
    pub struct RmsSim {
        fail_add_node: Arc<AtomicBool>,
        fail_inventory_get: Arc<AtomicBool>,
        registered_nodes: Arc<Mutex<Vec<rms::NodeInventoryInfo>>>,
        submitted_firmware_requests: Arc<Mutex<Vec<rms::UpdateFirmwareByDeviceListRequest>>>,
        queued_firmware_responses: Arc<Mutex<VecDeque<rms::UpdateFirmwareByDeviceListResponse>>>,
        firmware_job_statuses: Arc<Mutex<HashMap<String, rms::GetFirmwareJobStatusResponse>>>,
        firmware_job_errors: Arc<Mutex<HashMap<String, String>>>,
        submitted_switch_system_image_requests:
            Arc<Mutex<Vec<rms::UpdateSwitchSystemImageRequest>>>,
        queued_switch_system_image_responses:
            Arc<Mutex<VecDeque<rms::UpdateSwitchSystemImageResponse>>>,
        switch_system_image_job_statuses:
            Arc<Mutex<HashMap<String, rms::GetSwitchSystemImageJobStatusResponse>>>,
        switch_system_image_job_errors: Arc<Mutex<HashMap<String, String>>>,
    }

    impl Default for RmsSim {
        fn default() -> Self {
            Self {
                fail_add_node: Arc::new(AtomicBool::new(false)),
                fail_inventory_get: Arc::new(AtomicBool::new(false)),
                registered_nodes: Arc::new(Mutex::new(Vec::new())),
                submitted_firmware_requests: Arc::new(Mutex::new(Vec::new())),
                queued_firmware_responses: Arc::new(Mutex::new(VecDeque::new())),
                firmware_job_statuses: Arc::new(Mutex::new(HashMap::new())),
                firmware_job_errors: Arc::new(Mutex::new(HashMap::new())),
                submitted_switch_system_image_requests: Arc::new(Mutex::new(Vec::new())),
                queued_switch_system_image_responses: Arc::new(Mutex::new(VecDeque::new())),
                switch_system_image_job_statuses: Arc::new(Mutex::new(HashMap::new())),
                switch_system_image_job_errors: Arc::new(Mutex::new(HashMap::new())),
            }
        }
    }

    impl RmsSim {
        /// Convert RmsSim to the type expected by Api and StateHandlerServices
        pub fn as_rms_client(&self) -> Option<Arc<dyn RmsApi>> {
            Some(Arc::new(MockRmsClient {
                fail_add_node: self.fail_add_node.clone(),
                fail_inventory_get: self.fail_inventory_get.clone(),
                registered_nodes: self.registered_nodes.clone(),
                submitted_firmware_requests: self.submitted_firmware_requests.clone(),
                queued_firmware_responses: self.queued_firmware_responses.clone(),
                firmware_job_statuses: self.firmware_job_statuses.clone(),
                firmware_job_errors: self.firmware_job_errors.clone(),
                submitted_switch_system_image_requests: self
                    .submitted_switch_system_image_requests
                    .clone(),
                queued_switch_system_image_responses: self
                    .queued_switch_system_image_responses
                    .clone(),
                switch_system_image_job_statuses: self.switch_system_image_job_statuses.clone(),
                switch_system_image_job_errors: self.switch_system_image_job_errors.clone(),
            }))
        }

        pub fn as_switch_system_image_rms_client(
            &self,
        ) -> Option<Arc<dyn SwitchSystemImageRmsClient>> {
            Some(Arc::new(MockRmsClient {
                fail_add_node: self.fail_add_node.clone(),
                fail_inventory_get: self.fail_inventory_get.clone(),
                registered_nodes: self.registered_nodes.clone(),
                submitted_firmware_requests: self.submitted_firmware_requests.clone(),
                queued_firmware_responses: self.queued_firmware_responses.clone(),
                firmware_job_statuses: self.firmware_job_statuses.clone(),
                firmware_job_errors: self.firmware_job_errors.clone(),
                submitted_switch_system_image_requests: self
                    .submitted_switch_system_image_requests
                    .clone(),
                queued_switch_system_image_responses: self
                    .queued_switch_system_image_responses
                    .clone(),
                switch_system_image_job_statuses: self.switch_system_image_job_statuses.clone(),
                switch_system_image_job_errors: self.switch_system_image_job_errors.clone(),
            }))
        }

        /// Set whether `add_node` should return an error for testing
        /// if registration attempts are failing (and should retry).
        pub fn set_fail_add_node(&self, fail: bool) {
            self.fail_add_node.store(fail, Ordering::Relaxed);
        }

        /// Set whether `inventory_get` should return an error for
        /// testing things like whether RMS membership verification
        /// should retry, or going back to re-registration (or moving
        /// forward thanks to successful registration verification).
        pub fn set_fail_inventory_get(&self, fail: bool) {
            self.fail_inventory_get.store(fail, Ordering::Relaxed);
        }

        pub async fn queue_update_firmware_response(
            &self,
            response: rms::UpdateFirmwareByDeviceListResponse,
        ) {
            self.queued_firmware_responses
                .lock()
                .await
                .push_back(response);
        }

        pub async fn set_firmware_job_status(&self, response: rms::GetFirmwareJobStatusResponse) {
            self.firmware_job_statuses
                .lock()
                .await
                .insert(response.job_id.clone(), response);
        }

        pub async fn set_firmware_job_error(
            &self,
            job_id: impl Into<String>,
            message: impl Into<String>,
        ) {
            self.firmware_job_errors
                .lock()
                .await
                .insert(job_id.into(), message.into());
        }

        pub async fn submitted_firmware_requests(
            &self,
        ) -> Vec<rms::UpdateFirmwareByDeviceListRequest> {
            self.submitted_firmware_requests.lock().await.clone()
        }

        pub async fn queue_update_switch_system_image_response(
            &self,
            response: rms::UpdateSwitchSystemImageResponse,
        ) {
            self.queued_switch_system_image_responses
                .lock()
                .await
                .push_back(response);
        }

        pub async fn set_switch_system_image_job_status(
            &self,
            response: rms::GetSwitchSystemImageJobStatusResponse,
        ) {
            self.switch_system_image_job_statuses
                .lock()
                .await
                .insert(response.job_id.clone(), response);
        }

        pub async fn set_switch_system_image_job_error(
            &self,
            job_id: impl Into<String>,
            message: impl Into<String>,
        ) {
            self.switch_system_image_job_errors
                .lock()
                .await
                .insert(job_id.into(), message.into());
        }

        pub async fn submitted_switch_system_image_requests(
            &self,
        ) -> Vec<rms::UpdateSwitchSystemImageRequest> {
            self.submitted_switch_system_image_requests
                .lock()
                .await
                .clone()
        }
    }

    #[derive(Debug, Clone)]
    pub struct MockRmsClient {
        fail_add_node: Arc<AtomicBool>,
        fail_inventory_get: Arc<AtomicBool>,
        registered_nodes: Arc<Mutex<Vec<rms::NodeInventoryInfo>>>,
        submitted_firmware_requests: Arc<Mutex<Vec<rms::UpdateFirmwareByDeviceListRequest>>>,
        queued_firmware_responses: Arc<Mutex<VecDeque<rms::UpdateFirmwareByDeviceListResponse>>>,
        firmware_job_statuses: Arc<Mutex<HashMap<String, rms::GetFirmwareJobStatusResponse>>>,
        firmware_job_errors: Arc<Mutex<HashMap<String, String>>>,
        submitted_switch_system_image_requests:
            Arc<Mutex<Vec<rms::UpdateSwitchSystemImageRequest>>>,
        queued_switch_system_image_responses:
            Arc<Mutex<VecDeque<rms::UpdateSwitchSystemImageResponse>>>,
        switch_system_image_job_statuses:
            Arc<Mutex<HashMap<String, rms::GetSwitchSystemImageJobStatusResponse>>>,
        switch_system_image_job_errors: Arc<Mutex<HashMap<String, String>>>,
    }

    #[async_trait::async_trait]
    impl RmsApi for MockRmsClient {
        async fn get_device_info_by_device_list(
            &self,
            _cmd: rms::GetDeviceInfoByDeviceListRequest,
        ) -> Result<rms::GetDeviceInfoByDeviceListResponse, RackManagerError> {
            Ok(rms::GetDeviceInfoByDeviceListResponse::default())
        }
        async fn get_node_device_info(
            &self,
            _cmd: rms::GetNodeDeviceInfoRequest,
        ) -> Result<rms::GetNodeDeviceInfoResponse, RackManagerError> {
            Ok(rms::GetNodeDeviceInfoResponse::default())
        }
        async fn get_device_info_by_node_type(
            &self,
            _cmd: rms::GetDeviceInfoByNodeTypeRequest,
        ) -> Result<rms::GetDeviceInfoByNodeTypeResponse, RackManagerError> {
            Ok(rms::GetDeviceInfoByNodeTypeResponse::default())
        }
        async fn update_firmware_by_device_list(
            &self,
            cmd: rms::UpdateFirmwareByDeviceListRequest,
        ) -> Result<rms::UpdateFirmwareByDeviceListResponse, RackManagerError> {
            self.submitted_firmware_requests.lock().await.push(cmd);
            Ok(self
                .queued_firmware_responses
                .lock()
                .await
                .pop_front()
                .unwrap_or_default())
        }
        async fn set_power_state(
            &self,
            _cmd: rms::SetPowerStateRequest,
        ) -> Result<rms::SetPowerStateResponse, RackManagerError> {
            Ok(rms::SetPowerStateResponse::default())
        }
        async fn get_power_state(
            &self,
            _cmd: rms::GetPowerStateRequest,
        ) -> Result<rms::GetPowerStateResponse, RackManagerError> {
            Ok(rms::GetPowerStateResponse::default())
        }
        async fn sequence_rack_power(
            &self,
            _cmd: rms::SequenceRackPowerRequest,
        ) -> Result<rms::SequenceRackPowerResponse, RackManagerError> {
            Ok(rms::SequenceRackPowerResponse::default())
        }
        async fn get_all_inventory(
            &self,
            _cmd: rms::GetAllInventoryRequest,
        ) -> Result<rms::GetAllInventoryResponse, RackManagerError> {
            if self.fail_inventory_get.load(Ordering::Relaxed) {
                return Err(RackManagerError::ApiInvocationError(
                    tonic::Status::unavailable("mock RMS inventory_get failure"),
                ));
            }
            let nodes = self.registered_nodes.lock().await.clone();
            Ok(rms::GetAllInventoryResponse {
                nodes,
                ..Default::default()
            })
        }
        async fn add_node(
            &self,
            cmd: rms::AddNodeRequest,
        ) -> Result<rms::AddNodeResponse, RackManagerError> {
            if self.fail_add_node.load(Ordering::Relaxed) {
                return Err(RackManagerError::ApiInvocationError(
                    tonic::Status::unavailable("mock RMS add_node failure"),
                ));
            }
            // Track registered nodes so inventory_get can find them,
            // just like a real RMS would.
            let mut registered = self.registered_nodes.lock().await;
            for node in cmd.node_info {
                registered.push(librms::protos::rack_manager::NodeInventoryInfo {
                    node_id: node.node_id.clone(),
                    rack_id: node.rack_id.clone(),
                    r#type: node.r#type.unwrap_or(0),
                    ..Default::default()
                });
            }
            Ok(rms::AddNodeResponse::default())
        }
        async fn update_node(
            &self,
            _cmd: rms::UpdateNodeRequest,
        ) -> Result<rms::UpdateNodeResponse, RackManagerError> {
            Ok(rms::UpdateNodeResponse::default())
        }
        async fn remove_node(
            &self,
            _cmd: rms::RemoveNodeRequest,
        ) -> Result<rms::RemoveNodeResponse, RackManagerError> {
            Ok(rms::RemoveNodeResponse::default())
        }
        async fn get_rack_power_on_sequence(
            &self,
            _cmd: rms::GetRackPowerOnSequenceRequest,
        ) -> Result<rms::GetRackPowerOnSequenceResponse, RackManagerError> {
            Ok(rms::GetRackPowerOnSequenceResponse::default())
        }
        async fn set_rack_power_on_sequence(
            &self,
            _cmd: rms::SetRackPowerOnSequenceRequest,
        ) -> Result<rms::SetRackPowerOnSequenceResponse, RackManagerError> {
            Ok(rms::SetRackPowerOnSequenceResponse::default())
        }
        async fn list_racks(
            &self,
            _cmd: rms::ListRacksRequest,
        ) -> Result<rms::ListRacksResponse, RackManagerError> {
            Ok(rms::ListRacksResponse::default())
        }
        async fn get_node_firmware_inventory(
            &self,
            _cmd: rms::GetNodeFirmwareInventoryRequest,
        ) -> Result<rms::GetNodeFirmwareInventoryResponse, RackManagerError> {
            Ok(rms::GetNodeFirmwareInventoryResponse::default())
        }
        async fn get_rack_firmware_inventory(
            &self,
            _cmd: rms::GetRackFirmwareInventoryRequest,
        ) -> Result<rms::GetRackFirmwareInventoryResponse, RackManagerError> {
            Ok(rms::GetRackFirmwareInventoryResponse::default())
        }
        async fn list_firmware_on_switch(
            &self,
            _cmd: rms::ListFirmwareOnSwitchCommand,
        ) -> Result<rms::ListFirmwareOnSwitchResponse, RackManagerError> {
            Ok(rms::ListFirmwareOnSwitchResponse::default())
        }
        async fn push_firmware_to_switch(
            &self,
            _cmd: rms::PushFirmwareToSwitchCommand,
        ) -> Result<rms::PushFirmwareToSwitchResponse, RackManagerError> {
            Ok(rms::PushFirmwareToSwitchResponse::default())
        }
        async fn upgrade_firmware_on_switch(
            &self,
            _cmd: rms::UpgradeFirmwareOnSwitchCommand,
        ) -> Result<rms::UpgradeFirmwareOnSwitchResponse, RackManagerError> {
            Ok(rms::UpgradeFirmwareOnSwitchResponse::default())
        }
        async fn configure_scale_up_fabric_manager(
            &self,
            _cmd: rms::ConfigureScaleUpFabricManagerRequest,
        ) -> Result<rms::ConfigureScaleUpFabricManagerResponse, RackManagerError> {
            Ok(rms::ConfigureScaleUpFabricManagerResponse::default())
        }
        async fn fetch_switch_system_image(
            &self,
            _cmd: rms::FetchSwitchSystemImageRequest,
        ) -> Result<rms::FetchSwitchSystemImageResponse, RackManagerError> {
            Ok(rms::FetchSwitchSystemImageResponse::default())
        }
        async fn install_switch_system_image(
            &self,
            _cmd: rms::InstallSwitchSystemImageRequest,
        ) -> Result<rms::InstallSwitchSystemImageResponse, RackManagerError> {
            Ok(rms::InstallSwitchSystemImageResponse::default())
        }
        async fn list_switch_system_images(
            &self,
            _cmd: rms::ListSwitchSystemImagesRequest,
        ) -> Result<rms::ListSwitchSystemImagesResponse, RackManagerError> {
            Ok(rms::ListSwitchSystemImagesResponse::default())
        }
        async fn enable_scale_up_fabric_telemetry_interface(
            &self,
            _cmd: rms::EnableScaleUpFabricTelemetryInterfaceRequest,
        ) -> Result<rms::EnableScaleUpFabricTelemetryInterfaceResponse, RackManagerError> {
            Ok(rms::EnableScaleUpFabricTelemetryInterfaceResponse::default())
        }
        async fn version(&self) -> Result<(), RackManagerError> {
            Ok(())
        }
        async fn poll_job_status(
            &self,
            _cmd: rms::PollJobStatusCommand,
        ) -> Result<rms::PollJobStatusResponse, RackManagerError> {
            Ok(rms::PollJobStatusResponse::default())
        }
        async fn update_node_firmware_async(
            &self,
            _cmd: rms::UpdateNodeFirmwareRequest,
        ) -> Result<rms::UpdateNodeFirmwareResponse, RackManagerError> {
            Ok(rms::UpdateNodeFirmwareResponse::default())
        }
        async fn update_firmware_by_node_type_async(
            &self,
            _cmd: rms::UpdateFirmwareByNodeTypeRequest,
        ) -> Result<rms::UpdateFirmwareByNodeTypeAsyncResponse, RackManagerError> {
            Ok(rms::UpdateFirmwareByNodeTypeAsyncResponse::default())
        }
        async fn get_firmware_job_status(
            &self,
            cmd: rms::GetFirmwareJobStatusRequest,
        ) -> Result<rms::GetFirmwareJobStatusResponse, RackManagerError> {
            if let Some(message) = self
                .firmware_job_errors
                .lock()
                .await
                .get(&cmd.job_id)
                .cloned()
            {
                return Err(RackManagerError::ApiInvocationError(
                    tonic::Status::unavailable(message),
                ));
            }
            Ok(self
                .firmware_job_statuses
                .lock()
                .await
                .get(&cmd.job_id)
                .cloned()
                .unwrap_or(rms::GetFirmwareJobStatusResponse {
                    status: rms::ReturnCode::Failure as i32,
                    job_id: cmd.job_id,
                    state_description: "mock firmware job not found".to_string(),
                    error_message: "mock firmware job not found".to_string(),
                    ..Default::default()
                }))
        }
    }

    #[async_trait::async_trait]
    impl SwitchSystemImageRmsClient for MockRmsClient {
        async fn update_switch_system_image(
            &self,
            cmd: rms::UpdateSwitchSystemImageRequest,
        ) -> Result<rms::UpdateSwitchSystemImageResponse, tonic::Status> {
            self.submitted_switch_system_image_requests
                .lock()
                .await
                .push(cmd);
            Ok(self
                .queued_switch_system_image_responses
                .lock()
                .await
                .pop_front()
                .unwrap_or_default())
        }

        async fn get_switch_system_image_job_status(
            &self,
            cmd: rms::GetSwitchSystemImageJobStatusRequest,
        ) -> Result<rms::GetSwitchSystemImageJobStatusResponse, tonic::Status> {
            if let Some(message) = self
                .switch_system_image_job_errors
                .lock()
                .await
                .get(&cmd.job_id)
                .cloned()
            {
                return Err(tonic::Status::unavailable(message));
            }

            Ok(self
                .switch_system_image_job_statuses
                .lock()
                .await
                .get(&cmd.job_id)
                .cloned()
                .unwrap_or(rms::GetSwitchSystemImageJobStatusResponse {
                    status: rms::ReturnCode::Failure as i32,
                    job_id: cmd.job_id,
                    message: "mock switch system image job not found".to_string(),
                    error_message: "mock switch system image job not found".to_string(),
                    ..Default::default()
                }))
        }
    }
}
