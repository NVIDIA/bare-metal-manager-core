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

#[cfg(test)]
pub mod test_support {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use librms::protos::rack_manager as rms;
    use librms::{RackManagerError, RmsApi};
    use tokio::sync::Mutex;

    /// RMS simulation for testing, similar to RedfishSim
    pub struct RmsSim {
        fail_add_node: Arc<AtomicBool>,
        fail_inventory_get: Arc<AtomicBool>,
        registered_nodes: Arc<Mutex<Vec<rms::NodeInventoryInfo>>>,
    }

    impl Default for RmsSim {
        fn default() -> Self {
            Self {
                fail_add_node: Arc::new(AtomicBool::new(false)),
                fail_inventory_get: Arc::new(AtomicBool::new(false)),
                registered_nodes: Arc::new(Mutex::new(Vec::new())),
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
    }

    #[derive(Debug, Clone)]
    pub struct MockRmsClient {
        fail_add_node: Arc<AtomicBool>,
        fail_inventory_get: Arc<AtomicBool>,
        registered_nodes: Arc<Mutex<Vec<rms::NodeInventoryInfo>>>,
    }

    #[async_trait::async_trait]
    impl RmsApi for MockRmsClient {
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
                    ip_address: node.ip_address.clone(),
                    port: node.port,
                    mac_address: node.mac_address.clone(),
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
        async fn update_node_firmware(
            &self,
            _cmd: rms::UpdateNodeFirmwareRequest,
        ) -> Result<rms::UpdateNodeFirmwareResponse, RackManagerError> {
            Ok(rms::UpdateNodeFirmwareResponse::default())
        }
        async fn update_firmware_by_node_type(
            &self,
            _cmd: rms::UpdateFirmwareByNodeTypeRequest,
        ) -> Result<rms::UpdateFirmwareByNodeTypeResponse, RackManagerError> {
            Ok(rms::UpdateFirmwareByNodeTypeResponse::default())
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
        async fn update_scale_up_fabric_config(
            &self,
            _cmd: rms::UpdateScaleUpFabricConfigRequest,
        ) -> Result<rms::UpdateScaleUpFabricConfigResponse, RackManagerError> {
            Ok(rms::UpdateScaleUpFabricConfigResponse::default())
        }
        async fn get_scale_up_fabric_state(
            &self,
            _cmd: rms::GetScaleUpFabricStateRequest,
        ) -> Result<rms::GetScaleUpFabricStateResponse, RackManagerError> {
            Ok(rms::GetScaleUpFabricStateResponse::default())
        }
        async fn get_scale_up_fabric_services_status(
            &self,
            _cmd: rms::GetScaleUpFabricServicesStatusRequest,
        ) -> Result<rms::GetScaleUpFabricServicesStatusResponse, RackManagerError> {
            Ok(rms::GetScaleUpFabricServicesStatusResponse::default())
        }
        async fn enable_scale_up_fabric_manager(
            &self,
            _cmd: rms::EnableScaleUpFabricManagerRequest,
        ) -> Result<rms::EnableScaleUpFabricManagerResponse, RackManagerError> {
            Ok(rms::EnableScaleUpFabricManagerResponse::default())
        }
        async fn restart_scale_up_fabric_services(
            &self,
            _cmd: rms::RestartScaleUpFabricServicesRequest,
        ) -> Result<rms::RestartScaleUpFabricServicesResponse, RackManagerError> {
            Ok(rms::RestartScaleUpFabricServicesResponse::default())
        }
        async fn check_scale_up_fabric_services_connectivity(
            &self,
            _cmd: rms::CheckScaleUpFabricServicesConnectivityRequest,
        ) -> Result<rms::CheckScaleUpFabricServicesConnectivityResponse, RackManagerError> {
            Ok(rms::CheckScaleUpFabricServicesConnectivityResponse::default())
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
    }
}
