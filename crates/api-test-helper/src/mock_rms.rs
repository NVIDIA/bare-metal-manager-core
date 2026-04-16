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

//! MockRmsApi is a configurable mock implementation of librms::RmsApi.
//!
//! The idea is tests queue up responses for each method they care about
//! and want to test, then hand an `Arc<MockRmsApi>` to the code under test.
//! As methods are called, queued responses are popped off and returned in
//! order. Recorded requests can be inspected after the call to verify the
//! correct arguments were sent.
//!
//! # Example
//!
//! ```ignore
//! let mock = MockRmsApi::new();
//! mock.enqueue_power_state(Ok(MockRmsApi::power_ok())).await;
//!
//! let backend = RmsPowerShelfBackend::new(Arc::new(mock));
//! let results = backend.power_control(&endpoints, PowerAction::On).await.unwrap();
//!
//! assert!(results[0].success);
//! let calls = mock.power_state_calls().await;
//! assert_eq!(calls[0].node_id, "ps-001");
//! ```

use std::collections::VecDeque;
use std::sync::Arc;

use librms::protos::rack_manager as rms;
use librms::{RackManagerError, RmsApi};
use tokio::sync::Mutex;

/// A configurable mock `RmsApi` client that lets tests queue responses
/// per method and inspect what requests were sent.
///
/// Every `RmsApi` method has a corresponding:
/// - `enqueue_*()` — push a response to be returned on the next call
/// - `*_calls()` — retrieve all recorded requests for that method
///
/// If no response is queued when a method is called, it returns a
/// clear "no response queued" error so tests fail explicitly.
pub struct MockRmsApi {
    // Power control calls.
    set_power_state_responses:
        Mutex<VecDeque<Result<rms::SetPowerStateResponse, RackManagerError>>>,
    set_power_state_calls: Mutex<Vec<rms::SetPowerStateRequest>>,

    get_power_state_responses:
        Mutex<VecDeque<Result<rms::GetPowerStateResponse, RackManagerError>>>,
    get_power_state_calls: Mutex<Vec<rms::GetPowerStateRequest>>,

    sequence_rack_power_responses:
        Mutex<VecDeque<Result<rms::SequenceRackPowerResponse, RackManagerError>>>,
    sequence_rack_power_calls: Mutex<Vec<rms::SequenceRackPowerRequest>>,

    // Inventory calls.
    get_all_inventory_responses:
        Mutex<VecDeque<Result<rms::GetAllInventoryResponse, RackManagerError>>>,
    get_all_inventory_calls: Mutex<Vec<rms::GetAllInventoryRequest>>,

    add_node_responses: Mutex<VecDeque<Result<rms::AddNodeResponse, RackManagerError>>>,
    add_node_calls: Mutex<Vec<rms::AddNodeRequest>>,

    update_node_responses: Mutex<VecDeque<Result<rms::UpdateNodeResponse, RackManagerError>>>,
    update_node_calls: Mutex<Vec<rms::UpdateNodeRequest>>,

    remove_node_responses: Mutex<VecDeque<Result<rms::RemoveNodeResponse, RackManagerError>>>,
    remove_node_calls: Mutex<Vec<rms::RemoveNodeRequest>>,

    list_racks_responses: Mutex<VecDeque<Result<rms::ListRacksResponse, RackManagerError>>>,
    list_racks_calls: Mutex<Vec<rms::ListRacksRequest>>,

    // Device info calls.
    get_node_device_info_responses:
        Mutex<VecDeque<Result<rms::GetNodeDeviceInfoResponse, RackManagerError>>>,
    get_node_device_info_calls: Mutex<Vec<rms::GetNodeDeviceInfoRequest>>,

    get_device_info_by_node_type_responses:
        Mutex<VecDeque<Result<rms::GetDeviceInfoByNodeTypeResponse, RackManagerError>>>,
    get_device_info_by_node_type_calls: Mutex<Vec<rms::GetDeviceInfoByNodeTypeRequest>>,

    get_device_info_by_device_list_responses:
        Mutex<VecDeque<Result<rms::GetDeviceInfoByDeviceListResponse, RackManagerError>>>,
    get_device_info_by_device_list_calls: Mutex<Vec<rms::GetDeviceInfoByDeviceListRequest>>,

    // Power-on sequence calls.
    get_rack_power_on_sequence_responses:
        Mutex<VecDeque<Result<rms::GetRackPowerOnSequenceResponse, RackManagerError>>>,
    get_rack_power_on_sequence_calls: Mutex<Vec<rms::GetRackPowerOnSequenceRequest>>,

    set_rack_power_on_sequence_responses:
        Mutex<VecDeque<Result<rms::SetRackPowerOnSequenceResponse, RackManagerError>>>,
    set_rack_power_on_sequence_calls: Mutex<Vec<rms::SetRackPowerOnSequenceRequest>>,

    // Node firmware calls.
    get_node_firmware_inventory_responses:
        Mutex<VecDeque<Result<rms::GetNodeFirmwareInventoryResponse, RackManagerError>>>,
    get_node_firmware_inventory_calls: Mutex<Vec<rms::GetNodeFirmwareInventoryRequest>>,

    get_rack_firmware_inventory_responses:
        Mutex<VecDeque<Result<rms::GetRackFirmwareInventoryResponse, RackManagerError>>>,
    get_rack_firmware_inventory_calls: Mutex<Vec<rms::GetRackFirmwareInventoryRequest>>,

    update_node_firmware_async_responses:
        Mutex<VecDeque<Result<rms::UpdateNodeFirmwareResponse, RackManagerError>>>,
    update_node_firmware_async_calls: Mutex<Vec<rms::UpdateNodeFirmwareRequest>>,

    update_firmware_by_node_type_async_responses:
        Mutex<VecDeque<Result<rms::UpdateFirmwareByNodeTypeAsyncResponse, RackManagerError>>>,
    update_firmware_by_node_type_async_calls: Mutex<Vec<rms::UpdateFirmwareByNodeTypeRequest>>,

    update_firmware_by_device_list_responses:
        Mutex<VecDeque<Result<rms::UpdateFirmwareByDeviceListResponse, RackManagerError>>>,
    update_firmware_by_device_list_calls: Mutex<Vec<rms::UpdateFirmwareByDeviceListRequest>>,

    get_firmware_job_status_responses:
        Mutex<VecDeque<Result<rms::GetFirmwareJobStatusResponse, RackManagerError>>>,
    get_firmware_job_status_calls: Mutex<Vec<rms::GetFirmwareJobStatusRequest>>,

    // Switch firmware calls.
    list_firmware_on_switch_responses:
        Mutex<VecDeque<Result<rms::ListFirmwareOnSwitchResponse, RackManagerError>>>,
    list_firmware_on_switch_calls: Mutex<Vec<rms::ListFirmwareOnSwitchCommand>>,

    push_firmware_to_switch_responses:
        Mutex<VecDeque<Result<rms::PushFirmwareToSwitchResponse, RackManagerError>>>,
    push_firmware_to_switch_calls: Mutex<Vec<rms::PushFirmwareToSwitchCommand>>,

    upgrade_firmware_on_switch_responses:
        Mutex<VecDeque<Result<rms::UpgradeFirmwareOnSwitchResponse, RackManagerError>>>,
    upgrade_firmware_on_switch_calls: Mutex<Vec<rms::UpgradeFirmwareOnSwitchCommand>>,

    // Switch system images calls.
    fetch_switch_system_image_responses:
        Mutex<VecDeque<Result<rms::FetchSwitchSystemImageResponse, RackManagerError>>>,
    fetch_switch_system_image_calls: Mutex<Vec<rms::FetchSwitchSystemImageRequest>>,

    install_switch_system_image_responses:
        Mutex<VecDeque<Result<rms::InstallSwitchSystemImageResponse, RackManagerError>>>,
    install_switch_system_image_calls: Mutex<Vec<rms::InstallSwitchSystemImageRequest>>,

    list_switch_system_images_responses:
        Mutex<VecDeque<Result<rms::ListSwitchSystemImagesResponse, RackManagerError>>>,
    list_switch_system_images_calls: Mutex<Vec<rms::ListSwitchSystemImagesRequest>>,

    poll_job_status_responses:
        Mutex<VecDeque<Result<rms::PollJobStatusResponse, RackManagerError>>>,
    poll_job_status_calls: Mutex<Vec<rms::PollJobStatusCommand>>,

    // Scale-up fabric calls.
    configure_scale_up_fabric_manager_responses:
        Mutex<VecDeque<Result<rms::ConfigureScaleUpFabricManagerResponse, RackManagerError>>>,
    configure_scale_up_fabric_manager_calls: Mutex<Vec<rms::ConfigureScaleUpFabricManagerRequest>>,

    enable_scale_up_fabric_telemetry_interface_responses: Mutex<
        VecDeque<Result<rms::EnableScaleUpFabricTelemetryInterfaceResponse, RackManagerError>>,
    >,
    enable_scale_up_fabric_telemetry_interface_calls:
        Mutex<Vec<rms::EnableScaleUpFabricTelemetryInterfaceRequest>>,

    // Version (no request type).
    version_responses: Mutex<VecDeque<Result<(), RackManagerError>>>,
    version_call_count: Mutex<u32>,
}

/// Generate enqueue + inspect methods for a request/response pair.
macro_rules! impl_enqueue_inspect {
    ($enqueue:ident, $inspect:ident, $responses:ident, $calls:ident, $req:ty, $resp:ty) => {
        pub async fn $enqueue(&self, resp: Result<$resp, RackManagerError>) {
            self.$responses.lock().await.push_back(resp);
        }

        pub async fn $inspect(&self) -> Vec<$req> {
            self.$calls.lock().await.clone()
        }
    };
}

impl MockRmsApi {
    pub fn new() -> Self {
        Self {
            set_power_state_responses: Default::default(),
            set_power_state_calls: Default::default(),
            get_power_state_responses: Default::default(),
            get_power_state_calls: Default::default(),
            sequence_rack_power_responses: Default::default(),
            sequence_rack_power_calls: Default::default(),
            get_all_inventory_responses: Default::default(),
            get_all_inventory_calls: Default::default(),
            add_node_responses: Default::default(),
            add_node_calls: Default::default(),
            update_node_responses: Default::default(),
            update_node_calls: Default::default(),
            remove_node_responses: Default::default(),
            remove_node_calls: Default::default(),
            list_racks_responses: Default::default(),
            list_racks_calls: Default::default(),
            get_node_device_info_responses: Default::default(),
            get_node_device_info_calls: Default::default(),
            get_device_info_by_node_type_responses: Default::default(),
            get_device_info_by_node_type_calls: Default::default(),
            get_device_info_by_device_list_responses: Default::default(),
            get_device_info_by_device_list_calls: Default::default(),
            get_rack_power_on_sequence_responses: Default::default(),
            get_rack_power_on_sequence_calls: Default::default(),
            set_rack_power_on_sequence_responses: Default::default(),
            set_rack_power_on_sequence_calls: Default::default(),
            get_node_firmware_inventory_responses: Default::default(),
            get_node_firmware_inventory_calls: Default::default(),
            get_rack_firmware_inventory_responses: Default::default(),
            get_rack_firmware_inventory_calls: Default::default(),
            update_node_firmware_async_responses: Default::default(),
            update_node_firmware_async_calls: Default::default(),
            update_firmware_by_node_type_async_responses: Default::default(),
            update_firmware_by_node_type_async_calls: Default::default(),
            update_firmware_by_device_list_responses: Default::default(),
            update_firmware_by_device_list_calls: Default::default(),
            get_firmware_job_status_responses: Default::default(),
            get_firmware_job_status_calls: Default::default(),
            list_firmware_on_switch_responses: Default::default(),
            list_firmware_on_switch_calls: Default::default(),
            push_firmware_to_switch_responses: Default::default(),
            push_firmware_to_switch_calls: Default::default(),
            upgrade_firmware_on_switch_responses: Default::default(),
            upgrade_firmware_on_switch_calls: Default::default(),
            fetch_switch_system_image_responses: Default::default(),
            fetch_switch_system_image_calls: Default::default(),
            install_switch_system_image_responses: Default::default(),
            install_switch_system_image_calls: Default::default(),
            list_switch_system_images_responses: Default::default(),
            list_switch_system_images_calls: Default::default(),
            poll_job_status_responses: Default::default(),
            poll_job_status_calls: Default::default(),
            configure_scale_up_fabric_manager_responses: Default::default(),
            configure_scale_up_fabric_manager_calls: Default::default(),
            enable_scale_up_fabric_telemetry_interface_responses: Default::default(),
            enable_scale_up_fabric_telemetry_interface_calls: Default::default(),
            version_responses: Default::default(),
            version_call_count: Default::default(),
        }
    }

    /// Wrap in `Arc` for passing to code that expects `Arc<dyn RmsApi>`.
    pub fn into_arc(self) -> Arc<dyn RmsApi> {
        Arc::new(self)
    }

    // Power control
    impl_enqueue_inspect!(
        enqueue_set_power_state,
        set_power_state_calls,
        set_power_state_responses,
        set_power_state_calls,
        rms::SetPowerStateRequest,
        rms::SetPowerStateResponse
    );
    impl_enqueue_inspect!(
        enqueue_get_power_state,
        get_power_state_calls,
        get_power_state_responses,
        get_power_state_calls,
        rms::GetPowerStateRequest,
        rms::GetPowerStateResponse
    );
    impl_enqueue_inspect!(
        enqueue_sequence_rack_power,
        sequence_rack_power_calls,
        sequence_rack_power_responses,
        sequence_rack_power_calls,
        rms::SequenceRackPowerRequest,
        rms::SequenceRackPowerResponse
    );

    // Inventory
    impl_enqueue_inspect!(
        enqueue_get_all_inventory,
        get_all_inventory_calls,
        get_all_inventory_responses,
        get_all_inventory_calls,
        rms::GetAllInventoryRequest,
        rms::GetAllInventoryResponse
    );
    impl_enqueue_inspect!(
        enqueue_add_node,
        add_node_calls,
        add_node_responses,
        add_node_calls,
        rms::AddNodeRequest,
        rms::AddNodeResponse
    );
    impl_enqueue_inspect!(
        enqueue_update_node,
        update_node_calls,
        update_node_responses,
        update_node_calls,
        rms::UpdateNodeRequest,
        rms::UpdateNodeResponse
    );
    impl_enqueue_inspect!(
        enqueue_remove_node,
        remove_node_calls,
        remove_node_responses,
        remove_node_calls,
        rms::RemoveNodeRequest,
        rms::RemoveNodeResponse
    );
    impl_enqueue_inspect!(
        enqueue_list_racks,
        list_racks_calls,
        list_racks_responses,
        list_racks_calls,
        rms::ListRacksRequest,
        rms::ListRacksResponse
    );

    // Device info
    impl_enqueue_inspect!(
        enqueue_get_node_device_info,
        get_node_device_info_calls,
        get_node_device_info_responses,
        get_node_device_info_calls,
        rms::GetNodeDeviceInfoRequest,
        rms::GetNodeDeviceInfoResponse
    );
    impl_enqueue_inspect!(
        enqueue_get_device_info_by_node_type,
        get_device_info_by_node_type_calls,
        get_device_info_by_node_type_responses,
        get_device_info_by_node_type_calls,
        rms::GetDeviceInfoByNodeTypeRequest,
        rms::GetDeviceInfoByNodeTypeResponse
    );
    impl_enqueue_inspect!(
        enqueue_get_device_info_by_device_list,
        get_device_info_by_device_list_calls,
        get_device_info_by_device_list_responses,
        get_device_info_by_device_list_calls,
        rms::GetDeviceInfoByDeviceListRequest,
        rms::GetDeviceInfoByDeviceListResponse
    );

    // Power-on sequence
    impl_enqueue_inspect!(
        enqueue_get_rack_power_on_sequence,
        get_rack_power_on_sequence_calls,
        get_rack_power_on_sequence_responses,
        get_rack_power_on_sequence_calls,
        rms::GetRackPowerOnSequenceRequest,
        rms::GetRackPowerOnSequenceResponse
    );
    impl_enqueue_inspect!(
        enqueue_set_rack_power_on_sequence,
        set_rack_power_on_sequence_calls,
        set_rack_power_on_sequence_responses,
        set_rack_power_on_sequence_calls,
        rms::SetRackPowerOnSequenceRequest,
        rms::SetRackPowerOnSequenceResponse
    );

    // Node firmware
    impl_enqueue_inspect!(
        enqueue_get_node_firmware_inventory,
        get_node_firmware_inventory_calls,
        get_node_firmware_inventory_responses,
        get_node_firmware_inventory_calls,
        rms::GetNodeFirmwareInventoryRequest,
        rms::GetNodeFirmwareInventoryResponse
    );
    impl_enqueue_inspect!(
        enqueue_get_rack_firmware_inventory,
        get_rack_firmware_inventory_calls,
        get_rack_firmware_inventory_responses,
        get_rack_firmware_inventory_calls,
        rms::GetRackFirmwareInventoryRequest,
        rms::GetRackFirmwareInventoryResponse
    );
    impl_enqueue_inspect!(
        enqueue_update_node_firmware_async,
        update_node_firmware_async_calls,
        update_node_firmware_async_responses,
        update_node_firmware_async_calls,
        rms::UpdateNodeFirmwareRequest,
        rms::UpdateNodeFirmwareResponse
    );
    impl_enqueue_inspect!(
        enqueue_update_firmware_by_node_type_async,
        update_firmware_by_node_type_async_calls,
        update_firmware_by_node_type_async_responses,
        update_firmware_by_node_type_async_calls,
        rms::UpdateFirmwareByNodeTypeRequest,
        rms::UpdateFirmwareByNodeTypeAsyncResponse
    );
    impl_enqueue_inspect!(
        enqueue_update_firmware_by_device_list,
        update_firmware_by_device_list_calls,
        update_firmware_by_device_list_responses,
        update_firmware_by_device_list_calls,
        rms::UpdateFirmwareByDeviceListRequest,
        rms::UpdateFirmwareByDeviceListResponse
    );
    impl_enqueue_inspect!(
        enqueue_get_firmware_job_status,
        get_firmware_job_status_calls,
        get_firmware_job_status_responses,
        get_firmware_job_status_calls,
        rms::GetFirmwareJobStatusRequest,
        rms::GetFirmwareJobStatusResponse
    );

    // Switch firmware
    impl_enqueue_inspect!(
        enqueue_list_firmware_on_switch,
        list_firmware_on_switch_calls,
        list_firmware_on_switch_responses,
        list_firmware_on_switch_calls,
        rms::ListFirmwareOnSwitchCommand,
        rms::ListFirmwareOnSwitchResponse
    );
    impl_enqueue_inspect!(
        enqueue_push_firmware_to_switch,
        push_firmware_to_switch_calls,
        push_firmware_to_switch_responses,
        push_firmware_to_switch_calls,
        rms::PushFirmwareToSwitchCommand,
        rms::PushFirmwareToSwitchResponse
    );
    impl_enqueue_inspect!(
        enqueue_upgrade_firmware_on_switch,
        upgrade_firmware_on_switch_calls,
        upgrade_firmware_on_switch_responses,
        upgrade_firmware_on_switch_calls,
        rms::UpgradeFirmwareOnSwitchCommand,
        rms::UpgradeFirmwareOnSwitchResponse
    );

    // Switch system images
    impl_enqueue_inspect!(
        enqueue_fetch_switch_system_image,
        fetch_switch_system_image_calls,
        fetch_switch_system_image_responses,
        fetch_switch_system_image_calls,
        rms::FetchSwitchSystemImageRequest,
        rms::FetchSwitchSystemImageResponse
    );
    impl_enqueue_inspect!(
        enqueue_install_switch_system_image,
        install_switch_system_image_calls,
        install_switch_system_image_responses,
        install_switch_system_image_calls,
        rms::InstallSwitchSystemImageRequest,
        rms::InstallSwitchSystemImageResponse
    );
    impl_enqueue_inspect!(
        enqueue_list_switch_system_images,
        list_switch_system_images_calls,
        list_switch_system_images_responses,
        list_switch_system_images_calls,
        rms::ListSwitchSystemImagesRequest,
        rms::ListSwitchSystemImagesResponse
    );
    impl_enqueue_inspect!(
        enqueue_poll_job_status,
        poll_job_status_calls,
        poll_job_status_responses,
        poll_job_status_calls,
        rms::PollJobStatusCommand,
        rms::PollJobStatusResponse
    );

    // Scale-up fabric
    impl_enqueue_inspect!(
        enqueue_configure_scale_up_fabric_manager,
        configure_scale_up_fabric_manager_calls,
        configure_scale_up_fabric_manager_responses,
        configure_scale_up_fabric_manager_calls,
        rms::ConfigureScaleUpFabricManagerRequest,
        rms::ConfigureScaleUpFabricManagerResponse
    );
    impl_enqueue_inspect!(
        enqueue_enable_scale_up_fabric_telemetry_interface,
        enable_scale_up_fabric_telemetry_interface_calls,
        enable_scale_up_fabric_telemetry_interface_responses,
        enable_scale_up_fabric_telemetry_interface_calls,
        rms::EnableScaleUpFabricTelemetryInterfaceRequest,
        rms::EnableScaleUpFabricTelemetryInterfaceResponse
    );

    // Version (special — no request type)
    pub async fn enqueue_version(&self, resp: Result<(), RackManagerError>) {
        self.version_responses.lock().await.push_back(resp);
    }

    pub async fn version_call_count(&self) -> u32 {
        *self.version_call_count.lock().await
    }

    // ...and put a few response builders/helpers in here.

    /// Success response for `set_power_state`.
    pub fn power_ok() -> rms::SetPowerStateResponse {
        rms::SetPowerStateResponse {
            status: rms::ReturnCode::Success as i32,
            ..Default::default()
        }
    }

    /// Failure response for `set_power_state`.
    pub fn power_fail() -> rms::SetPowerStateResponse {
        rms::SetPowerStateResponse {
            status: rms::ReturnCode::Failure as i32,
            ..Default::default()
        }
    }

    /// Success response for `update_node_firmware_async` with a job ID.
    pub fn firmware_update_ok(job_id: &str) -> rms::UpdateNodeFirmwareResponse {
        rms::UpdateNodeFirmwareResponse {
            status: rms::ReturnCode::Success as i32,
            job_id: job_id.to_owned(),
            ..Default::default()
        }
    }

    /// Failure response for `update_node_firmware_async`.
    pub fn firmware_update_fail(msg: &str) -> rms::UpdateNodeFirmwareResponse {
        rms::UpdateNodeFirmwareResponse {
            status: rms::ReturnCode::Failure as i32,
            message: msg.to_owned(),
            ..Default::default()
        }
    }

    /// Success response for `get_firmware_job_status`.
    pub fn firmware_job_status_ok(
        state: rms::FirmwareJobState,
    ) -> rms::GetFirmwareJobStatusResponse {
        rms::GetFirmwareJobStatusResponse {
            status: rms::ReturnCode::Success as i32,
            job_state: state as i32,
            ..Default::default()
        }
    }

    /// Success response for `get_node_firmware_inventory`.
    pub fn firmware_inventory_ok(
        versions: &[(&str, &str)],
    ) -> rms::GetNodeFirmwareInventoryResponse {
        rms::GetNodeFirmwareInventoryResponse {
            status: rms::ReturnCode::Success as i32,
            firmware_list: versions
                .iter()
                .map(|(name, ver)| rms::FirmwareInventoryInfo {
                    name: name.to_string(),
                    version: ver.to_string(),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        }
    }

    /// Build an RMS API error (useful for simulating transport failures).
    pub fn unavailable(msg: &str) -> RackManagerError {
        RackManagerError::ApiInvocationError(tonic::Status::unavailable(msg))
    }
}

impl Default for MockRmsApi {
    fn default() -> Self {
        Self::new()
    }
}

/// Error returned when a test forgets to enqueue a response.
fn no_response_queued() -> RackManagerError {
    RackManagerError::ApiInvocationError(tonic::Status::internal("mock: no response queued"))
}

/// Pop the next queued response, or return a clear error if none was enqueued.
fn pop_or_err<T>(
    q: &mut tokio::sync::MutexGuard<'_, VecDeque<Result<T, RackManagerError>>>,
) -> Result<T, RackManagerError> {
    q.pop_front().unwrap_or(Err(no_response_queued()))
}

#[async_trait::async_trait]
impl RmsApi for MockRmsApi {
    async fn set_power_state(
        &self,
        cmd: rms::SetPowerStateRequest,
    ) -> Result<rms::SetPowerStateResponse, RackManagerError> {
        self.set_power_state_calls.lock().await.push(cmd);
        pop_or_err(&mut self.set_power_state_responses.lock().await)
    }
    async fn get_power_state(
        &self,
        cmd: rms::GetPowerStateRequest,
    ) -> Result<rms::GetPowerStateResponse, RackManagerError> {
        self.get_power_state_calls.lock().await.push(cmd);
        pop_or_err(&mut self.get_power_state_responses.lock().await)
    }
    async fn sequence_rack_power(
        &self,
        cmd: rms::SequenceRackPowerRequest,
    ) -> Result<rms::SequenceRackPowerResponse, RackManagerError> {
        self.sequence_rack_power_calls.lock().await.push(cmd);
        pop_or_err(&mut self.sequence_rack_power_responses.lock().await)
    }
    async fn get_all_inventory(
        &self,
        cmd: rms::GetAllInventoryRequest,
    ) -> Result<rms::GetAllInventoryResponse, RackManagerError> {
        self.get_all_inventory_calls.lock().await.push(cmd);
        pop_or_err(&mut self.get_all_inventory_responses.lock().await)
    }
    async fn add_node(
        &self,
        cmd: rms::AddNodeRequest,
    ) -> Result<rms::AddNodeResponse, RackManagerError> {
        self.add_node_calls.lock().await.push(cmd);
        pop_or_err(&mut self.add_node_responses.lock().await)
    }
    async fn update_node(
        &self,
        cmd: rms::UpdateNodeRequest,
    ) -> Result<rms::UpdateNodeResponse, RackManagerError> {
        self.update_node_calls.lock().await.push(cmd);
        pop_or_err(&mut self.update_node_responses.lock().await)
    }
    async fn remove_node(
        &self,
        cmd: rms::RemoveNodeRequest,
    ) -> Result<rms::RemoveNodeResponse, RackManagerError> {
        self.remove_node_calls.lock().await.push(cmd);
        pop_or_err(&mut self.remove_node_responses.lock().await)
    }
    async fn list_racks(
        &self,
        cmd: rms::ListRacksRequest,
    ) -> Result<rms::ListRacksResponse, RackManagerError> {
        self.list_racks_calls.lock().await.push(cmd);
        pop_or_err(&mut self.list_racks_responses.lock().await)
    }
    async fn get_node_device_info(
        &self,
        cmd: rms::GetNodeDeviceInfoRequest,
    ) -> Result<rms::GetNodeDeviceInfoResponse, RackManagerError> {
        self.get_node_device_info_calls.lock().await.push(cmd);
        pop_or_err(&mut self.get_node_device_info_responses.lock().await)
    }
    async fn get_device_info_by_node_type(
        &self,
        cmd: rms::GetDeviceInfoByNodeTypeRequest,
    ) -> Result<rms::GetDeviceInfoByNodeTypeResponse, RackManagerError> {
        self.get_device_info_by_node_type_calls
            .lock()
            .await
            .push(cmd);
        pop_or_err(&mut self.get_device_info_by_node_type_responses.lock().await)
    }
    async fn get_device_info_by_device_list(
        &self,
        cmd: rms::GetDeviceInfoByDeviceListRequest,
    ) -> Result<rms::GetDeviceInfoByDeviceListResponse, RackManagerError> {
        self.get_device_info_by_device_list_calls
            .lock()
            .await
            .push(cmd);
        pop_or_err(&mut self.get_device_info_by_device_list_responses.lock().await)
    }
    async fn get_rack_power_on_sequence(
        &self,
        cmd: rms::GetRackPowerOnSequenceRequest,
    ) -> Result<rms::GetRackPowerOnSequenceResponse, RackManagerError> {
        self.get_rack_power_on_sequence_calls.lock().await.push(cmd);
        pop_or_err(&mut self.get_rack_power_on_sequence_responses.lock().await)
    }
    async fn set_rack_power_on_sequence(
        &self,
        cmd: rms::SetRackPowerOnSequenceRequest,
    ) -> Result<rms::SetRackPowerOnSequenceResponse, RackManagerError> {
        self.set_rack_power_on_sequence_calls.lock().await.push(cmd);
        pop_or_err(&mut self.set_rack_power_on_sequence_responses.lock().await)
    }
    async fn get_node_firmware_inventory(
        &self,
        cmd: rms::GetNodeFirmwareInventoryRequest,
    ) -> Result<rms::GetNodeFirmwareInventoryResponse, RackManagerError> {
        self.get_node_firmware_inventory_calls
            .lock()
            .await
            .push(cmd);
        pop_or_err(&mut self.get_node_firmware_inventory_responses.lock().await)
    }
    async fn get_rack_firmware_inventory(
        &self,
        cmd: rms::GetRackFirmwareInventoryRequest,
    ) -> Result<rms::GetRackFirmwareInventoryResponse, RackManagerError> {
        self.get_rack_firmware_inventory_calls
            .lock()
            .await
            .push(cmd);
        pop_or_err(&mut self.get_rack_firmware_inventory_responses.lock().await)
    }
    async fn update_node_firmware_async(
        &self,
        cmd: rms::UpdateNodeFirmwareRequest,
    ) -> Result<rms::UpdateNodeFirmwareResponse, RackManagerError> {
        self.update_node_firmware_async_calls.lock().await.push(cmd);
        pop_or_err(&mut self.update_node_firmware_async_responses.lock().await)
    }
    async fn update_firmware_by_node_type_async(
        &self,
        cmd: rms::UpdateFirmwareByNodeTypeRequest,
    ) -> Result<rms::UpdateFirmwareByNodeTypeAsyncResponse, RackManagerError> {
        self.update_firmware_by_node_type_async_calls
            .lock()
            .await
            .push(cmd);
        pop_or_err(
            &mut self
                .update_firmware_by_node_type_async_responses
                .lock()
                .await,
        )
    }
    async fn update_firmware_by_device_list(
        &self,
        cmd: rms::UpdateFirmwareByDeviceListRequest,
    ) -> Result<rms::UpdateFirmwareByDeviceListResponse, RackManagerError> {
        self.update_firmware_by_device_list_calls
            .lock()
            .await
            .push(cmd);
        pop_or_err(&mut self.update_firmware_by_device_list_responses.lock().await)
    }
    async fn get_firmware_job_status(
        &self,
        cmd: rms::GetFirmwareJobStatusRequest,
    ) -> Result<rms::GetFirmwareJobStatusResponse, RackManagerError> {
        self.get_firmware_job_status_calls.lock().await.push(cmd);
        pop_or_err(&mut self.get_firmware_job_status_responses.lock().await)
    }
    async fn list_firmware_on_switch(
        &self,
        cmd: rms::ListFirmwareOnSwitchCommand,
    ) -> Result<rms::ListFirmwareOnSwitchResponse, RackManagerError> {
        self.list_firmware_on_switch_calls.lock().await.push(cmd);
        pop_or_err(&mut self.list_firmware_on_switch_responses.lock().await)
    }
    async fn push_firmware_to_switch(
        &self,
        cmd: rms::PushFirmwareToSwitchCommand,
    ) -> Result<rms::PushFirmwareToSwitchResponse, RackManagerError> {
        self.push_firmware_to_switch_calls.lock().await.push(cmd);
        pop_or_err(&mut self.push_firmware_to_switch_responses.lock().await)
    }
    async fn upgrade_firmware_on_switch(
        &self,
        cmd: rms::UpgradeFirmwareOnSwitchCommand,
    ) -> Result<rms::UpgradeFirmwareOnSwitchResponse, RackManagerError> {
        self.upgrade_firmware_on_switch_calls.lock().await.push(cmd);
        pop_or_err(&mut self.upgrade_firmware_on_switch_responses.lock().await)
    }
    async fn fetch_switch_system_image(
        &self,
        cmd: rms::FetchSwitchSystemImageRequest,
    ) -> Result<rms::FetchSwitchSystemImageResponse, RackManagerError> {
        self.fetch_switch_system_image_calls.lock().await.push(cmd);
        pop_or_err(&mut self.fetch_switch_system_image_responses.lock().await)
    }
    async fn install_switch_system_image(
        &self,
        cmd: rms::InstallSwitchSystemImageRequest,
    ) -> Result<rms::InstallSwitchSystemImageResponse, RackManagerError> {
        self.install_switch_system_image_calls
            .lock()
            .await
            .push(cmd);
        pop_or_err(&mut self.install_switch_system_image_responses.lock().await)
    }
    async fn list_switch_system_images(
        &self,
        cmd: rms::ListSwitchSystemImagesRequest,
    ) -> Result<rms::ListSwitchSystemImagesResponse, RackManagerError> {
        self.list_switch_system_images_calls.lock().await.push(cmd);
        pop_or_err(&mut self.list_switch_system_images_responses.lock().await)
    }
    async fn poll_job_status(
        &self,
        cmd: rms::PollJobStatusCommand,
    ) -> Result<rms::PollJobStatusResponse, RackManagerError> {
        self.poll_job_status_calls.lock().await.push(cmd);
        pop_or_err(&mut self.poll_job_status_responses.lock().await)
    }
    async fn configure_scale_up_fabric_manager(
        &self,
        cmd: rms::ConfigureScaleUpFabricManagerRequest,
    ) -> Result<rms::ConfigureScaleUpFabricManagerResponse, RackManagerError> {
        self.configure_scale_up_fabric_manager_calls
            .lock()
            .await
            .push(cmd);
        pop_or_err(
            &mut self
                .configure_scale_up_fabric_manager_responses
                .lock()
                .await,
        )
    }
    async fn enable_scale_up_fabric_telemetry_interface(
        &self,
        cmd: rms::EnableScaleUpFabricTelemetryInterfaceRequest,
    ) -> Result<rms::EnableScaleUpFabricTelemetryInterfaceResponse, RackManagerError> {
        self.enable_scale_up_fabric_telemetry_interface_calls
            .lock()
            .await
            .push(cmd);
        pop_or_err(
            &mut self
                .enable_scale_up_fabric_telemetry_interface_responses
                .lock()
                .await,
        )
    }
    async fn version(&self) -> Result<(), RackManagerError> {
        *self.version_call_count.lock().await += 1;
        self.version_responses
            .lock()
            .await
            .pop_front()
            .unwrap_or(Ok(()))
    }
}
