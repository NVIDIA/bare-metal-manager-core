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
    async fn apply_switch_system_image(
        &self,
        cmd: rms::ApplySwitchSystemImageRequest,
    ) -> Result<rms::ApplySwitchSystemImageResponse, tonic::Status>;

    async fn get_switch_system_image_job_status(
        &self,
        cmd: rms::GetSwitchSystemImageJobStatusRequest,
    ) -> Result<rms::GetSwitchSystemImageJobStatusResponse, tonic::Status>;
}

#[async_trait::async_trait]
impl SwitchSystemImageRmsClient for librms::RackManagerApi {
    async fn apply_switch_system_image(
        &self,
        cmd: rms::ApplySwitchSystemImageRequest,
    ) -> Result<rms::ApplySwitchSystemImageResponse, tonic::Status> {
        self.client.apply_switch_system_image(cmd).await
    }

    async fn get_switch_system_image_job_status(
        &self,
        cmd: rms::GetSwitchSystemImageJobStatusRequest,
    ) -> Result<rms::GetSwitchSystemImageJobStatusResponse, tonic::Status> {
        self.client.get_switch_system_image_job_status(cmd).await
    }
}

#[cfg(feature = "test-support")]
pub mod test_support {
    pub use crate::rms_sim::{MockRmsClient, RmsSim};
}
