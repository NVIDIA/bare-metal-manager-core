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

use carbide_redfish::libredfish::RedfishClientPool;
use libredfish::Redfish;

use crate::{CarbideError, CarbideResult};

/// set_host_uefi_password sets the UEFI password on the host and then power-cycles it.
/// It returns the job ID for the UEFI password change for vendors that require
/// generating a job to set the UEFI password.
pub async fn set_host_uefi_password(
    redfish_client: &dyn Redfish,
    redfish_client_pool: Arc<dyn RedfishClientPool>,
) -> CarbideResult<Option<String>> {
    redfish_client_pool
        .uefi_setup(redfish_client, false)
        .await
        .map_err(|e| {
            tracing::error!(%e, "Failed to run uefi_setup call");
            CarbideError::internal(format!("Failed redfish uefi_setup subtask: {e}"))
        })
}

pub async fn clear_host_uefi_password(
    redfish_client: &dyn Redfish,
    redfish_client_pool: Arc<dyn RedfishClientPool>,
) -> CarbideResult<Option<String>> {
    redfish_client_pool
        .clear_host_uefi_password(redfish_client)
        .await
        .map_err(|e| {
            tracing::error!(%e, "Failed to run clear_host_uefi_password call");
            CarbideError::internal(format!(
                "Failed redfish clear_host_uefi_password subtask: {e}"
            ))
        })
}
