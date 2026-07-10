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

use std::path::Path;

use crate::ca_cert_file::load_ca_cert_der;
use crate::errors::CarbideCliResult;
use crate::rpc::ApiClient;

pub async fn add_filename(filename: &str, api_client: &ApiClient) -> CarbideCliResult<()> {
    let filepath = Path::new(filename);
    println!(
        "Adding DPU device CA Certificate {0}",
        filepath.to_string_lossy()
    );

    let ca_cert_der = load_ca_cert_der(filepath)?;

    let ca_cert_id_response = api_client.0.dpu_add_device_ca_cert(ca_cert_der).await?;

    println!(
        "Successfully added DPU device CA Certificate {0} with id {1}",
        filepath.to_string_lossy(),
        ca_cert_id_response
            .id
            .map(|v| v.ca_cert_id.to_string())
            .unwrap_or("*CA ID has not been returned*".to_string()),
    );

    Ok(())
}
