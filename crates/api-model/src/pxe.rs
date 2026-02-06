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

use carbide_uuid::machine::MachineInterfaceId;
use rpc::forge::MachineArchitecture;

pub struct PxeInstructionRequest {
    pub interface_id: MachineInterfaceId,
    pub arch: MachineArchitecture,
    pub product: Option<String>,
}

impl TryFrom<rpc::forge::PxeInstructionRequest> for PxeInstructionRequest {
    type Error = rpc::errors::RpcDataConversionError;

    fn try_from(value: rpc::forge::PxeInstructionRequest) -> Result<Self, Self::Error> {
        let interface_id =
            value
                .interface_id
                .ok_or(rpc::errors::RpcDataConversionError::MissingArgument(
                    "Interface ID",
                ))?;

        let arch = rpc::forge::MachineArchitecture::try_from(value.arch).map_err(|_| {
            rpc::errors::RpcDataConversionError::InvalidArgument(
                "Unknown arch received.".to_string(),
            )
        })?;

        let product = value.product;

        Ok(PxeInstructionRequest {
            interface_id,
            arch,
            product,
        })
    }
}
