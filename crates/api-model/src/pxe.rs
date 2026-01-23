/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
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
