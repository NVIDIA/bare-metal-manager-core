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
use crate::{
    common::MachineInterface, extractors::machine_architecture::MachineArchitecture,
    rpc_error::PxeRequestError,
};
use axum::{
    extract::{FromRequestParts, Path, Query},
    http::request::Parts,
};
use rpc::uuid::machine::MachineInterfaceId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Serialize, Deserialize, Debug)]
struct MaybeMachineInterface {
    #[serde(rename(deserialize = "buildarch"))]
    build_architecture: String,
    #[serde(default)]
    uuid: Option<MachineInterfaceId>,
    #[serde(default)]
    uuid_as_param: Option<String>,
}

impl TryFrom<MaybeMachineInterface> for MachineInterface {
    type Error = PxeRequestError;

    fn try_from(value: MaybeMachineInterface) -> Result<Self, Self::Error> {
        let build_architecture = MachineArchitecture::try_from(value.build_architecture.as_str())?;

        let uuid = match (value.uuid, value.uuid_as_param) {
            (Some(uuid), _) => Ok(uuid),
            (None, Some(uuid)) => uuid.parse().map_err(PxeRequestError::RpcConversion),
            _ => Err(PxeRequestError::MissingMachineId),
        }?;

        Ok(MachineInterface {
            architecture: Some(build_architecture),
            interface_id: uuid,
        })
    }
}

impl<S> FromRequestParts<S> for MachineInterface
where
    S: Send + Sync,
{
    type Rejection = PxeRequestError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        if let Ok(maybe) = Query::<MaybeMachineInterface>::from_request_parts(parts, state).await {
            let mut maybe_machine_interface = maybe.0;
            maybe_machine_interface.uuid_as_param =
                Path::<HashMap<String, String>>::from_request_parts(parts, state)
                    .await
                    .ok()
                    .and_then(|params| params.0.get("uuid").cloned());
            maybe_machine_interface.try_into()
        } else {
            // it can only fail to parse because of missing build arch, the other fields are optional.
            Err(PxeRequestError::InvalidBuildArch)
        }
    }
}
