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
use std::collections::HashMap;

use axum::extract::{FromRequestParts, Path, Query};
use axum::http::request::Parts;
use carbide_uuid::machine::MachineInterfaceId;
use serde::{Deserialize, Serialize};

use crate::common::MachineInterface;
use crate::extractors::machine_architecture::MachineArchitecture;
use crate::rpc_error::PxeRequestError;

#[derive(Clone, Serialize, Deserialize, Debug)]
struct MaybeMachineInterface {
    #[serde(rename(deserialize = "buildarch"))]
    build_architecture: String,
    #[serde(default)]
    uuid: Option<MachineInterfaceId>,
    #[serde(default)]
    uuid_as_param: Option<String>,
    #[serde(default)]
    platform: Option<String>,
    #[serde(default)]
    manufacturer: Option<String>,
    #[serde(default)]
    product: Option<String>,
    #[serde(default)]
    serial: Option<String>,
    #[serde(default)]
    asset: Option<String>,
}

impl TryFrom<MaybeMachineInterface> for MachineInterface {
    type Error = PxeRequestError;

    fn try_from(value: MaybeMachineInterface) -> Result<Self, Self::Error> {
        let build_architecture = MachineArchitecture::try_from(value.build_architecture.as_str())?;

        let uuid = match (value.uuid, value.uuid_as_param) {
            (Some(uuid), _) => Ok(uuid),
            (None, Some(uuid)) => {
                uuid.parse()
                    .map_err(|e: carbide_uuid::typed_uuids::UuidError| {
                        PxeRequestError::UuidConversion(e.into())
                    })
            }
            _ => Err(PxeRequestError::MissingMachineId),
        }?;

        Ok(MachineInterface {
            architecture: Some(build_architecture),
            interface_id: uuid,
            platform: value.platform,
            manufacturer: value.manufacturer,
            product: value.product,
            serial: value.serial,
            asset: value.asset,
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
