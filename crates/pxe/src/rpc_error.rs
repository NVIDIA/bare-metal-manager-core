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
use std::fmt::{Debug, Display};

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum_client_ip::Rejection;
use carbide_uuid::UuidConversionError;
use rpc::errors::RpcDataConversionError;

pub enum PxeRequestError {
    CarbideApiError(tonic::Status),
    MissingClientConfig,
    MissingMachineId,
    MissingIp(Rejection),
    InvalidBuildArch,
    MalformedMachineId(String),
    MalformedBuildArch(String),
    RpcConversion(RpcDataConversionError),
    UuidConversion(UuidConversionError),
}

impl IntoResponse for PxeRequestError {
    fn into_response(self) -> Response {
        let response_string = self.to_string();
        let mut response = response_string.into_response();
        *response.status_mut() = StatusCode::BAD_REQUEST;
        response
    }
}

impl Debug for PxeRequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self, f)
    }
}

impl Display for PxeRequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::CarbideApiError(err) => format!("Error making a carbide API request: {err}"),
                Self::MissingClientConfig =>
                    "Missing client configuration from server config (should not reach this case)"
                        .to_string(),
                Self::MissingMachineId =>
                    "Missing Machine Identifier (UUID) specified in URI parameter uuid".to_string(),
                Self::InvalidBuildArch =>
                    "Invalid build arch specified in URI parameter buildarch".to_string(),
                Self::MalformedMachineId(err) => format!("Malformed Machine UUID: {err}"),
                Self::MalformedBuildArch(err) => format!("Malformed build arch: {err}"),
                Self::MissingIp(err) => format!("Source IP is missing. Error: {err:?}"),
                Self::RpcConversion(err) => format!("Error converting RPC data: {err:?}"),
                Self::UuidConversion(err) => format!("Error converting RPC UUID data: {err:?}"),
            }
        )
    }
}
