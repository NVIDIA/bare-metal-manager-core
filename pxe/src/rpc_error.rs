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
use std::fmt::{Debug, Display};

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};

pub enum PxeRequestError {
    CarbideApiError(tonic::Status),
    MissingClientConfig,
    MissingMachineId,
    InvalidBuildArch,
    MalformedMachineId(String),
    MalformedBuildArch(String),
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
                Self::CarbideApiError(err) =>
                    format!("Error making a carbide API request: {}", err),
                Self::MissingClientConfig =>
                    "Missing client configuration from server config (should not reach this case)"
                        .to_string(),
                Self::MissingMachineId =>
                    "Missing Machine Identifier (UUID) specified in URI parameter uuid".to_string(),
                Self::InvalidBuildArch =>
                    "Invalid build arch specified in URI parameter buildarch".to_string(),
                Self::MalformedMachineId(err) => format!("Malformed Machine UUID: {}", err),
                Self::MalformedBuildArch(err) => format!("Malformed build arch: {}", err),
            }
        )
    }
}
