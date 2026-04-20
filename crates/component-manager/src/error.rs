// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#[derive(Debug, thiserror::Error)]
pub enum ComponentManagerError {
    #[error("backend unavailable: {0}")]
    Unavailable(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    #[error("internal error: {0}")]
    Internal(String),

    #[error("gRPC transport error: {0}")]
    Transport(#[from] tonic::transport::Error),

    #[error("gRPC status error: {0}")]
    Status(#[from] tonic::Status),

    #[error("RMS error: {0}")]
    Rms(String),
}

impl From<librms::RackManagerError> for ComponentManagerError {
    fn from(err: librms::RackManagerError) -> Self {
        match err {
            librms::RackManagerError::ApiInvocationError(status) => {
                ComponentManagerError::Status(status)
            }
            librms::RackManagerError::TlsError(e) => {
                ComponentManagerError::Unavailable(e.to_string())
            }
        }
    }
}
