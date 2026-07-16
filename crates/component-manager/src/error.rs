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

    /// The selected backend does not implement or enable the requested operation.
    #[error("unsupported operation: {0}")]
    Unsupported(String),

    /// A mutating request may have reached the backend, but no job handle is
    /// available. Callers must reconcile observed credential state
    /// instead of retrying the mutation directly.
    ///
    /// For [`crate::nv_switch_manager::NvSwitchManager::start_password_rotation`],
    /// every other error guarantees that the backend did not accept the password
    /// mutation and the caller may release any staged submission marker.
    #[error("operation outcome unknown: {0}")]
    OperationOutcomeUnknown(String),

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
