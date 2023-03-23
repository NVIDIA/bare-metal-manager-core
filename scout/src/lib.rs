/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

#[derive(thiserror::Error, Debug)]
pub enum CarbideClientError {
    #[error("Generic error: {0}")]
    GenericError(String),

    #[error("Generic Tonic transport error {0}")]
    TonicTransportError(#[from] tonic::transport::Error),

    #[error("Generic Tonic status error {0}")]
    TonicStatusError(#[from] tonic::Status),

    #[error("Regex error {0}")]
    RegexError(#[from] regex::Error),

    #[error("Pwhash error {0}")]
    PwHash(#[from] pwhash::error::Error),

    #[error("StdIo error {0}")]
    StdIo(#[from] std::io::Error),

    #[error("Hardware enumeration error: {0}")]
    HardwareEnumerationError(
        #[from] forge_host_support::hardware_enumeration::HardwareEnumerationError,
    ),

    #[error("Hardware enumeration error: {0}")]
    RegistrationError(#[from] forge_host_support::registration::RegistrationError),

    #[error("Invalid gRPC enum value: {0}")]
    DiscriminantError(#[from] rpc::DiscriminantError),

    #[error("Subprocess {0} with arguments {1:?} failed with output: {2}")]
    SubprocessError(String, Vec<String>, String),
}

impl CarbideClientError {
    /// Constructs a `CarbideClientError::SubprocessError` from the result
    /// of a subprocess invocation
    pub fn subprocess_error(
        command: &std::process::Command,
        output: &std::process::Output,
    ) -> Self {
        return Self::SubprocessError(
            command.get_program().to_string_lossy().to_string(),
            command
                .get_args()
                .map(|arg| arg.to_string_lossy().to_string())
                .collect::<Vec<String>>(),
            String::from_utf8_lossy(&output.stderr).to_string(),
        );
    }
}

pub type CarbideClientResult<T> = Result<T, CarbideClientError>;
