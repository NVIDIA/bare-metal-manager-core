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

use std::num::ParseIntError;

use utils::cmd::CmdError;

#[derive(thiserror::Error, Debug)]
pub enum CarbideClientError {
    #[error("Generic error: {0}")]
    GenericError(String),

    #[error("Generic transport error {0}")]
    TransportError(String),

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
        #[from] carbide_host_support::hardware_enumeration::HardwareEnumerationError,
    ),

    #[error("Registration error: {0}")]
    RegistrationError(#[from] carbide_host_support::registration::RegistrationError),

    #[error("Error decoding gRPC enum value: {0}")]
    RpcDecodeError(String), // This should be '#[from] prost::DecodeError)' but don't work

    #[error("Subprocess failed: {0}")]
    SubprocessError(#[from] CmdError),

    #[error("NVME parsing failed: {0}")]
    NvmeParsingError(#[from] ParseIntError),

    #[error("TPM Error: {0}")]
    TpmError(String),

    #[error("MlxFwManagerError: {0}")]
    MlxFwManagerError(String),
}

pub type CarbideClientResult<T> = Result<T, CarbideClientError>;
