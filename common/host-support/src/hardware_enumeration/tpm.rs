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

//! TPM related operations

use std::process::Command;

/// Enumerates errors for TPM related operations
#[derive(Debug, thiserror::Error)]
pub enum TpmError {
    #[error("Unable to invoke subprocess {0}: {1}")]
    Subprocess(&'static str, std::io::Error),
    #[error("Subprocess exited with exit code {0:?}. Stderr: {1}")]
    SubprocessStatusNotOk(Option<i32>, String),
}

/// Returns the TPM's endorsement key certificate in binary format
pub fn get_ek_certificate() -> Result<Vec<u8>, TpmError> {
    // TODO: Do we need the `--raw` or `--offline` parameters?
    let output = Command::new("tpm2_getekcertificate")
        .output()
        .map_err(|e| TpmError::Subprocess("tpm2_getekcertificate", e))?;

    if !output.status.success() {
        let err = String::from_utf8(output.stderr).unwrap_or_else(|_| "Invalid UTF8".to_string());
        return Err(TpmError::SubprocessStatusNotOk(output.status.code(), err));
    }

    Ok(output.stdout)
}
