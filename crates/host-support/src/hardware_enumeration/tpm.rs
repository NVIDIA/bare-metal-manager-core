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
