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

use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::process::Command;

use tss_esapi::handles::AuthHandle;
use tss_esapi::interface_types::session_handles::AuthSession;

use crate::{CarbideClientError, attestation as attest};

pub(crate) const TPM_RECOVERY_ATTEMPTED_PATH: &str = "/tmp/tpm_recovery_reboot_attempted";

// From https://superuser.com/questions/1404738/tpm-2-0-hardware-error-da-lockout-mode
pub(crate) fn set_tpm_max_auth_fail() -> Result<(), CarbideClientError> {
    let output = Command::new("tpm2_dictionarylockout")
        .arg("--setup-parameters")
        .arg("--max-tries=256")
        .arg("--clear-lockout")
        .output()
        .map_err(|e| {
            CarbideClientError::TpmError(format!("tpm2_dictionarylockout call failed: {e}"))
        })?;
    tracing::info!(
        "Tried setting TPM_PT_MAX_AUTH_FAIL to 256. Return code is: {0}",
        output
            .status
            .code()
            .map(|v| v.to_string())
            .unwrap_or_else(|| "NO RETURN CODE PRESENT".to_string())
    );

    if !output.stderr.is_empty() {
        tracing::error!(
            "TPM_PT_MAX_AUTH_FAIL stderr is {0}",
            String::from_utf8(output.stderr).unwrap_or_else(|_| "Invalid UTF8".to_string())
        );
    }
    if !output.stdout.is_empty() {
        tracing::info!(
            "TPM_PT_MAX_AUTH_FAIL stdout is {0}",
            String::from_utf8(output.stdout).unwrap_or_else(|_| "Invalid UTF8".to_string())
        );
    }

    Ok(())
}

/// Clears the TPM storage hierarchies via TPM2_Clear (lockout authorization), after dictionary
/// lockout setup.
pub(crate) fn clear_tpm(tpm_path: &str) -> Result<(), CarbideClientError> {
    set_tpm_max_auth_fail()?;

    let mut ctx = attest::create_context_from_path(tpm_path).map_err(|e| {
        CarbideClientError::TpmError(format!("Could not create TPM context for clear: {e}"))
    })?;

    // TPM2_Clear must be authorized. In tss-esapi, `Context::clear` calls `required_session_1()`:
    // ESAPI session slot 1 cannot be None or the call fails with MissingAuthSession. That slot is
    // how authorization for the lockout handle is supplied—not an optional extra.
    //
    // We use `AuthSession::Password` (empty password) instead of `start_auth_session` + HMAC: for
    // the usual case where lockout hierarchy auth is empty, ESAPI’s password handle is enough.
    ctx.set_sessions((Some(AuthSession::Password), None, None));

    ctx.clear(AuthHandle::Lockout)
        .map_err(|e| CarbideClientError::TpmError(format!("TPM2_Clear (lockout) failed: {e}")))?;

    ctx.clear_sessions();
    tracing::info!("TPM lockout hierarchy clear completed");
    Ok(())
}

pub(crate) fn is_recoverable_tpm_client_error(error: &CarbideClientError) -> bool {
    match error {
        CarbideClientError::TpmError(message) => {
            message.contains("Could not create AttestKeyInfo")
                || message.contains("Could not create context")
                || message.contains("TPM2_Clear")
        }
        _ => false,
    }
}

/// Clears the TPM and reboots the host once per boot cycle to recover from missing TPM material.
pub(crate) fn recover_tpm_and_reboot(tpm_path: &str) -> Result<(), CarbideClientError> {
    if Path::new(TPM_RECOVERY_ATTEMPTED_PATH).exists() {
        return Err(CarbideClientError::TpmError(
            "TPM recovery was already attempted this boot cycle; refusing to loop".to_string(),
        ));
    }

    tracing::warn!("Attempting automated TPM clear and reboot to recover attestation state");
    clear_tpm(tpm_path)?;

    let mut marker =
        File::create(TPM_RECOVERY_ATTEMPTED_PATH).map_err(CarbideClientError::StdIo)?;
    marker
        .write_all(b"tpm recovery reboot requested\n")
        .map_err(CarbideClientError::StdIo)?;

    let output = Command::new("systemctl")
        .arg("reboot")
        .output()
        .map_err(CarbideClientError::StdIo)?;
    if !output.status.success() {
        return Err(CarbideClientError::GenericError(format!(
            "systemctl reboot failed with status {:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recoverable_tpm_errors_include_attest_key_info_failures() {
        let err = CarbideClientError::TpmError("Could not create AttestKeyInfo: test".to_string());
        assert!(is_recoverable_tpm_client_error(&err));
    }

    #[test]
    fn non_tpm_client_errors_are_not_recoverable() {
        let err = CarbideClientError::GenericError("transport failed".to_string());
        assert!(!is_recoverable_tpm_client_error(&err));
    }
}
