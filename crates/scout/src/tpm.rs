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

use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::Path;
use std::process::Command;

use tss_esapi::handles::AuthHandle;
use tss_esapi::interface_types::session_handles::AuthSession;

use crate::{CarbideClientError, attestation as attest};

pub(crate) const TPM_RECOVERY_ATTEMPTED_PATH: &str = "/run/scout/tpm_recovery_reboot_attempted";

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

/// Returns true when attestation-key setup failed after a TPM context was opened successfully.
///
/// Recovery is only attempted for this stage: context creation failures (bad path, missing device)
/// are not recoverable via TPM clear.
pub(crate) fn should_attempt_tpm_recovery_for_attest_key_failure(
    source: &dyn std::error::Error,
) -> bool {
    let message = source.to_string().to_ascii_lowercase();
    !message.contains("not supported")
}

fn claim_tpm_recovery_attempt() -> Result<(), CarbideClientError> {
    if let Some(parent) = Path::new(TPM_RECOVERY_ATTEMPTED_PATH).parent() {
        fs::create_dir_all(parent).map_err(CarbideClientError::StdIo)?;
    }

    let mut marker = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(TPM_RECOVERY_ATTEMPTED_PATH)
    {
        Ok(file) => file,
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {
            return Err(CarbideClientError::TpmError(
                "TPM recovery was already attempted this boot cycle; refusing to loop".to_string(),
            ));
        }
        Err(e) => return Err(CarbideClientError::StdIo(e)),
    };
    marker
        .write_all(b"tpm recovery reboot requested\n")
        .map_err(CarbideClientError::StdIo)
}

/// Clears the TPM and reboots the host once per boot cycle to recover from missing TPM material.
pub(crate) fn recover_tpm_and_reboot(tpm_path: &str) -> Result<(), CarbideClientError> {
    claim_tpm_recovery_attempt()?;

    tracing::warn!("Attempting automated TPM clear and reboot to recover attestation state");
    clear_tpm(tpm_path)?;

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
    fn attest_key_failure_recovery_classification_cases() {
        let cases: &[(&str, bool)] = &[
            ("handle already exists", true),
            ("tpm corruption detected", true),
            ("feature not supported on this device", false),
        ];

        for (message, want_recovery) in cases {
            let err: Box<dyn std::error::Error> = Box::new(std::io::Error::other(*message));
            assert_eq!(
                should_attempt_tpm_recovery_for_attest_key_failure(&*err),
                *want_recovery,
                "message={message:?}"
            );
        }
    }
}
