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

use std::process::Command;

use tss_esapi::handles::AuthHandle;
use tss_esapi::interface_types::session_handles::AuthSession;

use crate::{CarbideClientError, attestation as attest};

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

/// Clears the TPM storage hierarchies via TPM2_Clear (platform authorization), after dictionary
/// lockout setup.
pub(crate) fn clear_tpm_platform_hierarchy(tpm_path: &str) -> Result<(), CarbideClientError> {
    set_tpm_max_auth_fail()?;

    let mut ctx = attest::create_context_from_path(tpm_path).map_err(|e| {
        CarbideClientError::TpmError(format!("Could not create TPM context for clear: {e}"))
    })?;

    // TPM2_Clear must be authorized. In tss-esapi, `Context::clear` calls `required_session_1()`:
    // ESAPI session slot 1 cannot be None or the call fails with MissingAuthSession. That slot is
    // how authorization for the platform handle is supplied—not an optional extra.
    //
    // We use `AuthSession::Password` (empty password) instead of `start_auth_session` + HMAC: for
    // the usual case where platform hierarchy auth is empty, ESAPI’s password handle is enough; a
    // full TPM auth session is unnecessary.
    ctx.set_sessions((Some(AuthSession::Password), None, None));

    ctx.clear(AuthHandle::Platform)
        .map_err(|e| CarbideClientError::TpmError(format!("TPM2_Clear (platform) failed: {e}")))?;

    ctx.clear_sessions();
    tracing::info!("TPM platform hierarchy clear completed");
    Ok(())
}
