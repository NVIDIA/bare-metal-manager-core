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

use std::process;

use carbide_host_support::hardware_enumeration::enumerate_hardware;
use carbide_host_support::registration;
use carbide_host_support::registration::RegistrationError;
use carbide_uuid::machine::MachineId;
use tracing::{error, info};
use tss_esapi::Context;
use tss_esapi::handles::KeyHandle;

use crate::{CarbideClientError, attestation as attest};

pub async fn run(
    forge_api: &str,
    root_ca: String,
    machine_interface_id: Option<uuid::Uuid>,
    retry: &registration::DiscoveryRetry,
    tpm_path: &str,
) -> Result<(MachineId, Option<uuid::Uuid>), CarbideClientError> {
    let mut hardware_info = enumerate_hardware()?;
    info!("Successfully enumerated hardware");

    let is_dpu = hardware_info.tpm_ek_certificate.is_none();

    if machine_interface_id.is_none() && !is_dpu {
        return Err(CarbideClientError::GenericError(
            "--machine-interface-id=<uuid> is required for this subcommand.".to_string(),
        ));
    };

    // if we are not on dpu, obtain attestation key (AK) and send it to carbide
    let mut endorsement_key_handle_opt: Option<KeyHandle> = None;
    let mut att_key_handle_opt: Option<KeyHandle> = None;
    let mut tss_ctx_opt: Option<Context> = None;

    if !is_dpu {
        // set the max auth fail to 256 as a stop gap measure to prevent machines from failing during
        // repeated reingestion cycle
        set_tpm_max_auth_fail()?;

        // create tss context
        let mut tss_ctx = attest::create_context_from_path(tpm_path)
            .map_err(|e| CarbideClientError::TpmError(format!("Could not create context: {e}")))?;

        // CHANGETO - supply context externally
        hardware_info.tpm_description = attest::get_tpm_description(&mut tss_ctx);

        let result = attest::create_attest_key_info(&mut tss_ctx).map_err(|e| {
            CarbideClientError::TpmError(format!("Could not create AttestKeyInfo: {e}"))
        })?;

        hardware_info.attest_key_info = Some(result.0);
        endorsement_key_handle_opt = Some(result.1);
        att_key_handle_opt = Some(result.2);
        tss_ctx_opt = Some(tss_ctx);
    }

    let (registration_data, attest_key_challenge_opt, interface_id) =
        registration::register_machine(
            forge_api,
            root_ca.clone(),
            machine_interface_id,
            hardware_info,
            false,
            retry.clone(),
            true,
            is_dpu,
        )
        .await?;
    let machine_id = registration_data.machine_id;
    info!("successfully discovered machine {machine_id} for interface {machine_interface_id:?}");

    // If we are not on a DPU and have some post-registration things to do,
    // we do them here.
    if !is_dpu {
        // If we have received back an attestation key challenge, this means
        // that Carbide has requested an attestation, so do it!
        //
        // This will perform:
        // -> activate_credential() - to obtain nonce
        // -> get_pcr_quote() - to obtain pcr values
        // -> get_eventlog() - to obtain eventlog
        // -> and, finally, create_quote_request() to create the actual quote
        if let Some(attest_key_challenge) = attest_key_challenge_opt {
            tracing::info!(
                "Sent AttestKeyInfo and received AttestKeyBindChallenge, starting measurements ..."
            );
            tracing::info!(
                "cred_blob - {} bytes long, secret - {} bytes long",
                attest_key_challenge.cred_blob.len(),
                attest_key_challenge.encrypted_secret.len()
            );

            let Some(ek_handle) = endorsement_key_handle_opt else {
                return Err(CarbideClientError::TpmError(
                    "InternalError: EK is None".to_string(),
                ));
            };

            let Some(ak_handle) = att_key_handle_opt else {
                return Err(CarbideClientError::TpmError(
                    "InternalError: AK is None".to_string(),
                ));
            };

            let Some(mut tss_ctx) = tss_ctx_opt else {
                return Err(CarbideClientError::TpmError(
                    "InternalError: TSS_CTX is None".to_string(),
                ));
            };

            // retrieve credential (kind of AuthToken) from the bind_response
            let cred = attest::activate_credential(
                &attest_key_challenge.cred_blob,
                &attest_key_challenge.encrypted_secret,
                &mut tss_ctx,
                &ek_handle,
                &ak_handle,
            )
            .map_err(|e| {
                CarbideClientError::TpmError(format!("Could not activate credential: {e}"))
            })?;

            // obtain signed attestation (a hash of pcr values) and actual pcr values
            let (attest, signature, pcr_values) = attest::get_pcr_quote(&mut tss_ctx, &ak_handle)
                .map_err(|e| {
                CarbideClientError::TpmError(format!("Could not get PCR Quote: {e}"))
            })?;

            tracing::info!("Obtained PCR quote");

            let tpm_eventlog = attest::get_tpm_eventlog();

            // create Quote Request message
            let quote_request = attest::create_quote_request(
                attest,
                signature,
                pcr_values,
                &cred,
                &machine_id,
                &tpm_eventlog,
            )
            .map_err(|e| {
                CarbideClientError::TpmError(format!("Could not create quote request: {e}"))
            })?;
            // send to server
            if !registration::attest_quote(
                forge_api,
                root_ca.clone(),
                false,
                retry.clone(),
                &quote_request,
            )
            .await?
            {
                return Err(RegistrationError::AttestationFailed.into());
            }
        }
    }

    Ok((machine_id, interface_id))
}

// this is taken from here - https://superuser.com/questions/1404738/tpm-2-0-hardware-error-da-lockout-mode
fn set_tpm_max_auth_fail() -> Result<(), CarbideClientError> {
    let output = process::Command::new("tpm2_dictionarylockout")
        .arg("--setup-parameters")
        .arg("--max-tries=256")
        .arg("--clear-lockout")
        .output()
        .map_err(|e| {
            CarbideClientError::TpmError(format!("tpm2_dictionarylockout call failed: {e}"))
        })?;
    info!(
        "Tried setting TPM_PT_MAX_AUTH_FAIL to 256. Return code is: {0}",
        output
            .status
            .code()
            .map(|v| v.to_string())
            .unwrap_or("NO RETURN CODE PRESENT".to_string())
    );

    if !output.stderr.is_empty() {
        error!(
            "TPM_PT_MAX_AUTH_FAIL stderr is {0}",
            String::from_utf8(output.stderr).unwrap_or_else(|_| "Invalid UTF8".to_string())
        );
    }
    if !output.stdout.is_empty() {
        info!(
            "TPM_PT_MAX_AUTH_FAIL stdout is {0}",
            String::from_utf8(output.stdout).unwrap_or_else(|_| "Invalid UTF8".to_string())
        );
    }

    Ok(())
}
