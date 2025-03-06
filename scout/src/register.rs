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

use crate::attestation as attest;
use forge_host_support::{
    hardware_enumeration::enumerate_hardware, registration, registration::RegistrationError,
};
use std::process;
use tracing::{error, info};
use tss_esapi::Context;
use tss_esapi::handles::KeyHandle;

use crate::CarbideClientError;

pub async fn run(
    forge_api: &str,
    root_ca: String,
    machine_interface_id: uuid::Uuid,
    retry: &registration::DiscoveryRetry,
    tpm_path: &str,
) -> Result<String, CarbideClientError> {
    let mut hardware_info = enumerate_hardware()?;
    info!("Successfully enumerated hardware");

    let is_dpu = hardware_info.tpm_ek_certificate.is_none();

    // if we are not on dpu, obtain attestation key (AK) and send it to carbide
    let mut endorsement_key_handle_opt: Option<KeyHandle> = None;
    let mut att_key_handle_opt: Option<KeyHandle> = None;
    let mut tss_ctx_opt: Option<Context> = None;

    if !is_dpu {
        // set the max auth fail to 256 as a stop gap measure to prevent machines from failing during
        // repeated reingestion cycle
        set_tpm_max_auth_fail()?;

        // create tss context
        let mut tss_ctx = attest::create_context_from_path(tpm_path).map_err(|e| {
            CarbideClientError::TpmError(format!("Could not create context: {0}", e))
        })?;

        // CHANGETO - supply context externally
        hardware_info.tpm_description = attest::get_tpm_description(&mut tss_ctx);

        let result = attest::create_attest_key_info(&mut tss_ctx).map_err(|e| {
            CarbideClientError::TpmError(format!("Could not create AttestKeyInfo: {0}", e))
        })?;

        hardware_info.attest_key_info = Some(result.0);
        endorsement_key_handle_opt = Some(result.1);
        att_key_handle_opt = Some(result.2);
        tss_ctx_opt = Some(tss_ctx);
    }

    let (registration_data, attest_key_challenge_opt) = registration::register_machine(
        forge_api,
        root_ca.clone(),
        Some(machine_interface_id),
        hardware_info,
        false,
        retry.clone(),
        true,
        is_dpu,
    )
    .await?;
    let machine_id = registration_data.machine_id;
    info!("successfully discovered machine {machine_id} for interface {machine_interface_id}");

    // if we are not on dpu and we have received back attestation key challenge, this means
    // the carbide wants us to do an attestation ... so do it!
    if !is_dpu {
        // if attestation is requested, perform it
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
                CarbideClientError::TpmError(format!("Could not activate credential: {0}", e))
            })?;

            // obtain signed attestation (a hash of pcr values) and actual pcr values
            let (attest, signature, pcr_values) = attest::get_pcr_quote(&mut tss_ctx, &ak_handle)
                .map_err(|e| {
                CarbideClientError::TpmError(format!("Could not get PCR Quote: {0}", e))
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
                CarbideClientError::TpmError(format!("Could not create quote request: {0}", e))
            })?;
            // send to server
            if !registration::attest_quote(forge_api, root_ca, false, retry.clone(), &quote_request)
                .await?
            {
                return Err(RegistrationError::AttestationFailed.into());
            }
        }
    }

    Ok(machine_id)
}

// this is taken from here - https://superuser.com/questions/1404738/tpm-2-0-hardware-error-da-lockout-mode
fn set_tpm_max_auth_fail() -> Result<(), CarbideClientError> {
    let output = process::Command::new("tpm2_dictionarylockout")
        .arg("--setup-parameters")
        .arg("--max-tries=256")
        .arg("--clear-lockout")
        .output()
        .map_err(|e| {
            CarbideClientError::TpmError(format!("tpm2_dictionarylockout call failed: {0}", e))
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
