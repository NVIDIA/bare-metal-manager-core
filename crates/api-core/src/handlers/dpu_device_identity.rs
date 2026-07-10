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

//! Discovery-time DPU device-identity resolution (issue NVIDIA/infra-controller#355 epic).
//!
//! For a DPU, optionally replaces the legacy serial-derived `machine_id` with a
//! hardware-rooted one derived from the BlueField IRoT device-identity
//! certificate. The certificate is fetched **out-of-band** from the DPU BMC over
//! Redfish SPDM `ComponentIntegrity` (the same mechanism the SPDM controller
//! uses); verification, the `[dpu_device_attestation]` mode policy, and the
//! binding record are all delegated to
//! [`ApiDpuDeviceIdentityResolver`](crate::attestation::dpu_id_resolver::ApiDpuDeviceIdentityResolver)
//! — the same pipeline site-explorer uses — so the two paths cannot drift.
//!
//! Requires that site-explorer has pre-ingested the DPU's BMC (the cert fetch
//! correlates the DPU's DMI serial to its explored BMC endpoint).

use carbide_uuid::machine::MachineId;
use model::attestation::spdm::is_bluefield_dpu_irot;
use model::attestation::{DpuDeviceIdentityError, DpuDeviceIdentityResolver};
use model::hardware_info::HardwareInfo;

use crate::CarbideError;
use crate::api::Api;
use crate::attestation::dpu_id_resolver::ApiDpuDeviceIdentityResolver;

/// Resolves the `machine_id` to use for a DPU under the configured
/// [`DpuDeviceAttestationMode`]. `legacy_id` is the serial-derived id. Returns
/// the (possibly device-rooted) id, or an error in `Required` mode when no
/// verified device identity is available for a previously-unseen DPU.
pub(crate) async fn resolve_dpu_device_identity(
    api: &Api,
    hardware_info: &HardwareInfo,
    legacy_id: MachineId,
) -> Result<MachineId, CarbideError> {
    let mode = api.runtime_config.dpu_device_attestation.mode;
    let resolver = ApiDpuDeviceIdentityResolver::new(api.database_connection.clone(), mode);

    // An enrolled DPU (legacy or previously device-rooted) keeps its id in
    // every mode — including `disabled`, so a mode rollback never re-keys
    // adopted DPUs — and skips the BMC fetch entirely.
    if let Some(enrolled) = resolver
        .enrolled_machine_id(legacy_id)
        .await
        .map_err(carbide_error)?
    {
        return Ok(enrolled);
    }

    let irot_chain_pem = if resolver.wants_irot_chain() {
        fetch_irot_chain_pem(api, hardware_info).await
    } else {
        None
    };

    let resolved = resolver
        .resolve_dpu_machine_id(irot_chain_pem.as_deref(), Some(legacy_id))
        .await
        .map_err(carbide_error)?;

    // With a legacy id supplied, resolution always yields an id.
    Ok(resolved.unwrap_or(legacy_id))
}

fn carbide_error(e: DpuDeviceIdentityError) -> CarbideError {
    match e {
        DpuDeviceIdentityError::Required(msg) => CarbideError::FailedPrecondition(msg),
        DpuDeviceIdentityError::Internal(msg) => CarbideError::internal(msg),
    }
}

/// Fetches the BlueField IRoT certificate chain (PEM) from the DPU BMC.
/// Returns `None` (logging the reason) on any soft failure — no serial, no
/// explored BMC, no IRoT component, a Redfish error — so the resolver can
/// apply the mode policy.
async fn fetch_irot_chain_pem(api: &Api, hardware_info: &HardwareInfo) -> Option<String> {
    let serial = hardware_info
        .dmi_data
        .as_ref()
        .map(|d| d.product_serial.clone())
        .filter(|s| !s.is_empty())?;

    let mut endpoints = db::explored_endpoints::find_by_dpu_serial_numbers(
        &mut api.db_reader(),
        vec![serial.clone()],
    )
    .await
    .map_err(|e| tracing::warn!("DPU {serial}: explored_endpoints lookup failed: {e}"))
    .ok()?;

    if endpoints.len() > 1 {
        tracing::warn!(
            "DPU {serial}: {} explored BMC endpoints match this serial; using the lowest address",
            endpoints.len()
        );
        endpoints.sort_by_key(|e| e.address);
    }
    let Some(endpoint) = endpoints.into_iter().next() else {
        tracing::info!("DPU {serial}: no explored BMC endpoint; cannot fetch IRoT cert");
        return None;
    };

    let access =
        db::machine_interface::lookup_bmc_access_info(&mut api.db_reader(), endpoint.address, None)
            .await
            .map_err(|e| tracing::warn!("DPU {serial}: BMC access lookup failed: {e}"))
            .ok()?;

    let client = api
        .redfish_pool
        .client_by_info(&access)
        .await
        .map_err(|e| tracing::warn!("DPU {serial}: redfish client creation failed: {e}"))
        .ok()?;

    let integrities = client
        .get_component_integrities()
        .await
        .map_err(|e| tracing::warn!("DPU {serial}: get_component_integrities failed: {e}"))
        .ok()?;

    let Some(cert_link) = integrities
        .members
        .into_iter()
        .find(|m| is_bluefield_dpu_irot(&m.id))
        .and_then(|m| m.spdm)
        .map(|s| {
            s.identity_authentication
                .responder_authentication
                .component_certificate
                .odata_id
        })
    else {
        tracing::info!("DPU {serial}: no BlueField IRoT ComponentIntegrity cert link");
        return None;
    };

    let ca_cert = client
        .get_component_ca_certificate(&cert_link)
        .await
        .map_err(|e| tracing::warn!("DPU {serial}: get_component_ca_certificate failed: {e}"))
        .ok()?;

    Some(ca_cert.certificate_string)
}
