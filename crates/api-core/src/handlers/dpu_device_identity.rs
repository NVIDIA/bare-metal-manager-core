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
//! uses) and verified against the configured NVIDIA device roots in api-core,
//! co-located with the host TPM EK path. Governed by the
//! `[dpu_device_attestation]` mode:
//!
//! - `disabled`: always keep the legacy id.
//! - `best_effort`: use the device-rooted id when the cert is available and
//!   verifies, otherwise fall back to the legacy id.
//! - `required`: fail discovery for a new DPU when no verified device identity
//!   is available.
//!
//! Requires that site-explorer has pre-ingested the DPU's BMC (the cert fetch
//! correlates the DPU's DMI serial to its explored BMC endpoint).

use carbide_uuid::machine::MachineId;
use chrono::Utc;
use model::hardware_info::HardwareInfo;
use model::machine::machine_search_config::MachineSearchConfig;
use sha2::{Digest, Sha256};

use crate::CarbideError;
use crate::api::Api;
use crate::attestation::dpu_device::{
    self, DpuDeviceAttestationMode, DpuIdentity, VerifiedDpuDevice,
};

/// SPDM `ComponentIntegrity` id of the BlueField DPU Initial Root of Trust — the
/// Arm/NIC device-identity target. (`Bluefield_ERoT` is the BMC's own root of
/// trust and is intentionally not used here.) Matched case-insensitively because
/// the vendor's casing is inconsistent (brand "BlueField" vs Redfish id
/// "Bluefield").
const BLUEFIELD_DPU_IROT: &str = "Bluefield_DPU_IRoT";

/// Resolves the `machine_id` to use for a DPU under the configured
/// [`DpuDeviceAttestationMode`]. `legacy_id` is the serial-derived id. Returns
/// the (possibly device-rooted) id, or an error in `Required` mode when no
/// verified device identity is available.
pub(crate) async fn resolve_dpu_device_identity(
    api: &Api,
    hardware_info: &HardwareInfo,
    legacy_id: MachineId,
) -> Result<MachineId, CarbideError> {
    let mode = api.runtime_config.dpu_device_attestation.mode;
    if mode == DpuDeviceAttestationMode::Disabled {
        return Ok(legacy_id);
    }

    // Best-effort fetch + verify of the IRoT device certificate (returns the
    // verified identity and the leaf cert sha256 for the binding record).
    let verified = fetch_and_verify_irot(api, hardware_info).await;

    // An already-enrolled DPU keeps its legacy id (no re-keying on upgrade).
    let legacy_known = db::machine::find_one(
        &mut api.db_reader(),
        &legacy_id,
        MachineSearchConfig {
            include_dpus: true,
            ..MachineSearchConfig::default()
        },
    )
    .await?
    .is_some();

    let identity = dpu_device::select_dpu_machine_id(
        mode,
        legacy_id,
        verified.as_ref().map(|(v, _)| v),
        legacy_known,
    )
    .map_err(|e| CarbideError::FailedPrecondition(e.to_string()))?;

    // Record the verified binding only when a device-rooted id was actually
    // adopted. Best-effort: a failure here must not fail discovery.
    if let (DpuIdentity::NewDeviceRooted(machine_id), Some((v, sha))) = (&identity, &verified)
        && let Err(e) = record_binding(api, *machine_id, sha, &v.device_serial).await
    {
        tracing::warn!("failed to record DPU device-identity binding: {e}");
    }

    Ok(identity.machine_id())
}

/// Fetches the BlueField IRoT certificate chain from the DPU BMC and verifies it
/// against the configured device roots. Returns `None` (logging the reason) on
/// any soft failure — no serial, no explored BMC, no IRoT component, a Redfish
/// error, or a verification failure — so callers can apply the mode policy.
async fn fetch_and_verify_irot(
    api: &Api,
    hardware_info: &HardwareInfo,
) -> Option<(VerifiedDpuDevice, Vec<u8>)> {
    let serial = hardware_info
        .dmi_data
        .as_ref()
        .map(|d| d.product_serial.clone())
        .filter(|s| !s.is_empty())?;

    let endpoints = db::explored_endpoints::find_by_dpu_serial_numbers(
        &mut api.db_reader(),
        vec![serial.clone()],
    )
    .await
    .map_err(|e| tracing::warn!("DPU {serial}: explored_endpoints lookup failed: {e}"))
    .ok()?;

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
        .find(|m| m.id.eq_ignore_ascii_case(BLUEFIELD_DPU_IROT))
        .and_then(|m| m.spdm)
        .map(|s| {
            s.identity_authentication
                .responder_authentication
                .component_certificate
                .odata_id
        })
    else {
        tracing::info!("DPU {serial}: no {BLUEFIELD_DPU_IROT} ComponentIntegrity cert link");
        return None;
    };

    let ca_cert = client
        .get_component_ca_certificate(&cert_link)
        .await
        .map_err(|e| tracing::warn!("DPU {serial}: get_component_ca_certificate failed: {e}"))
        .ok()?;

    let chain_der = dpu_device::pem_chain_to_der(&ca_cert.certificate_string)
        .map_err(|e| tracing::warn!("DPU {serial}: IRoT cert chain PEM parse failed: {e}"))
        .ok()?;

    let roots = db::attestation::dpu_device_ca_certs::get_all(&mut api.db_reader())
        .await
        .map_err(|e| tracing::warn!("DPU {serial}: loading device roots failed: {e}"))
        .ok()?;
    let roots_der: Vec<Vec<u8>> = roots.into_iter().map(|r| r.ca_cert_der).collect();

    let verified = dpu_device::verify_device_cert_chain(&chain_der, &roots_der, Utc::now())
        .map_err(|e| tracing::warn!("DPU {serial}: IRoT cert verification failed: {e}"))
        .ok()?;

    let mut hasher = Sha256::new();
    hasher.update(&chain_der[0]);
    let sha = hasher.finalize().to_vec();

    tracing::info!(
        "DPU {serial}: verified IRoT device identity -> machine_id {}",
        verified.machine_id
    );
    Some((verified, sha))
}

/// Persists the verified device-identity → machine_id binding (audit record).
async fn record_binding(
    api: &Api,
    machine_id: MachineId,
    device_cert_sha256: &[u8],
    device_serial: &str,
) -> Result<(), CarbideError> {
    let mut txn = api.txn_begin().await?;
    db::attestation::dpu_device_cert_status::upsert(
        &mut txn,
        machine_id,
        device_cert_sha256,
        device_serial,
        None,
        &Utc::now(),
    )
    .await?;
    txn.commit().await?;
    Ok(())
}
