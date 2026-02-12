/*
 * SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;

pub use ::rpc::forge as rpc;
use carbide_uuid::nvlink::NvLinkDomainId;
use db::WithTransaction;
use futures_util::FutureExt;
use model::hardware_info::{GpuPlatformInfo, HardwareInfo, MachineNvLinkInfo, NvLinkGpu};
use model::machine::machine_id::{from_hardware_info, host_id_from_dpu_hardware_info};
use model::machine::machine_search_config::MachineSearchConfig;
use model::machine::{DpuInitState, DpuInitStates, ManagedHostState};
use tonic::{Request, Response, Status};

use crate::api::{Api, log_machine_id, log_request_data};
use crate::cfg::file::NvLinkConfig;
use crate::handlers::utils::convert_and_log_machine_id;
use crate::{CarbideError, CarbideResult, attestation as attest};

pub(crate) async fn discover_machine(
    api: &Api,
    request: Request<rpc::MachineDiscoveryInfo>,
) -> Result<Response<rpc::MachineDiscoveryResult>, Status> {
    // We don't log_request_data(&request); here because the hardware info is huge
    let remote_ip: Option<IpAddr> = match request.metadata().get("X-Forwarded-For") {
        None => {
            // Normal production case.
            // This is set in api/src/listener.rs::listen_and_serve when we `accept` the connection
            // The IP is usually an IPv4-mapped IPv6 addresses (e.g. `::ffff:10.217.133.10`) so
            // we use to_canonical() to convert it to IPv4.
            request
                .extensions()
                .get::<Arc<crate::listener::ConnectionAttributes>>()
                .map(|conn_attrs| conn_attrs.peer_address().ip().to_canonical())
        }
        Some(ip_str) => {
            // Development case, we override the remote IP with HTTP header
            ip_str
                .to_str()
                .ok()
                .and_then(|s| s.parse().map(|ip: IpAddr| ip.to_canonical()).ok())
        }
    };

    let machine_discovery_info = request.into_inner();
    let interface_id = machine_discovery_info.machine_interface_id;

    let discovery_data = machine_discovery_info
        .discovery_data
        .map(|data| match data {
            rpc::machine_discovery_info::DiscoveryData::Info(info) => info,
        })
        .ok_or_else(|| Status::invalid_argument("Discovery data is not populated"))?;
    let attest_key_info_opt = discovery_data.attest_key_info.clone();
    let hardware_info = HardwareInfo::try_from(discovery_data).map_err(CarbideError::from)?;

    // this is an early check for certificate creation that happens later on in this method.
    // let's save us the hassle and return immediately if the below condition is not satisfied
    if api.runtime_config.attestation_enabled
        && !hardware_info.is_dpu()
        && attest_key_info_opt.is_none()
    {
        return Err(Status::invalid_argument("AttestKeyInfo is not populated"));
    }

    // Generate a stable Machine ID based on the hardware information
    let stable_machine_id = from_hardware_info(&hardware_info).map_err(|e| {
            CarbideError::InvalidArgument(
                format!("Insufficient HardwareInfo to derive a Stable Machine ID for Machine on InterfaceId {interface_id:?}: {e}"),
            )
        })?;
    log_machine_id(&stable_machine_id);

    // Before opening a database transaction, get information from nvlink if we need it.
    // Discover NMX-M info if this is a GBX00 machine
    let nvlink_info = if hardware_info.is_gbx00()
        && let Some(platform_info) = hardware_info
            .gpus
            .first()
            .and_then(|gpu| gpu.platform_info.as_ref())
        && let Some(nvlink_config) = api.runtime_config.nvlink_config.as_ref()
        && nvlink_config.enabled
    {
        get_nvlink_info_from_nmx_m(api, nvlink_config, platform_info)
            .await
            .map_err(|e| {
                tracing::warn!("Failed to get NVLink info from NMX-M: {e}");
                e
            })
            .ok()
    } else {
        None
    };

    let mut txn = api.txn_begin().await?;
    tracing::debug!(
        ?remote_ip,
        ?interface_id,
        "discover_machine loading interface"
    );

    if !hardware_info.is_dpu()
        && hardware_info.tpm_ek_certificate.is_none()
        && api.runtime_config.tpm_required
    {
        return Err(CarbideError::InvalidArgument(format!(
                "Ignoring DiscoverMachine request for non-tpm enabled host with InterfaceId {interface_id:?}"
            ))
            .into());
    } else if !hardware_info.is_dpu() && hardware_info.tpm_ek_certificate.is_some() {
        // this means we do have an EK cert for a host

        // get the EK cert from incoming message
        let tpm_ek_cert =
            hardware_info
                .tpm_ek_certificate
                .as_ref()
                .ok_or(CarbideError::InvalidArgument(
                    "tpm_ek_cert is empty".to_string(),
                ))?;

        attest::match_insert_new_ek_cert_status_against_ca(
            &mut txn,
            tpm_ek_cert,
            &stable_machine_id,
        )
        .await?;
    }

    let interface =
        db::machine_interface::find_by_ip_or_id(&mut txn, remote_ip, interface_id).await?;
    let machine_id = if hardware_info.is_dpu() {
        // if site explorer is creating machine records and there isn't one for this machine return an error
        if api
            .runtime_config
            .site_explorer
            .create_machines
            .load(Ordering::Relaxed)
        {
            db::machine::find_one(
                &mut txn,
                &stable_machine_id,
                MachineSearchConfig {
                    include_dpus: true,
                    ..MachineSearchConfig::default()
                },
            )
            .await?
            .ok_or_else(|| {
                Status::invalid_argument(format!(
                    "Machine id {stable_machine_id} was not discovered by site-explorer."
                ))
            })?;
        }

        let db_machine = if machine_discovery_info.create_machine {
            let machine = db::machine::get_or_create(
                &mut txn,
                Some(&api.common_pools),
                &stable_machine_id,
                &interface,
            )
            .await?;

            // Update the record only when create_machine is enabled.
            // Site-explorer will update if machine is created by site-explorer.
            db::machine_interface::associate_interface_with_dpu_machine(
                &interface.id,
                &stable_machine_id,
                &mut txn,
            )
            .await?;
            machine
        } else {
            db::machine::find_one(
                &mut txn,
                &stable_machine_id,
                MachineSearchConfig {
                    include_dpus: true,
                    ..MachineSearchConfig::default()
                },
            )
            .await?
            .ok_or_else(|| {
                Status::invalid_argument(format!("Machine id {stable_machine_id} not found."))
            })?
        };

        let (network_config, _version) = db_machine.network_config.clone().take();
        if network_config.loopback_ip.is_none() {
            let loopback_ip = db::machine::allocate_loopback_ip(
                &api.common_pools,
                &mut txn,
                &stable_machine_id.to_string(),
            )
            .await?;

            let (mut network_config, version) = db_machine.network_config.clone().take();
            network_config.loopback_ip = Some(loopback_ip);
            network_config.use_admin_network = Some(true);
            db::machine::try_update_network_config(
                &mut txn,
                &stable_machine_id,
                version,
                &network_config,
            )
            .await?;
        }

        if api
            .runtime_config
            .vmaas_config
            .as_ref()
            .map(|vc| vc.secondary_overlay_support)
            .unwrap_or_default()
            && network_config.secondary_overlay_vtep_ip.is_none()
        {
            let secondary_vtep_ip = db::machine::allocate_secondary_vtep_ip(
                &api.common_pools,
                &mut txn,
                &stable_machine_id.to_string(),
            )
            .await?;

            let (mut network_config, version) = db_machine.network_config.clone().take();
            network_config.secondary_overlay_vtep_ip = Some(secondary_vtep_ip);
            network_config.use_admin_network = Some(true);
            db::machine::try_update_network_config(
                &mut txn,
                &stable_machine_id,
                version,
                &network_config,
            )
            .await?;
        }

        db_machine.id
    } else {
        // Now we know stable machine id for host. Let's update it in db.
        db::machine::try_sync_stable_id_with_current_machine_id_for_host(
            &mut txn,
            &interface.machine_id,
            &stable_machine_id,
        )
        .await?
    };

    db::machine_topology::create_or_update_with_bom_validation(
        &mut txn,
        &stable_machine_id,
        &hardware_info,
        api.runtime_config.bom_validation.enabled,
    )
    .await?;

    if hardware_info.is_dpu() {
        // Create Host proactively.
        // In case host interface is created, this method will return existing one, instead
        // creating new everytime.
        let machine_interface =
            db::machine_interface::create_host_machine_dpu_interface_proactively(
                &mut txn,
                Some(&hardware_info),
                &machine_id,
            )
            .await?;

        // Create host machine with temporary ID if no machine is attached.
        if machine_interface.machine_id.is_none() {
            let predicted_machine_id =
                host_id_from_dpu_hardware_info(&hardware_info).map_err(|e| {
                    CarbideError::InvalidArgument(format!("hardware info missing: {e}"))
                })?;
            let mi_id = machine_interface.id;
            let proactive_machine = db::machine::get_or_create(
                &mut txn,
                Some(&api.common_pools),
                &predicted_machine_id,
                &machine_interface,
            )
            .await?;

            // Update host and DPUs state correctly.
            db::machine::update_state(
                &mut txn,
                &predicted_machine_id,
                &ManagedHostState::DPUInit {
                    dpu_states: DpuInitStates {
                        states: HashMap::from([(machine_id, DpuInitState::Init)]),
                    },
                },
            )
            .await?;

            tracing::info!(
                ?mi_id,
                machine_id = %proactive_machine.id,
                "Created host machine proactively",
            );
        }
    }

    // if attestation is enabled and it is not a DPU, then we create a random nonce (auth token)
    // and create a decrypting challenge (make credential) out of it.
    // Whoever was able to decrypt it (activate credential), possesses
    // the TPM that the endorsement key (EK) and the attestation key (AK) that they came from.
    // if attestation is not enabled, or it is a DPU, then issue machine certificates immediately
    #[cfg(feature = "linux-build")]
    let mut attest_key_bind_challenge_opt: Option<rpc::AttestKeyBindChallenge> = None;
    let mut make_machine_certificate = false;
    #[cfg(not(feature = "linux-build"))]
    let attest_key_bind_challenge_opt: Option<rpc::AttestKeyBindChallenge> = None;

    if api.runtime_config.attestation_enabled && !hardware_info.is_dpu() {
        #[cfg(feature = "linux-build")]
        if let Some(attest_key_info) = attest_key_info_opt {
            tracing::info!(
                "It is not a DPU and attestation is enabled. Generating Attest Key Bind Challenge ..."
            );

            attest_key_bind_challenge_opt = Some(
                crate::handlers::measured_boot::create_attest_key_bind_challenge(
                    &mut txn,
                    &attest_key_info,
                    &stable_machine_id,
                )
                .await?,
            );
        } else {
            return Err(Status::invalid_argument(
                "Internal Error: This should have been handled above! AttestKeyInfo is not populated.",
            ));
        }

        #[cfg(not(feature = "linux-build"))]
        {
            tracing::warn!(
                %stable_machine_id,
                "Attestation enabled but linux-build feature disabled; vending certificate without attestation challenge"
            );
            make_machine_certificate = true;
        }
    } else {
        tracing::info!(
            "Attestation enabled is {}. Is_DPU is {}. Vending certs to machine with id {}",
            api.runtime_config.attestation_enabled,
            hardware_info.is_dpu(),
            stable_machine_id,
        );

        // Don't make the certificate here, wait until we commit the transaction
        #[cfg(feature = "linux-build")]
        {
            make_machine_certificate = true;
        }
    }

    if let Some(nvlink_info) = nvlink_info {
        db::machine::update_nvlink_info(&mut txn, &machine_id, nvlink_info).await?;
    }

    txn.commit().await?;

    let machine_certificate = if make_machine_certificate {
        if std::env::var("UNSUPPORTED_CERTIFICATE_PROVIDER").is_ok() {
            Some(forge_secrets::certificates::Certificate::default())
        } else {
            Some(
                api.certificate_provider
                    .get_certificate(&stable_machine_id.to_string(), None, None)
                    .await
                    .map_err(|err| CarbideError::ClientCertificateError(err.to_string()))?,
            )
        }
    } else {
        None
    };

    let response = Ok(Response::new(rpc::MachineDiscoveryResult {
        machine_id: Some(stable_machine_id),
        machine_certificate: machine_certificate.map(Into::into),
        attest_key_challenge: attest_key_bind_challenge_opt,
        machine_interface_id: Some(interface.id),
    }));

    if hardware_info.is_dpu()
        && let Some(dpu_info) = hardware_info.dpu_info.as_ref()
    {
        // WARNING: DONOT REUSE OLD TXN HERE. IT WILL CREATE DEADLOCK.
        //
        // Create a new transaction here for network devices. Inner transaction is not so
        // helpful in postgres and using same transaction creates deadlock with
        // machine_interface table.

        // Create DPU and LLDP Association.
        api.with_txn(|txn| {
            db::network_devices::dpu_to_network_device_map::create_dpu_network_device_association(
                txn,
                &dpu_info.switches,
                &stable_machine_id,
            )
            .boxed()
        })
        .await??;
    }

    response
}

// Host has completed discovery
pub(crate) async fn discovery_completed(
    api: &Api,
    request: Request<rpc::MachineDiscoveryCompletedRequest>,
) -> Result<Response<rpc::MachineDiscoveryCompletedResponse>, Status> {
    log_request_data(&request);

    let req = request.into_inner();
    let machine_id = convert_and_log_machine_id(req.machine_id.as_ref())?;

    let (machine, mut txn) = api
        .load_machine(&machine_id, MachineSearchConfig::default())
        .await?;
    db::machine::update_discovery_time(&machine.id, &mut txn).await?;

    let discovery_result = "Success".to_owned();

    txn.commit().await?;

    tracing::info!(
        %machine_id,
        discovery_result, "discovery_completed",
    );
    Ok(Response::new(rpc::MachineDiscoveryCompletedResponse {}))
}

// Match up the platform info from scout with the GPU data from NMX-M to get the domain UUID and NMX-M GPU IDs.
async fn get_nvlink_info_from_nmx_m(
    api: &Api,
    nvlink_config: &NvLinkConfig,
    platform_info: &GpuPlatformInfo,
) -> CarbideResult<MachineNvLinkInfo> {
    let nmx_m_client = api
        .nmxm_pool
        .create_client(&nvlink_config.nmx_m_endpoint, None)
        .await
        .map_err(|e| CarbideError::internal(format!("Failed to create NMX-M client: {e}")))?;

    let nmx_m_gpu_list = nmx_m_client
        .get_gpu(None)
        .await
        .map_err(|e| CarbideError::internal(format!("Failed to get compute nodes: {e}")))?;

    // Get the list of GPUs which match the location info returned from scout.
    let matching_gpus = nmx_m_gpu_list
        .iter()
        .filter(|gpu| {
            // If NMX-M GPU location info tray index matches the tray index returned from scout.
            gpu.location_info
                .as_ref()
                .map(|info| {
                    info.tray_index.unwrap_or_default() as u32 == platform_info.tray_index
                        && info.slot_id.unwrap_or_default() as u32 == platform_info.slot_number
                        && info.chassis_serial_number.as_deref().unwrap_or_default()
                            == platform_info.chassis_serial
                })
                .unwrap_or(false)
        })
        .collect::<Vec<_>>();

    let domain_uuid = matching_gpus
        .first()
        .and_then(|gpu| gpu.domain_uuid)
        .ok_or_else(|| {
            CarbideError::internal(format!(
                "Failed to find domain UUID for GPUs: {matching_gpus:?}"
            ))
        })?;

    Ok(MachineNvLinkInfo {
        domain_uuid: NvLinkDomainId::from(domain_uuid),
        gpus: matching_gpus
            .into_iter()
            .cloned()
            .map(NvLinkGpu::from)
            .collect(),
    })
}
