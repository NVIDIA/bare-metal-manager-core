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

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use ::rpc::forge as rpc;
use carbide_utils::none_if_empty::NoneIfEmpty;
use carbide_uuid::machine::{MachineId, MachineIdSource, MachineInterfaceId};
use carbide_uuid::nvlink::NvLinkDomainId;
use db::WithTransaction;
use futures_util::FutureExt;
use model::hardware_info::{GpuPlatformInfo, HardwareInfo, MachineNvLinkInfo, NvLinkGpu};
use model::machine::machine_id::{from_hardware_info, host_id_from_dpu_hardware_info};
use model::machine::machine_search_config::MachineSearchConfig;
use model::machine::{DpuInitState, DpuInitStates, ManagedHostState};
use tonic::{Request, Response, Status};

use crate::api::{Api, log_machine_id, log_request_data};
use crate::handlers::client_resolution::{
    OverlayAddressOwnerLookup, find_overlay_address_owner, is_same_host_inband_interface,
};
use crate::handlers::utils::convert_and_log_machine_id;
use crate::{CarbideError, attestation as attest};

pub(crate) async fn discover_machine(
    api: &Api,
    request: Request<rpc::MachineDiscoveryInfo>,
) -> Result<Response<rpc::MachineDiscoveryResult>, Status> {
    // We don't log_request_data(&request); here because the hardware info is huge

    // This is set in api/src/listener.rs::listen_and_serve when we `accept` the connection
    // The IP is usually an IPv4-mapped IPv6 addresses (e.g. `::ffff:10.217.133.10`) so
    // we use to_canonical() to convert it to IPv4.
    let remote_ip = request
        .extensions()
        .get::<Arc<carbide_authn::middleware::ConnectionAttributes>>()
        .map(|conn_attrs| conn_attrs.peer_address.ip().to_canonical());

    let machine_discovery_info = request.into_inner();
    let discovery_reporter = machine_discovery_info.discovery_reporter();

    let discovery_data = machine_discovery_info
        .discovery_data
        .map(|data| match data {
            rpc::machine_discovery_info::DiscoveryData::Info(info) => info,
        })
        .ok_or_else(|| {
            CarbideError::InvalidArgument("discovery data is not populated".to_string())
        })?;
    let attest_key_info_opt = discovery_data.attest_key_info.clone();
    let hardware_info = HardwareInfo::try_from(discovery_data).map_err(CarbideError::from)?;

    // this is an early check for certificate creation that happens later on in this method.
    // let's save us the hassle and return immediately if the below condition is not satisfied
    if api.runtime_config.attestation_enabled
        && !hardware_info.is_dpu()
        && attest_key_info_opt.is_none()
    {
        return Err(
            CarbideError::InvalidArgument("AttestKeyInfo is not populated".to_string()).into(),
        );
    }

    // Generate a stable Machine ID based on the hardware information
    let stable_machine_id = from_hardware_info(&hardware_info).map_err(|e| {
            CarbideError::InvalidArgument(
                format!("insufficient HardwareInfo to derive a stable machine ID from DiscoverMachine call by {remote_ip:?}: {e}"),
            )
        })?;
    log_machine_id(&stable_machine_id);

    // Build NVLink info from scout GPU platform info. domain_uuid is backfilled by the
    // NVLink partition monitor from NMX-C hello.
    let gpu_platform_infos: Vec<&GpuPlatformInfo> = hardware_info
        .gpus
        .iter()
        .filter_map(|gpu| gpu.platform_info.as_ref())
        .collect();

    let nvlink_info = if hardware_info.is_mnnvl_capable()
        && !gpu_platform_infos.is_empty()
        && api
            .runtime_config
            .nvlink_config
            .as_ref()
            .is_some_and(|config| config.enabled)
    {
        nvlink_info_from_gpu_platform_infos(&gpu_platform_infos)
    } else {
        None
    };

    let secure_remote_ip = if api.runtime_config.allow_insecure_discovery {
        None
    } else {
        Some(remote_ip.ok_or_else(|| {
            CarbideError::InvalidArgument(
                "could not determine client IP address for discovery".to_string(),
            )
        })?)
    };

    // LOAD-BEARING (#4711): reject the hopeless retries BEFORE the admission
    // permit and the global admin-segment locks. See
    // `unlocked_discovery_rejection` for the measurements and the safety
    // rules; without it this handler is a fleet-wide serialization point that
    // wedges machine creation at scale.
    if let Some(rejection) = unlocked_discovery_rejection(
        api,
        machine_discovery_info.machine_interface_id,
        machine_discovery_info.create_machine,
        &hardware_info,
        &stable_machine_id,
        remote_ip,
    )
    .await
    {
        return Err(rejection.into());
    }

    // Keep readers that are waiting behind instance allocation out of open
    // database transactions. Hold the same permit through the main discovery
    // transaction so the admin-lock queue remains bounded too.
    let admin_admission = db::machine_interface::admin_lock_admission().await;

    // Resolve direct underlay ownership before taking the long-lived machine
    // and admin locks below. This authenticates the already-arrived request
    // against one ownership snapshot, then releases the address-table read
    // lock. The main transaction locks and verifies only the same interface;
    // it does not re-evaluate overlay ownership after authentication.
    let direct_interface_id = if let Some(remote_ip) = secure_remote_ip {
        let mut source_txn = api.txn_begin().await?;
        let direct_interface =
            db::machine_interface::find_by_ip(source_txn.as_pgconn(), remote_ip).await?;
        let direct_interface_id = if let Some(interface) = direct_interface {
            match find_overlay_address_owner(source_txn.as_pgconn(), remote_ip).await? {
                OverlayAddressOwnerLookup::NotFound => Some(interface.id),
                OverlayAddressOwnerLookup::One(owner)
                    if is_same_host_inband_interface(&interface, &owner) =>
                {
                    Some(interface.id)
                }
                OverlayAddressOwnerLookup::One(_) | OverlayAddressOwnerLookup::Ambiguous => {
                    tracing::warn!(
                        machine_interface_id = %interface.id,
                        %remote_ip,
                        "discovery source IP matches unrelated underlay and overlay owners"
                    );
                    return Err(discovery_source_owner_error().into());
                }
            }
        } else {
            None
        };
        source_txn.commit().await?;
        direct_interface_id
    } else {
        None
    };

    let mut txn = api.txn_begin().await?;

    // Advisory-lock the admin segments before any machine-interface row work
    // in this transaction, so the whole transaction holds locks in the
    // allocator order (segment advisory lock first, then interface rows).
    //
    // LOAD-BEARING (#4711), read before changing the branch below.
    //
    // The DPU branch takes the locks EXCLUSIVELY: it writes interface rows
    // (`associate_interface_with_dpu_machine`, the proactive host-interface
    // create, `set_primary_interface`) and ends in
    // `reconcile_admin_addresses_for_host`, which re-acquires the same locks
    // exclusively -- as a no-op only because this transaction already holds
    // them in that mode.
    //
    // The host branch takes them SHARED. Every segment-lock-reachable call in
    // this handler is gated behind `if hardware_info.is_dpu()`; the host path
    // only reads interfaces (`find_one`,
    // `find_{optional_for_update,for_update_if_matches_instance}_by_ip`) and
    // writes `machines`, `machine_topologies`, and attestation rows, none of
    // which touch a segment lock. Shared still conflicts with exclusive, so a
    // host discovery remains mutually excluded from DPU discovery, machine
    // creation, deletion, and reconcile; only host-versus-host becomes
    // concurrent. That is the whole win: shared acquisitions measured 0.41 ms
    // against 14-155 ms for exclusive on the hottest key.
    //
    // DANGER: PostgreSQL advisory locks do NOT upgrade. Adding any call that
    // reaches a segment lock -- interface create, address allocation,
    // `reconcile_admin_addresses_for_host` -- to the host path would make this
    // transaction take S and then ask for X on the same key, which deadlocks
    // against another transaction doing the same. Such a call must either move
    // behind `is_dpu()` or force this branch back to
    // `lock_all_admin_segments`.
    if hardware_info.is_dpu() {
        db::machine_interface::lock_all_admin_segments(&mut txn, "machine_discovery_dpu").await?;
    } else {
        db::machine_interface::lock_all_admin_segments_shared(&mut txn, "machine_discovery_host")
            .await?;
    }

    tracing::debug!(
        remote_ip_address = ?remote_ip,
        caller_machine_interface_id = ?machine_discovery_info.machine_interface_id,
        "discover_machine loading interface"
    );

    // Who's discovery info is this? DiscoverMachine is an anonymous call, and so normally we should
    // look it up ourselves from the client IP. But that isn't feasible in integration tests, so
    // config.allow_insecure_discovery lets the caller pass a machine_interface_id.
    let caller_interface = if let Some(remote_ip) = secure_remote_ip {
        if let Some(expected_interface_id) = direct_interface_id {
            match db::machine_interface::find_optional_for_update_by_ip(&mut txn, remote_ip).await?
            {
                Some(interface) if interface.id == expected_interface_id => interface,
                _ => {
                    tracing::warn!(
                        machine_interface_id = %expected_interface_id,
                        %remote_ip,
                        "discovery source interface changed during authentication"
                    );
                    return Err(discovery_source_owner_error().into());
                }
            }
        } else {
            // Caller may be an allocated instance running scout (e.g. for machine validation). We
            // need the machine_interface_id in the payload to know which interface to use. We will
            // check it against the caller's IP to make sure it belongs to instance on the same
            // machine.
            let machine_interface_id = machine_discovery_info.machine_interface_id.ok_or_else(|| {
                CarbideError::InvalidArgument(
                    "no machine_interface found for client IP address, and no machine_interface_id was provided".to_string(),
                )
            })?;
            db::machine_interface::find_for_update_if_matches_instance_ip(
                &mut txn,
                machine_interface_id,
                remote_ip,
            )
            .await?
            .ok_or_else(|| {
                tracing::error!(
                    %machine_interface_id,
                    %remote_ip,
                    "potential machine impersonation attempt: caller-provided machine_interface_id does not belong to this remote IP, or the IP has ambiguous overlay ownership"
                );
                discovery_source_owner_error()
            })?
        }
    } else {
        let interface_id = machine_discovery_info.machine_interface_id.ok_or_else(|| {
            CarbideError::InvalidArgument(
                "machine_interface_id is required for insecure discovery".to_string(),
            )
        })?;
        let interface = db::machine_interface::find_one(&mut txn, interface_id).await?;
        tracing::warn!(
            machine_interface_id = %interface_id,
            "Allowing insecure discovery: trusting caller-provided machine_interface_id. This is for integration tests only and must not be done in production."
        );
        interface
    };

    let site_explorer_creates_machines = api
        .runtime_config
        .site_explorer
        .create_machines
        .load(Ordering::Relaxed);

    // Now that we know who's submitting this DiscoveryInfo, make sure they're not submitting info
    // for another host in an attempt to get their machine certificate.
    let authorized = match caller_interface.machine_id.as_ref() {
        Some(caller_machine_id) if caller_machine_id == &stable_machine_id => {
            // The stable machine ID generated from the discovery info matches the caller's machine
            // ID, good.
            true
        }
        Some(caller_machine_id)
            if caller_machine_id.machine_type().is_predicted_host()
                && stable_machine_id.machine_type().is_host() =>
        {
            // This is a predicted host being promoted to a known host, which we allow.
            true
        }
        None if hardware_info.is_dpu() && machine_discovery_info.create_machine => {
            // There's no machine ID at all yet, and this is a dpu attempting to create a machine
            // entry from DiscoveryInfo. We only allow this if site explorer isn't configured to
            // create machines.
            !site_explorer_creates_machines
        }
        _ => false,
    };
    if !authorized {
        return Err(CarbideError::PermissionDeniedError(
            "machine discovery is not authorized for the selected interface".to_string(),
        )
        .into());
    }

    if !hardware_info.is_dpu()
        && hardware_info.tpm_ek_certificate.is_none()
        && api.runtime_config.tpm_required
    {
        return Err(CarbideError::InvalidArgument(format!(
            "ignoring DiscoverMachine request for non-tpm enabled host with InterfaceId {:?}",
            caller_interface.id,
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

    if !hardware_info.is_dpu()
        && hardware_info.tpm_ek_certificate.is_none()
        && stable_machine_id.source() == MachineIdSource::ProductBoardChassisSerial
        && let Some(existing_machine_id) = caller_interface.machine_id
        && existing_machine_id.source() == MachineIdSource::Tpm
        && existing_machine_id.machine_type().is_host()
    {
        return Err(CarbideError::FailedPrecondition(format!(
            "TPM EK certificate missing for host discovery on InterfaceId {:?}; refusing to derive serial-based machine id {} for existing TPM-derived machine id {}",
            caller_interface.id, stable_machine_id, existing_machine_id,
        ))
        .into());
    }

    let machine_id = if hardware_info.is_dpu() {
        // if site explorer is creating machine records and there isn't one for this machine return an error
        if site_explorer_creates_machines {
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
                CarbideError::InvalidArgument(format!(
                    "machine id {stable_machine_id} was not discovered by site-explorer"
                ))
            })?;
        }

        let db_machine = if machine_discovery_info.create_machine {
            let machine = db::machine::get_or_create(
                &mut txn,
                Some(&api.common_pools),
                &stable_machine_id,
                &caller_interface,
            )
            .await?;

            // Update the record only when create_machine is enabled.
            // Site-explorer will update if machine is created by site-explorer.
            db::machine_interface::associate_interface_with_dpu_machine(
                &caller_interface.id,
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
                CarbideError::InvalidArgument(format!("machine id {stable_machine_id} not found"))
            })?
        };

        // Collect every missing address into one `network_config` write. Each
        // write bumps the whole machine group, so writing one field at a time
        // leaves the later call with a stale `network_config_version`.
        let (mut network_config, network_config_version) = db_machine.network_config.clone().take();
        let owner_id = stable_machine_id.to_string();
        let mut network_config_changed = false;

        if network_config.loopback_ip.is_none() {
            let loopback_ip =
                db::machine::allocate_loopback_ip(&api.common_pools, &mut txn, &owner_id).await?;
            network_config.loopback_ip = Some(loopback_ip);
            network_config_changed = true;
        }

        if network_config.loopback_ip_v6.is_none()
            && let Some(loopback_ip_v6) =
                db::machine::allocate_loopback_ip_v6(&api.common_pools, &mut txn, &owner_id).await?
        {
            network_config.loopback_ip_v6 = Some(loopback_ip_v6);
            network_config_changed = true;
        }

        if network_config_changed
            && !db::machine::try_update_network_config(
                &mut txn,
                &stable_machine_id,
                network_config_version,
                &network_config,
            )
            .await?
        {
            // The version error also rolls back the allocations above.
            return Err(CarbideError::ConcurrentModificationError(
                "machine",
                network_config_version.to_string(),
            )
            .into());
        }

        db_machine.id
    } else {
        // Now we know stable machine id for host. Let's update it in db.
        db::machine::try_sync_stable_id_with_current_machine_id_for_host(
            &mut txn,
            &caller_interface.machine_id,
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
                api.runtime_config.retained_boot_interface_window,
            )
            .await?;

        let host_machine_id = if let Some(host_machine_id) = machine_interface.machine_id {
            host_machine_id
        } else {
            // Create host machine with temporary ID if no machine is attached.
            let predicted_machine_id =
                host_id_from_dpu_hardware_info(&hardware_info).map_err(|e| {
                    CarbideError::InvalidArgument(format!("hardware info missing: {e}"))
                })?;

            let host_has_primary = db::machine_interface::find_by_machine_ids(
                &mut txn,
                std::slice::from_ref(&predicted_machine_id),
            )
            .await?
            .get(&predicted_machine_id)
            .is_some_and(|interfaces| {
                interfaces
                    .iter()
                    .any(|interface| interface.primary_interface)
            });
            if host_has_primary && machine_interface.primary_interface {
                db::machine_interface::set_primary_interface(
                    &machine_interface.id,
                    false,
                    &mut txn,
                )
                .await?;
            }

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
                &proactive_machine.id,
                &ManagedHostState::DPUInit {
                    dpu_states: DpuInitStates {
                        states: HashMap::from([(machine_id, DpuInitState::Init)]),
                    },
                },
            )
            .await?;

            tracing::info!(
                machine_interface_id = ?mi_id,
                machine_id = %proactive_machine.id,
                "Created host machine proactively",
            );

            proactive_machine.id
        };

        // Normalize admin address ownership any time DPU discovery creates
        // or reattaches a DPU-backed host interface.
        let active_config_changed =
            db::machine_interface::reconcile_admin_addresses_for_host(&mut txn, &host_machine_id)
                .await?;
        if active_config_changed {
            let (network_config, network_config_version) =
                db::machine::get_network_config(&mut txn, &host_machine_id)
                    .await?
                    .take();
            db::machine::try_update_network_config(
                &mut txn,
                &host_machine_id,
                network_config_version,
                &network_config,
            )
            .await?;
        }
    }

    // if attestation is enabled and it is not a DPU, then we create a random nonce (auth token)
    // and create a decrypting challenge (make credential) out of it.
    // Whoever was able to decrypt it (activate credential), possesses
    // the TPM that the endorsement key (EK) and the attestation key (AK) that they came from.
    // if attestation is not enabled, or it is a DPU, then issue machine certificates immediately
    let attest_key_challenge = if api.runtime_config.attestation_enabled && !hardware_info.is_dpu()
    {
        let Some(attest_key_info) = attest_key_info_opt else {
            return Err(CarbideError::InvalidArgument(
                "internal error: this should have been handled above! AttestKeyInfo is not populated".into(),
            )
            .into());
        };

        tracing::info!(
            "It is not a DPU and attestation is enabled. Generating Attest Key Bind Challenge ..."
        );
        Some(
            crate::handlers::measured_boot::create_attest_key_bind_challenge(
                &mut txn,
                &attest_key_info,
                &stable_machine_id,
            )
            .await?,
        )
    } else {
        tracing::info!(
            attestation_enabled = api.runtime_config.attestation_enabled,
            is_dpu = hardware_info.is_dpu(),
            %stable_machine_id,
            "Vending attestation certificates",
        );

        None
    };

    if let Some(nvlink_info) = nvlink_info {
        db::machine::update_nvlink_info(&mut txn, &machine_id, nvlink_info).await?;
    }

    if discovery_reporter == rpc::MachineDiscoveryReporter::Scout
        && let Some(scout_version) = machine_discovery_info
            .discovery_reporter_version
            .as_deref()
            .none_if_empty()
    {
        db::machine::update_last_scout_observed_version(
            &stable_machine_id,
            scout_version,
            &mut txn,
        )
        .await?;
    }

    txn.commit().await?;
    drop(admin_admission);

    let machine_certificate = if attest_key_challenge.is_none() {
        if std::env::var("UNSUPPORTED_CERTIFICATE_PROVIDER").is_ok() {
            Some(rpc::MachineCertificate::default())
        } else {
            Some(
                api.certificate_provider
                    .get_certificate(&stable_machine_id.to_string(), None, None)
                    .await
                    .map_err(|err| CarbideError::ClientCertificateError(err.to_string()))?
                    .into(),
            )
        }
    } else {
        None
    };

    let response = Ok(Response::new(rpc::MachineDiscoveryResult {
        machine_id: Some(stable_machine_id),
        machine_certificate,
        attest_key_challenge,
        machine_interface_id: Some(caller_interface.id),
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

fn discovery_source_owner_error() -> CarbideError {
    CarbideError::PermissionDeniedError(
        "discovery source IP and selected interface do not identify one host".to_string(),
    )
}

/// Unlocked pre-check for `discover_machine`: returns the error the locked
/// path would return, for the one case that dominates admin-segment lock
/// traffic, WITHOUT taking the admission permit or the global locks.
///
/// # Why this exists (#4711, measured -- do not delete)
///
/// Instrumented 4,500-host ingestion run: the `machine_discovery` call site
/// was 705,875 of 718,000 admin-segment advisory lock acquisitions -- 99% of
/// all of them -- and roughly **15 of every 16 were failed retries**. A site
/// has only ~2 admin segments, so `lock_all_admin_segments` is effectively a
/// global lock, and every discovering machine in the fleet queued on it.
///
/// `machine-a-tron` (and scout / DPU agents in the field) re-issue
/// `DiscoverMachine` every 5 seconds with no backoff until their machine
/// exists. Each of those retries took every admin-segment lock at the top of
/// the handler and only then fell out with `PermissionDenied` a few dozen
/// lines later. That is a positive feedback loop: slower ingestion -> more
/// retries -> more global-lock traffic -> slower ingestion, until machine
/// creation wedges with every backend parked in `pg_advisory_xact_lock`.
///
/// This is the same shape of fix as the `#4711 fast path` in
/// `machine_interface::reconcile_admin_addresses_for_host`: decide with an
/// unlocked read, and only pay for the lock when the call can actually do
/// work.
///
/// # Rules any future edit must keep
///
/// 1. **Read-only, and never `FOR UPDATE`.** Taking `machine_interfaces` /
///    `machine_interface_addresses` row locks before the segment advisory
///    lock would invert the allocator order documented on
///    `machine_interface::lock_network_segments_exclusive` (segment advisory
///    lock first, then interface/address rows) and risk deadlock against
///    every flow that follows it. Hence
///    `find_optional_by_ip_unlocked` rather than
///    `find_optional_for_update_by_ip`, and a `MachineSearchConfig` with
///    `for_update` left at its `false` default.
/// 2. **Reject only on monotonic "nothing exists yet" facts.** Both facts
///    tested here -- the caller's interface has no machine association at
///    all, and the machine this hardware derives does not exist -- flip false
///    exactly once, when site-explorer creates and associates, and never flip
///    back under normal operation. So a rejection here is never durable: the
///    client's retry 5s later passes the pre-check and takes exactly today's
///    code path. Do NOT add a condition that can oscillate; that would turn a
///    transient rejection into a livelock.
/// 3. **Uncertainty falls through.** No interface for the source IP, an
///    ambiguous IP, an instance-scoped caller (the allocated-host-running-
///    scout case, which has no lock-free lookup), or any query error returns
///    `None` and lets the locked path produce the authoritative answer. This
///    is a filter, never a source of state the write path then trusts.
/// 4. **Same error as the locked path.** The rejection below is byte-for-byte
///    the `PermissionDeniedError` the authorization match returns for these
///    inputs, so clients and tests see no behavioural change.
///
/// Residual risk is one lost round trip: if the association lands between this
/// read and where the locked path would have read it, the caller is rejected
/// and retries 5s later. That is the same window the client already tolerates.
///
/// Takes the two request fields it needs by value rather than the whole
/// `MachineDiscoveryInfo`, because `discovery_data` has already been moved out
/// of it by the time this runs.
async fn unlocked_discovery_rejection(
    api: &Api,
    caller_machine_interface_id: Option<MachineInterfaceId>,
    create_machine: bool,
    hardware_info: &HardwareInfo,
    stable_machine_id: &MachineId,
    remote_ip: Option<IpAddr>,
) -> Option<CarbideError> {
    // Reads go straight to the pool: no transaction is opened, so a rejected
    // retry never occupies a pool connection while the fleet is contending.
    let pool = &api.database_connection;

    // Mirror the handler's caller-interface resolution, read-only. Only the
    // two lookups that have a lock-free equivalent are mirrored; anything else
    // falls through (rule 3).
    let caller_interface = if api.runtime_config.allow_insecure_discovery {
        let interface_id = caller_machine_interface_id?;
        db::machine_interface::find_one(pool, interface_id)
            .await
            .ok()?
    } else {
        db::machine_interface::find_optional_by_ip_unlocked(pool, remote_ip?)
            .await
            .ok()??
    };

    // Monotonic fact 1: the caller's interface is not associated with any
    // machine yet. This is the state every machine sits in while it waits for
    // site-explorer, and it is what makes the authorization match below
    // reduce to a constant. Once an association exists the match can succeed,
    // so we must not decide anything here.
    if caller_interface.machine_id.is_some() {
        return None;
    }

    // Monotonic fact 2: the machine this hardware derives does not exist.
    // Strictly narrower than fact 1 needs -- `machine_interfaces.machine_id`
    // has an `ON UPDATE CASCADE` FK to `machines(id)`, so an unassociated
    // interface already implies the caller owns nothing -- but it anchors the
    // pre-check on the "site-explorer has not created it yet" condition the
    // retry loop is actually waiting on, and it guarantees we stop rejecting
    // the moment the machine appears.
    let machine_exists = db::machine::find_one(
        pool,
        stable_machine_id,
        MachineSearchConfig {
            include_dpus: true,
            ..MachineSearchConfig::default()
        },
    )
    .await
    .ok()?
    .is_some();
    if machine_exists {
        return None;
    }

    // With `caller_interface.machine_id == None` the authorization match in
    // `discover_machine` collapses to exactly this arm:
    //     None if hardware_info.is_dpu() && create_machine
    //         => !site_explorer_creates_machines
    // (every other arm needs a `Some(machine_id)`). Evaluate it here and
    // reject only when it is false. Keep this expression in sync with that
    // match.
    let site_explorer_creates_machines = api
        .runtime_config
        .site_explorer
        .create_machines
        .load(Ordering::Relaxed);
    let authorized = hardware_info.is_dpu() && create_machine && !site_explorer_creates_machines;
    if authorized {
        // This call would go on to create the machine itself. Not our case.
        return None;
    }

    tracing::debug!(
        target: "carbide::lock_profile",
        phase = "machine_discovery",
        outcome = "rejected_unlocked",
        %stable_machine_id,
        machine_interface_id = %caller_interface.id,
        is_dpu = hardware_info.is_dpu(),
        "discovery rejected without taking admin segment locks"
    );

    Some(CarbideError::PermissionDeniedError(
        "machine discovery is not authorized for the selected interface".to_string(),
    ))
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

/// Builds NVLink discovery info from scout `GpuPlatformInfo` for every GPU that reported it.
fn nvlink_info_from_gpu_platform_infos(
    platform_infos: &[&GpuPlatformInfo],
) -> Option<MachineNvLinkInfo> {
    let chassis_serial = platform_infos
        .first()
        .map(|p| p.chassis_serial.clone())
        .unwrap_or_default();
    if chassis_serial.trim().is_empty() {
        return None;
    }

    let gpus = platform_infos
        .iter()
        .map(|platform_info| {
            let guid = {
                let s = platform_info.fabric_guid.trim();
                if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                    u64::from_str_radix(hex, 16).unwrap_or(0)
                } else {
                    s.parse::<u64>().unwrap_or(0)
                }
            };
            NvLinkGpu {
                tray_index: platform_info.tray_index as i32,
                slot_id: platform_info.slot_number as i32,
                device_id: platform_info.module_id as i32,
                guid,
            }
        })
        .collect();

    Some(MachineNvLinkInfo {
        domain_uuid: NvLinkDomainId::nil(),
        chassis_serial,
        gpus,
    })
}
