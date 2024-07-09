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

use std::net::IpAddr;
use std::str::FromStr;

use ::rpc::forge as rpc;
use tonic::{Request, Response, Status};

use crate::api::{log_machine_id, log_request_data, Api};
use crate::db::dpu_agent_upgrade_policy::DpuAgentUpgradePolicy;
use crate::db::instance::{Instance, InstanceId};
use crate::db::machine::{Machine, MachineSearchConfig};
use crate::db::vpc::Vpc;
use crate::db::DatabaseError;
use crate::model::hardware_info::MachineInventory;
use crate::model::instance::status::network::{
    InstanceInterfaceStatusObservation, InstanceNetworkStatusObservation,
};
use crate::model::machine::machine_id::{try_parse_machine_id, MachineId};
use crate::model::machine::network::MachineNetworkStatusObservation;
use crate::model::machine::upgrade_policy::{AgentUpgradePolicy, BuildVersion};
use crate::model::RpcDataConversionError;
use crate::state_controller::snapshot_loader::{
    DbSnapshotLoader, MachineStateSnapshotLoader, SnapshotLoaderError,
};
use crate::{ethernet_virtualization, CarbideError};

/// vxlan5555 is special HBN single vxlan device. It handles networking between machines on the
/// same subnet. It handles the encapsulation into VXLAN and VNI for cross-host comms.
const HBN_SINGLE_VLAN_DEVICE: &str = "vxlan5555";

pub(crate) async fn get_managed_host_network_config(
    api: &Api,
    request: Request<rpc::ManagedHostNetworkConfigRequest>,
) -> Result<tonic::Response<rpc::ManagedHostNetworkConfigResponse>, tonic::Status> {
    log_request_data(&request);

    let request = request.into_inner();
    let dpu_machine_id = match &request.dpu_machine_id {
        Some(id) => try_parse_machine_id(id).map_err(CarbideError::from)?,
        None => {
            return Err(CarbideError::MissingArgument("dpu_machine_id").into());
        }
    };
    log_machine_id(&dpu_machine_id);

    let loader = DbSnapshotLoader {};
    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin get_managed_host_network_config",
            e,
        ))
    })?;

    let snapshot = match loader
        .load_machine_snapshot(&mut txn, &dpu_machine_id)
        .await
    {
        Ok(snap) => snap,
        Err(SnapshotLoaderError::HostNotFound(_)) => {
            return Err(CarbideError::NotFoundError {
                kind: "machine",
                id: dpu_machine_id.to_string(),
            }
            .into());
        }
        Err(err) => {
            return Err(CarbideError::from(err).into());
        }
    };

    let dpu_snapshot = match snapshot
        .dpu_snapshots
        .iter()
        .find(|s| s.machine_id == dpu_machine_id)
    {
        Some(dpu_snapshot) => dpu_snapshot,
        None => {
            return Err(Status::failed_precondition(format!(
                "DPU {} needs discovery.  DPU snapshot not found for managed host",
                dpu_machine_id
            )))
        }
    };

    let loopback_ip = match dpu_snapshot.loopback_ip() {
        Some(ip) => ip,
        None => {
            return Err(Status::failed_precondition(format!(
                "DPU {} needs discovery. Does not have a loopback IP yet.",
                dpu_machine_id
            )));
        }
    };
    let use_admin_network = dpu_snapshot.use_admin_network();

    let admin_interface_rpc =
        ethernet_virtualization::admin_network(&mut txn, &snapshot.host_snapshot.machine_id)
            .await?;

    let mut vpc_vni = None;

    let tenant_interfaces = match &snapshot.instance {
        None => vec![],
        Some(instance) => {
            let interfaces = &instance.config.network.interfaces;
            let vpc = Vpc::find_by_segment(&mut txn, interfaces[0].network_segment_id)
                .await
                .map_err(CarbideError::from)?;
            vpc_vni = vpc.vni;

            let mut tenant_interfaces = Vec::with_capacity(interfaces.len());

            //Get IP address of physical interface
            let physical_iface = interfaces.iter().find(|x| {
                rpc::InterfaceFunctionType::from(x.function_id.function_type())
                    == rpc::InterfaceFunctionType::Physical
            });

            let Some(physical_iface) = physical_iface else {
                return Err(CarbideError::GenericError(String::from(
                    "Physical interface not found",
                ))
                .into());
            };

            let physical_ip: IpAddr = match physical_iface.ip_addrs.iter().next() {
                Some((_, ip_addr)) => *ip_addr,
                None => {
                    return Err(CarbideError::GenericError(String::from(
                        "Physical IP address not found",
                    ))
                    .into())
                }
            };

            for iface in interfaces {
                tenant_interfaces.push(
                    ethernet_virtualization::tenant_network(
                        &mut txn,
                        instance.instance_id,
                        iface,
                        physical_ip,
                    )
                    .await?,
                );
            }
            tenant_interfaces
        }
    };

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit get_managed_host_network_config",
            e,
        ))
    })?;

    let network_config = rpc::ManagedHostNetworkConfig {
        loopback_ip: loopback_ip.to_string(),
    };

    let resp = rpc::ManagedHostNetworkConfigResponse {
        instance_id: snapshot
            .instance
            .as_ref()
            .map(|instance| instance.instance_id.into()),
        asn: api.eth_data.asn,
        dhcp_servers: api.eth_data.dhcp_servers.clone(),
        route_servers: api.eth_data.route_servers.clone(),
        // TODO: Automatically add the prefix(es?) from the IPv4 loopback
        // pool to deny_prefixes. The database stores the pool in an
        // exploded representation, so we either need to reconstruct the
        // original prefix from what's in the database, or find some way to
        // store it when it's added or resized.
        deny_prefixes: api
            .eth_data
            .deny_prefixes
            .iter()
            .map(|net| net.to_string())
            .collect(),
        vni_device: if use_admin_network {
            "".to_string()
        } else {
            HBN_SINGLE_VLAN_DEVICE.to_string()
        },
        managed_host_config: Some(network_config),
        // TODO: multidpu: Fix it for multiple dpus.
        managed_host_config_version: snapshot.dpu_snapshots[0]
            .network_config
            .version
            .version_string(),
        use_admin_network,
        admin_interface: Some(admin_interface_rpc),
        tenant_interfaces,
        instance_network_config_version: if use_admin_network {
            "".to_string()
        } else {
            snapshot
                .instance
                .unwrap()
                .network_config_version
                .version_string()
        },
        remote_id: dpu_machine_id.remote_id(),
        network_virtualization_type: Some(if api.runtime_config.nvue_enabled {
            // new
            rpc::VpcVirtualizationType::EthernetVirtualizerWithNvue as i32
        } else {
            // old
            rpc::VpcVirtualizationType::EthernetVirtualizer as i32
        }),
        vpc_vni: vpc_vni.map(|vni| vni as u32),
        enable_dhcp: api.runtime_config.dpu_dhcp_server_enabled,
        host_interface_id: snapshot.host_snapshot.interfaces.iter().find_map(|x| {
            if x.is_primary {
                Some(x.id.to_string())
            } else {
                None
            }
        }),
    };

    // If this all worked, we shouldn't emit a log line
    tracing::Span::current().record("logfmt.suppress", true);

    Ok(Response::new(resp))
}

pub(crate) async fn update_agent_reported_inventory(
    api: &Api,
    request: Request<rpc::DpuAgentInventoryReport>,
) -> Result<Response<()>, tonic::Status> {
    log_request_data(&request);

    let request = request.into_inner();
    let dpu_machine_id = match &request.machine_id {
        Some(id) => try_parse_machine_id(id).map_err(CarbideError::from)?,
        None => {
            return Err(CarbideError::MissingArgument("machine_id").into());
        }
    };

    log_machine_id(&dpu_machine_id);

    if let Some(inventory) = request.inventory.as_ref() {
        let mut txn = api.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin create_machine_inventory",
                e,
            ))
        })?;

        let inventory =
            MachineInventory::try_from(inventory.clone()).map_err(CarbideError::from)?;
        Machine::update_agent_reported_inventory(&mut txn, &dpu_machine_id, &inventory)
            .await
            .map_err(CarbideError::from)?;

        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(file!(), line!(), "commit inventory", e))
        })?;
    } else {
        return Err(Status::invalid_argument("inventory missing from request"));
    }

    tracing::info!(
        machine_id = %dpu_machine_id,
        software_inventory = ?request.inventory,
        "update machine inventory",
    );

    Ok(Response::new(()))
}

pub(crate) async fn record_dpu_network_status(
    api: &Api,
    request: Request<rpc::DpuNetworkStatus>,
) -> Result<Response<()>, tonic::Status> {
    log_request_data(&request);

    let request = request.into_inner();
    let dpu_machine_id = match &request.dpu_machine_id {
        Some(id) => try_parse_machine_id(id).map_err(CarbideError::from)?,
        None => {
            return Err(CarbideError::MissingArgument("dpu_machine_id").into());
        }
    };
    log_machine_id(&dpu_machine_id);

    let hs = request
        .health
        .as_ref()
        .ok_or_else(|| CarbideError::MissingArgument("health_status"))?;

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin record_dpu_network_status",
            e,
        ))
    })?;

    let observed_at = match request.observed_at.clone() {
        Some(ts) => {
            // Use DPU clock
            let system_time = std::time::SystemTime::try_from(ts).map_err(|err| {
                tracing::warn!(
                    machine_id = %dpu_machine_id,
                    "record_dpu_network_status invalid timestamp `observed_at`: {err}"
                );
                CarbideError::InvalidArgument("observed_at".to_string())
            })?;
            chrono::DateTime::from(system_time)
        }
        None => {
            // Use carbide-api clock
            chrono::Utc::now()
        }
    };

    let machine_obs =
        MachineNetworkStatusObservation::try_from(request.clone()).map_err(CarbideError::from)?;
    Machine::update_network_status_observation(&mut txn, &dpu_machine_id, &machine_obs)
        .await
        .map_err(CarbideError::from)?;
    tracing::trace!(
        machine_id = %dpu_machine_id,
        machine_network_config = ?request.network_config_version,
        instance_network_config = ?request.instance_network_config_version,
        agent_version = machine_obs.agent_version,
        "Applied network configs",
    );

    // Generate and store a health-report
    // In case forge-dpu-agent sends it in the new format - use directly that
    // Otherwise convert the legacy format
    let mut health_report = if let Some(health_report) = &request.dpu_health {
        health_report::HealthReport::try_from(health_report.clone()).map_err(|e| {
            CarbideError::GenericError(format!("Can not convert health report: {e}"))
        })?
    } else {
        // Convert NetworkHealth into Health report
        let mut report = health_report::HealthReport {
            source: "forge-dpu-agent".to_string(),
            observed_at: None,
            successes: Vec::new(),
            alerts: Vec::new(),
        };
        for passed in hs.passed.iter() {
            report.successes.push(health_report::HealthProbeSuccess {
                id: passed.to_string().parse().unwrap(),
            })
        }
        for failed in hs.failed.iter() {
            report.alerts.push(health_report::HealthProbeAlert {
                id: failed.parse().map_err(|e| {
                    CarbideError::GenericError(format!(
                        "Can not convert health probe alert id: {e}"
                    ))
                })?,
                in_alert_since: Some(chrono::Utc::now()),
                // We don't really know the message. The legacy format doesn't associate it with a probe ID
                message: failed.clone(),
                tenant_message: None,
                classifications: vec![
                    health_report::HealthAlertClassification::prevent_host_state_changes(),
                ],
            })
        }
        // Mimic the old behavior of forge-dpu-agent which sets is_healthy to false
        // but adds no failure in case configs change
        if !hs.is_healthy && hs.failed.is_empty() {
            report.alerts.push(health_report::HealthProbeAlert {
                id: "PostConfigCheckWait".parse().map_err(|e| {
                    CarbideError::GenericError(format!(
                        "Can not convert health probe alert id: {e}"
                    ))
                })?,
                in_alert_since: Some(chrono::Utc::now()),
                message: "PostConfigCheckWait".to_string(),
                tenant_message: None,
                classifications: vec![
                    health_report::HealthAlertClassification::prevent_host_state_changes(),
                ],
            });
        }

        report
    };
    // We ignore what dpu-agent sends as timestamp and time, and replace
    // it with more accurate information
    health_report.source = "forge-dpu-agent".to_string();
    health_report.observed_at = Some(chrono::Utc::now());
    // TODO: Fix the in_alert times
    Machine::update_dpu_agent_health_report(&mut txn, &dpu_machine_id, &health_report)
        .await
        .map_err(CarbideError::from)?;

    // We already persisted the machine parts of applied_config in
    // update_network_status_observation above. Now do the instance parts.
    if let Some(version_string) = request.instance_network_config_version {
        let Ok(version) = version_string.as_str().parse() else {
            return Err(CarbideError::InvalidArgument(
                "applied_config.instance_network_config_version".to_string(),
            )
            .into());
        };
        let mut interfaces: Vec<InstanceInterfaceStatusObservation> = vec![];
        for iface in request.interfaces {
            let v = iface.try_into().map_err(CarbideError::from)?;
            interfaces.push(v);
        }
        let instance_obs = InstanceNetworkStatusObservation {
            config_version: version,
            observed_at,
            interfaces,
        };

        let instance_id = InstanceId::from_grpc(request.instance_id)?;
        Instance::update_network_status_observation(&mut txn, instance_id, &instance_obs)
            .await
            .map_err(CarbideError::from)?;
    }

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit record_dpu_network_status",
            e,
        ))
    })?;

    // Check if we need to flag this forge-dpu-agent for upgrade or mark an upgrade completed
    // We do this here because we just learnt about which version of forge-dpu-agent is
    // running.
    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin record_dpu_network_status upgrade check",
            e,
        ))
    })?;
    if let Some(policy) = DpuAgentUpgradePolicy::get(&mut txn)
        .await
        .map_err(CarbideError::from)?
    {
        let _needs_upgrade = Machine::apply_agent_upgrade_policy(&mut txn, policy, &dpu_machine_id)
            .await
            .map_err(CarbideError::from)?;
    }
    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit record_dpu_network_status upgrade check",
            e,
        ))
    })?;

    // If this all worked and the DPU is healthy, we shouldn't emit a log line
    // If there is any error the report, the logging of the follow-up report is
    // suppressed for a certain amount of time to reduce logging noise.
    // The suppression is keyed by the type of errors that occur. If the set
    // of errors changed, the log will be emitted again.
    let suppress_log_key = match (&request.network_config_error, hs.is_healthy) {
        (Some(error), true) => error.to_string(),
        (Some(error), false) => {
            format!("{}_{:?}_{}", error, hs.failed, hs.message())
        }
        (None, true) => String::new(),
        (None, false) => {
            format!("{:?}_{}", hs.failed, hs.message())
        }
    };

    if suppress_log_key.is_empty()
        || !api
            .dpu_health_log_limiter
            .should_log(&dpu_machine_id, &suppress_log_key)
    {
        tracing::Span::current().record("logfmt.suppress", true);
    }

    Ok(Response::new(()))
}

/// Network status of each managed host, as reported by forge-dpu-agent.
/// For use by forge-admin-cli
///
/// Currently: Status of HBN on each DPU
pub(crate) async fn get_all_managed_host_network_status(
    api: &Api,
    request: Request<rpc::ManagedHostNetworkStatusRequest>,
) -> Result<Response<rpc::ManagedHostNetworkStatusResponse>, Status> {
    log_request_data(&request);

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin get_all_managed_host_network_status",
            e,
        ))
    })?;

    let all_status = Machine::get_all_network_status_observation(&mut txn, 2000)
        .await
        .map_err(CarbideError::from)?;

    let mut out = Vec::with_capacity(all_status.len());
    for machine_network_status in all_status {
        out.push(machine_network_status.into());
    }
    Ok(Response::new(rpc::ManagedHostNetworkStatusResponse {
        all: out,
    }))
}

/// Should this DPU upgrade it's forge-dpu-agent?
/// Once the upgrade is complete record_dpu_network_status will receive the updated
/// version and write the DB to say our upgrade is complete.
pub(crate) async fn dpu_agent_upgrade_check(
    api: &Api,
    request: tonic::Request<rpc::DpuAgentUpgradeCheckRequest>,
) -> Result<tonic::Response<rpc::DpuAgentUpgradeCheckResponse>, Status> {
    log_request_data(&request);

    let req = request.into_inner();
    let machine_id = MachineId::from_str(&req.machine_id).map_err(|_| {
        CarbideError::from(RpcDataConversionError::InvalidMachineId(
            req.machine_id.clone(),
        ))
    })?;
    log_machine_id(&machine_id);
    if !machine_id.machine_type().is_dpu() {
        return Err(Status::invalid_argument(
            "Upgrade check can only be performed on DPUs",
        ));
    }

    // We usually want these two to match
    let agent_version = req.current_agent_version;
    let server_version = forge_version::v!(build_version);
    BuildVersion::try_from(server_version)
        .map_err(|_| Status::internal("Invalid server version, cannot check for upgrade"))?;

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin dpu_agent_upgrade_check ",
            e,
        ))
    })?;
    let machine = Machine::find_one(&mut txn, &machine_id, MachineSearchConfig::default())
        .await
        .map_err(CarbideError::from)?;
    let machine = machine.ok_or(CarbideError::NotFoundError {
        kind: "dpu",
        id: machine_id.to_string(),
    })?;
    let should_upgrade = machine.needs_agent_upgrade();
    if should_upgrade {
        tracing::debug!(
            %machine_id,
            agent_version,
            server_version,
            "Needs forge-dpu-agent upgrade",
        );
    } else {
        tracing::trace!(%machine_id, agent_version, "forge-dpu-agent is up to date");
    }
    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "end dpu_agent_upgrade_check handler",
            e,
        ))
    })?;

    // The debian/ubuntu package version is our build_version minus the initial `v`
    let package_version = &server_version[1..];

    let response = rpc::DpuAgentUpgradeCheckResponse {
        should_upgrade,
        package_version: package_version.to_string(),
        server_version: server_version.to_string(),
    };
    Ok(tonic::Response::new(response))
}

/// Get or set the forge-dpu-agent upgrade policy.
pub(crate) async fn dpu_agent_upgrade_policy_action(
    api: &Api,
    request: tonic::Request<rpc::DpuAgentUpgradePolicyRequest>,
) -> Result<tonic::Response<rpc::DpuAgentUpgradePolicyResponse>, Status> {
    log_request_data(&request);
    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin apply_agent_upgrade_policy_all",
            e,
        ))
    })?;

    let req = request.into_inner();
    let mut did_change = false;
    if let Some(new_policy) = req.new_policy {
        let policy: AgentUpgradePolicy = new_policy.into();

        DpuAgentUpgradePolicy::set(&mut txn, policy)
            .await
            .map_err(CarbideError::from)?;
        did_change = true;
    }

    let Some(active_policy) = DpuAgentUpgradePolicy::get(&mut txn)
        .await
        .map_err(CarbideError::from)?
    else {
        return Err(tonic::Status::not_found("No agent upgrade policy"));
    };
    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit apply_agent_upgrade_policy_all",
            e,
        ))
    })?;
    let response = rpc::DpuAgentUpgradePolicyResponse {
        active_policy: active_policy.into(),
        did_change,
    };
    Ok(tonic::Response::new(response))
}
