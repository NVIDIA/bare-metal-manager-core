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
use std::str::FromStr;

use crate::api::{Api, log_machine_id, log_request_data};
use crate::cfg::file::VpcIsolationBehaviorType;
use crate::db;
use crate::db::domain::Domain;
use crate::db::dpu_agent_upgrade_policy::DpuAgentUpgradePolicy;
use crate::db::machine::MachineSearchConfig;
use crate::db::managed_host::LoadSnapshotOptions;
use crate::db::network_security_group;
use crate::db::network_segment::{NetworkSegment, NetworkSegmentSearchConfig};
use crate::db::vpc::{Vpc, VpcDpuLoopback};
use crate::db::{DatabaseError, ObjectColumnFilter, network_segment};
use crate::handlers::utils::convert_and_log_machine_id;
use crate::machine_update_manager::machine_update_module::HOST_UPDATE_HEALTH_PROBE_ID;
use crate::model::hardware_info::MachineInventory;
use crate::model::machine::network::MachineNetworkStatusObservation;
use crate::model::machine::upgrade_policy::{AgentUpgradePolicy, BuildVersion};
use crate::model::machine::{InstanceState, ManagedHostState};
use crate::{CarbideError, ethernet_virtualization};
use ::rpc::errors::RpcDataConversionError;
use ::rpc::forge as rpc;
use forge_network::virtualization::VpcVirtualizationType;
use forge_uuid::{machine::MachineId, machine::MachineInterfaceId};
use itertools::Itertools;
use tonic::{Request, Response, Status};

/// vxlan48 is special HBN single vxlan device. It handles networking between machines on the
/// same subnet. It handles the encapsulation into VXLAN and VNI for cross-host comms.
const HBN_SINGLE_VLAN_DEVICE: &str = "vxlan48";

pub(crate) async fn get_managed_host_network_config_inner(
    api: &Api,
    dpu_machine_id: MachineId,
    snapshot: crate::model::machine::ManagedHostStateSnapshot,
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<rpc::ManagedHostNetworkConfigResponse, tonic::Status> {
    let dpu_snapshot = match snapshot
        .dpu_snapshots
        .iter()
        .find(|s| s.id == dpu_machine_id)
    {
        Some(dpu_snapshot) => dpu_snapshot,
        None => {
            return Err(Status::failed_precondition(format!(
                "DPU {} needs discovery.  DPU snapshot not found for managed host",
                dpu_machine_id
            )));
        }
    };

    let maybe_instance =
        Option::<rpc::Instance>::try_from(snapshot.clone()).map_err(CarbideError::from)?;

    let primary_dpu_snapshot = snapshot
        .host_snapshot
        .interfaces
        .iter()
        .find(|x| x.primary_interface)
        .ok_or_else(|| CarbideError::internal("Primary Interface is missing.".to_string()))?;

    let primary_dpu = db::machine_interface::find_one(txn, primary_dpu_snapshot.id).await?;
    let is_primary_dpu = primary_dpu
        .attached_dpu_machine_id
        .map(|x| x == dpu_snapshot.id)
        .unwrap_or(false);

    let loopback_ip = match dpu_snapshot.loopback_ip() {
        Some(ip) => ip,
        None => {
            return Err(Status::failed_precondition(format!(
                "DPU {} needs discovery. Does not have a loopback IP yet.",
                dpu_machine_id
            )));
        }
    };
    let use_admin_network = if is_primary_dpu {
        dpu_snapshot.use_admin_network()
    } else {
        true
    };

    let mut network_virtualization_type = if api.runtime_config.nvue_enabled {
        VpcVirtualizationType::EthernetVirtualizerWithNvue
    } else {
        VpcVirtualizationType::EthernetVirtualizer
    };

    let mut use_fnn_over_admin_nw = false;
    if use_admin_network {
        // If FNN config is enabled, we should use it in admin network.
        if let Some(fnn) = &api.runtime_config.fnn {
            if let Some(admin) = &fnn.admin_vpc {
                if admin.enabled {
                    use_fnn_over_admin_nw = true;
                    network_virtualization_type = VpcVirtualizationType::Fnn;
                }
            }
        }
    }

    let (admin_interface_rpc, host_interface_id) = ethernet_virtualization::admin_network(
        txn,
        &snapshot.host_snapshot.id,
        &dpu_snapshot.id,
        use_fnn_over_admin_nw,
        &api.common_pools,
    )
    .await?;

    let mut vpc_vni = None;

    let tenant_interfaces = match &snapshot.instance {
        None => vec![],
        // We don't support secondary DPU yet.
        // If admin network is to be used for this managedhost, why to send old tenant data, which
        // is just to be deleted.
        Some(_instance) if !is_primary_dpu || use_admin_network => {
            vec![]
        }
        Some(_instance)
            // If instance is waiting for network segment to come up in READY state, stay on admin
            // network.
            if matches!(
                snapshot.managed_state,
                ManagedHostState::Assigned {
                    instance_state: InstanceState::WaitingForNetworkSegmentToBeReady,
                }
            ) =>
        {
            // Should/Can we still query and return the NSG of the VPC so that
            // policies can be configured on the DPU while interfaces are still coming up?
            vec![]
        }
        Some(instance) => {
            let interfaces = &instance.config.network.interfaces;
            let Some(network_segment_id) = interfaces[0].network_segment_id else {
                // Network segment allocation is done before persisting record in db. So if still
                // network segment is empty, return error.
                return Err(CarbideError::NetworkSegmentNotAllocated.into());
            };
            let vpc = Vpc::find_by_segment(txn, network_segment_id)
                .await
                .map_err(CarbideError::from)?;

            // So the network_virtualization_type historically didn't come from the VPC table,
            // even though the value was being set there, and we're in the process of changing
            // that. If it's Fnn*, then set it accordingly. If it is EXPLICITLY ETV w/ NVUE,
            // then set it accordingly. If it's ETV, then check the runtime config to see if
            // nvue_enabled is true.
            network_virtualization_type = match vpc.network_virtualization_type {
                VpcVirtualizationType::Fnn => VpcVirtualizationType::Fnn,
                VpcVirtualizationType::EthernetVirtualizerWithNvue => {
                    VpcVirtualizationType::EthernetVirtualizerWithNvue
                }
                VpcVirtualizationType::EthernetVirtualizer => {
                    if api.runtime_config.nvue_enabled {
                        VpcVirtualizationType::EthernetVirtualizerWithNvue
                    } else {
                        VpcVirtualizationType::EthernetVirtualizer
                    }
                }
            };

            vpc_vni = vpc.vni.map(|x|x as u32);

            let network_security_group_details = match snapshot.instance {
                None => None,
                Some(ref i) => {
                    match i.config.network_security_group_id {
                        // If the instance doesn't have an NSG configured directly,
                        // we'll see if we the associated VPC does.
                        None => match vpc.network_security_group_id {
                            None => None,
                            Some(vpc_nsg_id) => {
                                // Make our DB query for the IDs to get our NetworkSecurityGroup
                                let network_security_group =
                                    network_security_group::find_by_ids(
                                        txn,
                                        &[vpc_nsg_id],
                                        Some(&i.config.tenant.tenant_organization_id),
                                        false,
                                    )
                                    .await?
                                    .pop()
                                    .ok_or(CarbideError::NotFoundError {
                                        kind: "NetworkSecurityGroup",
                                        id: i.config.tenant.tenant_organization_id.to_string(),
                                    })?;

                                Some((
                                    i32::from(rpc::NetworkSecurityGroupSource::NsgSourceVpc),
                                    network_security_group,
                                ))
                            }
                        },
                        Some(ref nsg_id) => {

                            // Make our DB query for the IDs to get our NetworkSecurityGroup
                            let network_security_group  =
                                network_security_group::find_by_ids(
                                    txn,
                                    &[nsg_id.to_owned()],
                                    Some(&i.config.tenant.tenant_organization_id),
                                    false,
                                )
                                .await?
                                .pop()
                                .ok_or(CarbideError::NotFoundError {
                                    kind: "NetworkSecurityGroup",
                                    id: i.config.tenant.tenant_organization_id.to_string(),
                                })?;

                            Some((
                                i32::from(
                                    rpc::NetworkSecurityGroupSource::NsgSourceInstance,
                                ),
                                network_security_group,
                            ))
                        }
                    }
                }
            };

            let mut tenant_interfaces = Vec::with_capacity(interfaces.len());

            //Get Physical interface
            let physical_iface = interfaces.iter().find(|x| {
                rpc::InterfaceFunctionType::from(x.function_id.function_type())
                    == rpc::InterfaceFunctionType::Physical
            });

            let Some(physical_iface) = physical_iface else {
                return Err(CarbideError::internal(String::from(
                    "Physical interface not found",
                ))
                .into());
            };

            //Get Physical IP
            let physical_ip: IpAddr = match physical_iface.ip_addrs.iter().next() {
                Some((_, ip_addr)) => *ip_addr,
                None => {
                    return Err(CarbideError::internal(String::from(
                        "Physical IP address not found",
                    ))
                    .into())
                }
            };

            // All interfaces have the segment id allocated. It is already validated during
            // instance creation.
            let segment_ids = interfaces.iter().filter_map(|x|x.network_segment_id).collect_vec();
            let segment_details = NetworkSegment::find_by(
                txn,
                ObjectColumnFilter::List(network_segment::IdColumn, &segment_ids),
                NetworkSegmentSearchConfig::default(),
            ).await
            .map_err(CarbideError::from)?;

            let segment_details = segment_details.iter().map(|x|(x.id, x)).collect::<HashMap<_,_>>();

            let Some(segment) = segment_details.get(&network_segment_id) else {
                return Err(Status::internal(format!(
                    "Tenant segment id {} is not found in db.",
                    network_segment_id
                )));
            };

            let domain = match segment.subdomain_id {
                Some(domain_id) => {
                    Domain::find_by_uuid(txn, domain_id)
                        .await
                        .map_err(CarbideError::from)?
                        .ok_or_else(|| CarbideError::NotFoundError {
                            kind: "domain",
                            id: domain_id.to_string(),
                        })?
                        .name
                }
                None => "unknowndomain".to_string(),
            };

            //Set FQDN
            let instance_hostname = &instance.config.tenant.hostname;
            let fqdn: String;
            if let Some(hostname) = instance_hostname.clone() {
                fqdn = format!("{}.{}", hostname.clone(), domain);
            } else {
                let dashed_ip: String = physical_ip
                    .to_string()
                    .split('.')
                    .collect::<Vec<&str>>()
                    .join("-");
                fqdn = format!("{}.{}", dashed_ip, domain);
            }

            let tenant_loopback_ip = if VpcVirtualizationType::Fnn == network_virtualization_type {
                let tenant_loopback_ip = VpcDpuLoopback::get_or_allocate_loopback_ip_for_vpc(
                    &api.common_pools,
                    txn,
                    &dpu_machine_id,
                    &vpc.id,
                )
                .await?;

                Some(tenant_loopback_ip.to_string())
            } else {
                None
            };

            for iface in interfaces {
                // This can not happen as validated during instance creation.
                let Some(iface_segment) = iface.network_segment_id else {
                    return Err(Status::internal(format!(
                        "Tenant segment is not assigned for iface: {:?}.",
                        iface
                    )));
                };

                let Some(segment) = segment_details.get(&iface_segment) else {
                    return Err(Status::internal(format!(
                        "Tenant segment id {} is not found in db. Can not fetch the details.",
                        iface_segment
                    )));
                };

                tenant_interfaces.push(
                    ethernet_virtualization::tenant_network(
                        txn,
                        instance.id,
                        iface,
                        fqdn.clone(),
                        // DPU agent reads loopback ip only from 0th interface.
                        // function build in nvue.rs
                        tenant_loopback_ip.clone(),
                        api.runtime_config.nvue_enabled,
                        network_virtualization_type,
                        network_security_group_details.clone(),
                        segment,
                        match api.runtime_config.vpc_peering_policy_on_existing {
                            None => api.runtime_config.vpc_peering_policy,
                            Some(vpc_peering_policy) => Some(vpc_peering_policy)
                        }
                    )
                    .await?,
                );
            }
            tenant_interfaces
        }
    };

    // If admin network is in use, use admin network's vpc_vni.
    if use_admin_network {
        // 0 means non-fnn case.
        vpc_vni = if admin_interface_rpc.vpc_vni != 0 {
            Some(admin_interface_rpc.vpc_vni)
        } else {
            None
        };
    }

    let network_config = rpc::ManagedHostNetworkConfig {
        loopback_ip: loopback_ip.to_string(),
        quarantine_state: snapshot
            .host_snapshot
            .network_config
            .quarantine_state
            .clone()
            .map(Into::into),
    };

    let asn = if network_virtualization_type == VpcVirtualizationType::Fnn {
        dpu_snapshot.asn.ok_or_else(|| {
            let message = format!(
                "FNN configured but DPU {} has not been assigned an ASN",
                dpu_snapshot.id
            );

            tracing::error!(message);
            CarbideError::internal(message)
        })?
    } else {
        api.eth_data.asn
    };

    let deny_prefixes: Vec<String> = api
        .eth_data
        .deny_prefixes
        .iter()
        .map(|net| net.to_string())
        .collect();

    let site_fabric_prefixes: Vec<String> = api
        .eth_data
        .site_fabric_prefixes
        .as_ref()
        .map(|s| s.as_ip_slice())
        .unwrap_or_default()
        .iter()
        .map(|net| net.to_string())
        .collect();

    let deprecated_deny_prefixes = match api.runtime_config.vpc_isolation_behavior {
        VpcIsolationBehaviorType::MutualIsolation => {
            [site_fabric_prefixes.as_slice(), deny_prefixes.as_slice()].concat()
        }
        VpcIsolationBehaviorType::Open => deny_prefixes.clone(),
    };

    let resp = rpc::ManagedHostNetworkConfigResponse {
        instance_id: snapshot
            .instance
            .as_ref()
            .map(|instance| instance.id.into()),
        asn,
        dhcp_servers: api.eth_data.dhcp_servers.clone(),
        route_servers: api.eth_data.route_servers.clone(),
        // TODO: Automatically add the prefix(es?) from the IPv4 loopback
        // pool to deny_prefixes. The database stores the pool in an
        // exploded representation, so we either need to reconstruct the
        // original prefix from what's in the database, or find some way to
        // store it when it's added or resized.
        deprecated_deny_prefixes,
        deny_prefixes,
        site_fabric_prefixes,
        datacenter_asn: api.runtime_config.datacenter_asn,
        vpc_isolation_behavior: rpc::VpcIsolationBehaviorType::from(
            api.runtime_config.vpc_isolation_behavior,
        )
        .into(),
        vni_device: if use_admin_network {
            "".to_string()
        } else {
            HBN_SINGLE_VLAN_DEVICE.to_string()
        },
        managed_host_config: Some(network_config),
        managed_host_config_version: dpu_snapshot.network_config.version.version_string(),
        use_admin_network,
        admin_interface: Some(admin_interface_rpc),
        tenant_interfaces,
        stateful_acls_enabled: api
            .runtime_config
            .network_security_group
            .stateful_acls_enabled,
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
        network_virtualization_type: Some(
            rpc::VpcVirtualizationType::from(network_virtualization_type).into(),
        ),
        vpc_vni,
        // Deprecated: this field is always true now.
        // This should be removed in future version.
        enable_dhcp: true,
        host_interface_id: Some(host_interface_id.to_string()),
        is_primary_dpu,
        multidpu_enabled: api.runtime_config.multi_dpu.enabled,
        min_dpu_functioning_links: api.runtime_config.min_dpu_functioning_links,
        dpu_network_pinger_type: api.runtime_config.dpu_network_monitor_pinger_type.clone(),
        internet_l3_vni: Some(api.runtime_config.internet_l3_vni),
        instance: maybe_instance,
    };

    // If this all worked, we shouldn't emit a log line
    tracing::Span::current().record("logfmt.suppress", true);

    Ok(resp)
}

pub(crate) async fn get_managed_host_network_config(
    api: &Api,
    request: Request<rpc::ManagedHostNetworkConfigRequest>,
) -> Result<tonic::Response<rpc::ManagedHostNetworkConfigResponse>, tonic::Status> {
    log_request_data(&request);

    let request = request.into_inner();
    let dpu_machine_id = convert_and_log_machine_id(request.dpu_machine_id.as_ref())?;

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin get_managed_host_network_config",
            e,
        ))
    })?;

    let snapshot = db::managed_host::load_snapshot(
        &mut txn,
        &dpu_machine_id,
        LoadSnapshotOptions::default().with_host_health(api.runtime_config.host_health),
    )
    .await
    .map_err(CarbideError::from)?
    .ok_or(CarbideError::NotFoundError {
        kind: "machine",
        id: dpu_machine_id.to_string(),
    })?;

    let resp =
        get_managed_host_network_config_inner(api, dpu_machine_id, snapshot, &mut txn).await?;

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit get_managed_host_network_config",
            e,
        ))
    })?;

    Ok(Response::new(resp))
}

pub(crate) async fn update_agent_reported_inventory(
    api: &Api,
    request: Request<rpc::DpuAgentInventoryReport>,
) -> Result<Response<()>, tonic::Status> {
    log_request_data(&request);

    let request = request.into_inner();
    let dpu_machine_id = convert_and_log_machine_id(request.machine_id.as_ref())?;

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
        db::machine::update_agent_reported_inventory(&mut txn, &dpu_machine_id, &inventory)
            .await
            .map_err(CarbideError::from)?;

        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(file!(), line!(), "commit inventory", e))
        })?;
    } else {
        return Err(Status::invalid_argument("inventory missing from request"));
    }

    tracing::debug!(
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
    let dpu_machine_id = convert_and_log_machine_id(request.dpu_machine_id.as_ref())?;

    // TODO: persist this somewhere
    let _fabric_interfaces_data = request.fabric_interfaces.as_slice();

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin record_dpu_network_status",
            e,
        ))
    })?;

    // Load the DPU Object. We require it to update the health report based
    // on the last report
    let dpu_machine = db::machine::find_one(
        &mut txn,
        &dpu_machine_id,
        MachineSearchConfig {
            include_dpus: true,
            // We should probably be setting this to to true everywhere
            // or including FOR UPDATE on all SELECT queries, but
            // this wasn't being done up to now.  Based on the nature
            // of health/status reporting (things could go
            // unhealthy at any time, including moments after
            // checking), the locking probably wouldn't buy much
            // here, but maybe someone with broader knowledge of
            // the codebase should re-examine that assumption.
            for_update: false,
            ..Default::default()
        },
    )
    .await
    .map_err(CarbideError::from)?
    .ok_or_else(|| CarbideError::NotFoundError {
        kind: "machine",
        id: dpu_machine_id.to_string(),
    })?;

    let machine_obs = {
        let mut obs = MachineNetworkStatusObservation::try_from(request.clone())
            .map_err(CarbideError::from)?;
        if let Some(agent_version) = obs.agent_version.as_ref() {
            obs.agent_version_superseded_at =
                db::forge_version::date_superseded(&mut txn, agent_version.as_str())
                    .await
                    .map_err(CarbideError::from)?;
        }
        obs
    };

    // Instance network observation is the part of network observation now.
    db::machine::update_network_status_observation(&mut txn, &dpu_machine_id, &machine_obs)
        .await
        .map_err(CarbideError::from)?;
    tracing::trace!(
        machine_id = %dpu_machine_id,
        machine_network_config = ?request.network_config_version,
        instance_network_config = ?request.instance_network_config_version,
        instance_config_version = ?request.instance_config_version,
        agent_version = machine_obs.agent_version,
        "Applied network configs",
    );

    // Store the DPU submitted health-report
    let mut health_report = health_report::HealthReport::try_from(
        request
            .dpu_health
            .as_ref()
            .ok_or_else(|| CarbideError::MissingArgument("dpu_health"))?
            .clone(),
    )
    .map_err(|e| CarbideError::internal(e.to_string()))?;
    // We ignore what dpu-agent sends as timestamp and time, and replace
    // it with more accurate information
    health_report.source = "forge-dpu-agent".to_string();
    health_report.observed_at = Some(chrono::Utc::now());
    // Fix the in_alert times based on the previously stored report
    health_report.update_in_alert_since(dpu_machine.dpu_agent_health_report.as_ref());

    db::machine::update_dpu_agent_health_report(&mut txn, &dpu_machine_id, &health_report)
        .await
        .map_err(CarbideError::from)?;

    for rpc::LastDhcpRequest {
        host_interface_id,
        timestamp,
    } in request.last_dhcp_requests.iter()
    {
        let Some(host_interface_id) = host_interface_id else {
            return Err(CarbideError::MissingArgument(
                "applied_config.last_dhcp_request.host_interface_id",
            )
            .into());
        };
        db::machine_interface::update_last_dhcp(
            &mut txn,
            MachineInterfaceId(
                uuid::Uuid::try_from(host_interface_id).map_err(CarbideError::from)?,
            ),
            Some(timestamp.parse().map_err(|e| {
                Status::invalid_argument(format!("Failed parsing dhcp timestamp: {e}"))
            })?),
        )
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
        let _needs_upgrade =
            db::machine::apply_agent_upgrade_policy(&mut txn, policy, &dpu_machine_id).await?;
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
    let suppress_log_key = match &request.network_config_error {
        Some(error) => error.to_string(),
        None => String::new(),
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

    let all_status = db::machine::get_all_network_status_observation(&mut txn, 2000)
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

/// Should this DPU upgrade its forge-dpu-agent?
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
    let machine = db::machine::find_one(&mut txn, &machine_id, MachineSearchConfig::default())
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

/// Trigger DPU reprovisioning
/// In case user passes a DPU ID, trigger_dpu_reprovisioning only for that particular DPU.
/// In case user passes a host id, trigger_dpu_reprovisioning
pub(crate) async fn trigger_dpu_reprovisioning(
    api: &Api,
    request: tonic::Request<rpc::DpuReprovisioningRequest>,
) -> Result<tonic::Response<()>, tonic::Status> {
    use ::rpc::forge::dpu_reprovisioning_request::Mode;

    log_request_data(&request);
    let req = request.into_inner();
    let machine_id = req.machine_id.as_ref().or(req.dpu_id.as_ref());
    let machine_id = convert_and_log_machine_id(machine_id)?;

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin trigger_dpu_reprovisioning ",
            e,
        ))
    })?;

    let snapshot = db::managed_host::load_snapshot(
        &mut txn,
        &machine_id,
        LoadSnapshotOptions {
            include_history: false,
            include_instance_data: false,
            host_health_config: api.runtime_config.host_health,
        },
    )
    .await
    .map_err(CarbideError::from)?
    .ok_or(CarbideError::NotFoundError {
        kind: "machine",
        id: machine_id.to_string(),
    })?;

    // Start reprovisioning only if the host has an HostUpdateInProgress health alert
    let update_alert = snapshot
        .aggregate_health
        .alerts
        .iter()
        .find(|a| a.id == *HOST_UPDATE_HEALTH_PROBE_ID);
    if !update_alert.is_some_and(|alert| {
        alert
            .classifications
            .contains(&health_report::HealthAlertClassification::prevent_allocations())
    }) {
        return Err(Status::invalid_argument(
            "Machine must have a 'HostUpdateInProgress' Health Alert with 'PreventAllocations' classification.",
        ));
    }

    if snapshot.dpu_snapshots.iter().any(|ms| {
        ms.reprovision_requested
            .as_ref()
            .is_some_and(|x| x.started_at.is_some())
    }) {
        match req.mode() {
            Mode::Restart => {}
            _ => {
                return Err(CarbideError::internal(
                    "Reprovisioning is already started.".to_string(),
                )
                .into());
            }
        }
    }

    match req.mode() {
        Mode::Set => {
            let initiator = req.initiator().as_str_name();
            if machine_id.machine_type().is_dpu() {
                db::machine::trigger_dpu_reprovisioning_request(
                    &machine_id,
                    &mut txn,
                    initiator,
                    req.update_firmware,
                )
                .await
                .map_err(CarbideError::from)?;
            } else {
                for dpu_snapshot in &snapshot.dpu_snapshots {
                    db::machine::trigger_dpu_reprovisioning_request(
                        &dpu_snapshot.id,
                        &mut txn,
                        initiator,
                        req.update_firmware,
                    )
                    .await
                    .map_err(CarbideError::from)?;
                }
            }
        }
        Mode::Clear => {
            if machine_id.machine_type().is_dpu() {
                db::machine::clear_dpu_reprovisioning_request(&mut txn, &machine_id, true)
                    .await
                    .map_err(CarbideError::from)?;
            } else {
                for dpu_snapshot in &snapshot.dpu_snapshots {
                    db::machine::clear_dpu_reprovisioning_request(&mut txn, &dpu_snapshot.id, true)
                        .await
                        .map_err(CarbideError::from)?;
                }
            }
        }
        Mode::Restart => {
            // Restart case.
            // Restart is valid only for host_id.
            if !machine_id.machine_type().is_host() {
                return Err(CarbideError::InvalidArgument("A restart has to be triggered for all DPUs together. Only host_id is accepted for restart operation.".to_string()).into());
            }

            if snapshot.dpu_snapshots.is_empty() {
                return Err(CarbideError::InvalidArgument(
                    "Machine has no DPUs, cannot trigger DPU reprovisioning.".to_string(),
                )
                .into());
            }

            let ids = snapshot
                .dpu_snapshots
                .iter()
                .filter_map(|x| {
                    if x.reprovision_requested.is_some() {
                        Some(&x.id)
                    } else {
                        None
                    }
                })
                .collect_vec();

            if ids.is_empty() {
                return Err(CarbideError::InvalidArgument(
                    "No DPUs are currently reprovisioning on {machine_id}, cannot restart reprovisioning. Use `set` to begin reprovisioning DPUs.".to_string(),
                )
                    .into());
            }

            db::machine::restart_dpu_reprovisioning(&mut txn, &ids, req.update_firmware)
                .await
                .map_err(CarbideError::from)?;
        }
    }

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "end trigger_dpu_reprovisioning",
            e,
        ))
    })?;

    Ok(Response::new(()))
}
