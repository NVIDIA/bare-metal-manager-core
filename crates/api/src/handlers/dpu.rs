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
use std::str::FromStr;

use ::rpc::errors::RpcDataConversionError;
use ::rpc::{common as rpc_common, forge as rpc};
use carbide_uuid::machine::MachineId;
use db::{
    DatabaseError, ObjectColumnFilter, WithTransaction, dpu_agent_upgrade_policy,
    network_security_group, network_segment,
};
use forge_network::virtualization::VpcVirtualizationType;
use futures_util::FutureExt;
use futures_util::future::join_all;
use itertools::Itertools;
use model::extension_service::{ExtensionService, ExtensionServiceVersionInfo};
use model::hardware_info::MachineInventory;
use model::instance::config::extension_services::InstanceExtensionServiceConfig;
use model::machine::machine_search_config::MachineSearchConfig;
use model::machine::network::MachineNetworkStatusObservation;
use model::machine::upgrade_policy::{AgentUpgradePolicy, BuildVersion};
use model::machine::{InstanceState, LoadSnapshotOptions, ManagedHostState};
use model::machine_update_module::HOST_UPDATE_HEALTH_PROBE_ID;
use model::network_segment::NetworkSegmentSearchConfig;
use tonic::{Request, Response, Status};
use utils::models::arch::CpuArchitecture;

use crate::api::{Api, log_machine_id, log_request_data};
use crate::cfg::file::VpcIsolationBehaviorType;
use crate::handlers::extension_service;
use crate::handlers::utils::convert_and_log_machine_id;
use crate::{CarbideError, ethernet_virtualization};

/// vxlan48 is special HBN single vxlan device. It handles networking between machines on the
/// same subnet. It handles the encapsulation into VXLAN and VNI for cross-host comms.
const HBN_SINGLE_VLAN_DEVICE: &str = "vxlan48";

pub(crate) async fn get_managed_host_network_config_inner(
    api: &Api,
    dpu_machine_id: MachineId,
) -> Result<rpc::ManagedHostNetworkConfigResponse, tonic::Status> {
    let mut txn = api.txn_begin().await?;

    let snapshot = db::managed_host::load_snapshot(
        &mut txn,
        &dpu_machine_id,
        LoadSnapshotOptions::default().with_host_health(api.runtime_config.host_health),
    )
    .await?
    .ok_or(CarbideError::NotFoundError {
        kind: "machine",
        id: dpu_machine_id.to_string(),
    })?;

    let dpu_snapshot = match snapshot
        .dpu_snapshots
        .iter()
        .find(|s| s.id == dpu_machine_id)
    {
        Some(dpu_snapshot) => dpu_snapshot,
        None => {
            return Err(Status::failed_precondition(format!(
                "DPU {dpu_machine_id} needs discovery.  DPU snapshot not found for managed host"
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

    let primary_dpu = db::machine_interface::find_one(&mut txn, primary_dpu_snapshot.id).await?;
    let is_primary_dpu = primary_dpu
        .attached_dpu_machine_id
        .map(|x| x == dpu_snapshot.id)
        .unwrap_or(false);

    let loopback_ip = match dpu_snapshot.loopback_ip() {
        Some(ip) => ip,
        None => {
            return Err(Status::failed_precondition(format!(
                "DPU {dpu_machine_id} needs discovery. Does not have a loopback IP yet."
            )));
        }
    };

    if api
        .runtime_config
        .vmaas_config
        .as_ref()
        .map(|vc| vc.secondary_overlay_support)
        .unwrap_or_default()
        && dpu_snapshot
            .network_config
            .secondary_overlay_vtep_ip
            .is_none()
    {
        return Err(Status::failed_precondition(format!(
            "DPU {dpu_machine_id} needs discovery. Does not have a secondary VTEP IP yet."
        )));
    };

    // its ok if there is no locator here.  if there isn't one, then only the primary dpu is allowed to be configred (checked below)
    let device_locator = snapshot
        .host_snapshot
        .get_device_locator_for_dpu_id(&dpu_machine_id)
        .ok();

    let dpu_has_tenant_interface_config =
        snapshot
            .instance
            .as_ref()
            .is_some_and(|interface_snapshot| {
                interface_snapshot
                    .config
                    .network
                    .interfaces
                    .iter()
                    .any(|interface_config| {
                        (interface_config.device_locator.is_none() && is_primary_dpu)
                            || (interface_config.device_locator.is_some()
                                && device_locator == interface_config.device_locator)
                    })
            });

    // If there is an instance, the state machine sets all DPUs to be on the tenant network.  But if there are
    // no interfaces configured for this DPU, then override and put it back on the admin network.  This will
    // prevent the host from using the DPU at all.
    let use_admin_network = dpu_snapshot.use_admin_network() || !dpu_has_tenant_interface_config;

    let mut network_virtualization_type = if api.runtime_config.nvue_enabled {
        VpcVirtualizationType::EthernetVirtualizerWithNvue
    } else {
        VpcVirtualizationType::EthernetVirtualizer
    };

    let mut use_fnn_over_admin_nw = false;

    // If FNN config is enabled, we should use it in admin network.
    if let Some(fnn) = &api.runtime_config.fnn
        && let Some(admin) = &fnn.admin_vpc
        && admin.enabled
    {
        use_fnn_over_admin_nw = true;
        network_virtualization_type = VpcVirtualizationType::Fnn;
    }

    let booturl_override = if snapshot
        .host_snapshot
        .hardware_info
        .as_ref()
        .map(|h| h.machine_type)
        == Some(CpuArchitecture::X86_64)
    {
        api.runtime_config.x86_pxe_boot_url_override.clone()
    } else {
        api.runtime_config.arm_pxe_boot_url_override.clone()
    };

    let (admin_interface_rpc, host_interface_id) = ethernet_virtualization::admin_network(
        &mut txn,
        &snapshot.host_snapshot.id,
        &dpu_snapshot.id,
        use_fnn_over_admin_nw,
        &api.common_pools,
        &booturl_override,
    )
    .await?;

    // If admin network is in use and is fnn, use admin network's vpc_vni.
    let mut vpc_vni = if use_admin_network && admin_interface_rpc.vpc_vni != 0 {
        Some(admin_interface_rpc.vpc_vni)
    } else {
        None
    };

    let admin_vpc_routing_profile = api
        .runtime_config
        .fnn
        .as_ref()
        .and_then(|f| f.admin_vpc.as_ref())
        .map(|v| &v.routing_profile);

    let (routing_profile, tenant_interfaces) = match &snapshot.instance {
        None => (admin_vpc_routing_profile, vec![]),
        // We don't support secondary DPU yet.
        // If admin network is to be used for this managedhost, why to send old tenant data, which
        // is just to be deleted.
        Some(_instance) if use_admin_network => {
            (admin_vpc_routing_profile, vec![])
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
            (admin_vpc_routing_profile, vec![])
        }
        Some(instance) => {
            let interfaces = &instance.config.network.interfaces;
            let Some(network_segment_id) = interfaces[0].network_segment_id else {
                // Network segment allocation is done before persisting record in db. So if still
                // network segment is empty, return error.
                return Err(CarbideError::NetworkSegmentNotAllocated.into());
            };
            let vpc = db::vpc::find_by_segment(&mut txn, network_segment_id)
                .await?;

            // We probably shouldn't allow multiple interfaces that are in different VPCs with
            // different routing-profiles.  Even in the case of something like a GW instance,
            // We should probably require that all tenants/vpcs being serviced have a routing profile
            // that matches the GW instance.
            // However, if we decide to allow total mixing-and-matching, then this would need to move into
            // tenant_network() and the profile details would have to move into the flattened interface details.
            let routing_profile =  if vpc.network_virtualization_type == VpcVirtualizationType::Fnn {
                api
                    .runtime_config
                    .fnn
                    .as_ref()
                    .map(|f| {
                        let Some(profile_type) = vpc.routing_profile_type.map(|t| t.to_string()) else {
                            return Err(CarbideError::Internal{ message: "tenant routing profile type not found in tenant record".to_string()});
                        };

                        let Some(profile) = f.routing_profiles.get(&profile_type) else {
                            return Err(CarbideError::NotFoundError {
                                kind: "routing profile type found in tenant record is not defined",
                                id: profile_type,
                            });
                        };
                    Ok(profile)
                })
                .transpose()?
            } else {
                None
            };

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

            let suppress_tenant_security_groups = match &snapshot.managed_state {
                ManagedHostState::Assigned { instance_state } => {
                    // Within the BootingWithDiscoveryImage state, we use the
                    // tenant's network to boot the discovery/scout image via
                    // PXE, and then phone home via HTTPS to the API to signal
                    // that the machine is no longer running the tenant OS (at
                    // which point it's safe to move to the admin network). The
                    // tenant's NSGs can interfere with these connections, so we
                    // must avoid installing them.
                    matches!(instance_state, InstanceState::BootingWithDiscoveryImage { ..})
                },
                _ => false,
            };

            // Check if there's an NSG on the instance.
            let network_security_group_details = if !suppress_tenant_security_groups
                && let Some((tenant_id, Some(nsg_id))) = snapshot.instance.as_ref().map(|i| {
                (
                    &i.config.tenant.tenant_organization_id,
                    i.config.network_security_group_id.as_ref(),
                )
            }) {
                // Make our DB query for the IDs to get our NetworkSecurityGroup
                let network_security_group =
                    network_security_group::find_by_ids(&mut txn, &[nsg_id.to_owned()], Some(tenant_id), false)
                        .await?
                        .pop()
                        .ok_or(CarbideError::NotFoundError {
                            kind: "NetworkSecurityGroup",
                            id: tenant_id.to_string(),
                        })?;

                Some((
                    i32::from(rpc::NetworkSecurityGroupSource::NsgSourceInstance),
                    network_security_group,
                ))
            } else {
                None
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
            let segment_details = db::network_segment::find_by(
                &mut txn,
                ObjectColumnFilter::List(network_segment::IdColumn, &segment_ids),
                NetworkSegmentSearchConfig::default(),
            ).await?;

            let segment_details = segment_details.iter().map(|x|(x.id, x)).collect::<HashMap<_,_>>();

            let Some(segment) = segment_details.get(&network_segment_id) else {
                return Err(Status::internal(format!(
                    "Tenant segment id {network_segment_id} is not found in db."
                )));
            };

            let domain = match segment.subdomain_id {
                Some(domain_id) => {
                    db::dns::domain::find_by_uuid(&mut txn, domain_id)
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
                fqdn = format!("{hostname}.{domain}");
            } else {
                let dashed_ip: String = physical_ip
                    .to_string()
                    .split('.')
                    .collect::<Vec<&str>>()
                    .join("-");
                fqdn = format!("{dashed_ip}.{domain}");
            }

            let tenant_loopback_ip = if VpcVirtualizationType::Fnn == network_virtualization_type {
                let tenant_loopback_ip = db::vpc_dpu_loopback::get_or_allocate_loopback_ip_for_vpc(
                    &api.common_pools,
                    &mut txn,
                    &dpu_machine_id,
                    &vpc.id,
                )
                .await?;

                Some(tenant_loopback_ip.to_string())
            } else {
                None
            };

            // if there is no device then this is a legacy config and only the primary dpu is allowed.
            // all other DPUs don't get interfaces
            for iface in interfaces.iter().filter(|i|
                (i.device_locator.is_none() && is_primary_dpu) || (i.device_locator.as_ref().is_some_and(|dl| device_locator.as_ref().is_some_and(|dl2| dl2 == dl)))
            ) {
                // This can not happen as validated during instance creation.
                let Some(iface_segment) = iface.network_segment_id else {
                    return Err(Status::internal(format!(
                        "Tenant segment is not assigned for iface: {iface:?}."
                    )));
                };

                let Some(segment) = segment_details.get(&iface_segment) else {
                    return Err(Status::internal(format!(
                        "Tenant segment id {iface_segment} is not found in db. Can not fetch the details."
                    )));
                };

                let tenant_interface =
                    ethernet_virtualization::tenant_network(
                        &mut txn,
                        instance.id,
                        iface,
                        fqdn.clone(),
                        // DPU agent reads loopback ip only from 0th interface.
                        // function build in nvue.rs
                        tenant_loopback_ip.clone(),
                        api.runtime_config.nvue_enabled,
                        network_virtualization_type,
                        suppress_tenant_security_groups,
                        network_security_group_details.clone(),
                        segment,
                        match api.runtime_config.vpc_peering_policy_on_existing {
                            None => api.runtime_config.vpc_peering_policy,
                            Some(vpc_peering_policy) => Some(vpc_peering_policy)
                        },
                        &booturl_override,
                )
                .await?;

                tenant_interfaces.push(tenant_interface);
            }

            (routing_profile, tenant_interfaces)
        }
    };

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

    // Strip the source_type for the route servers that we feed back to the DPUs -- they just care
    // about the IP address. Although, maybe in the future, we might be interested in sending the
    // entire struct down, and then putting some smarts inside the DPU re: the source_type.
    // Only pass them on if route servers are enabled.
    let route_servers = if api.runtime_config.enable_route_servers {
        db::route_servers::get(&mut txn)
            .await?
            .into_iter()
            .map(|rs| rs.address.to_string())
            .collect()
    } else {
        vec![]
    };

    // If instance is present, get the extension services configured for the instance.

    // simple grouping of stuff we need from the extension service:
    struct ExtensionServiceInfo<'a> {
        service: ExtensionService,
        version: ExtensionServiceVersionInfo,
        instance_config: &'a InstanceExtensionServiceConfig,
    }

    // First fetch from the database, while we have a transaction:
    let extension_service_info = if let Some(instance) = snapshot.instance.as_ref() {
        let mut extension_service_info: Vec<ExtensionServiceInfo> =
            Vec::with_capacity(instance.config.extension_services.service_configs.len());
        for config in &instance.config.extension_services.service_configs {
            // @TODO(Felicity): optimize database query to fetch all extension service versions at once.
            //  This might be ok for now since the number of extension services is expected to be small.
            let service_res =
                db::extension_service::find_by_ids(&mut txn, &[config.service_id], false).await?;
            let service =
                service_res
                    .into_iter()
                    .next()
                    .ok_or_else(|| CarbideError::NotFoundError {
                        kind: "ExtensionService",
                        id: config.service_id.to_string(),
                    })?;

            let version = db::extension_service::find_version_info(
                &mut txn,
                config.service_id,
                Some(config.version),
            )
            .await?;

            extension_service_info.push(ExtensionServiceInfo {
                service,
                version,
                instance_config: config,
            });
        }
        extension_service_info
    } else {
        Vec::new()
    };

    // Next, get credentials for each extension service from vault. This should be done after the
    // transaction is committed.
    txn.commit().await?;
    let extension_services = join_all(extension_service_info.into_iter().map(|info| async move {
        // Get the credential if it exists
        let credential = if info.version.has_credential {
            let key = extension_service::create_extension_service_credential_key(
                &info.service.id,
                info.version.version,
            );
            Some(
                extension_service::get_extension_service_credential(&api.credential_provider, key)
                    .await?,
            )
        } else {
            None
        };

        Ok::<_, tonic::Status>(rpc::ManagedHostDpuExtensionServiceConfig {
            service_id: info.service.id.to_string(),
            name: info.service.name,
            removed: info.instance_config.removed.map(|ts| ts.to_string()),
            version: info.version.version.to_string(),
            service_type: rpc::DpuExtensionServiceType::from(info.service.service_type.clone())
                .into(),
            data: info.version.data,
            credential,
            observability: info.version.observability.map(|o| o.into()),
        })
    }))
    .await
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?;

    let resp = rpc::ManagedHostNetworkConfigResponse {
        instance_id: snapshot.instance.as_ref().map(|instance| instance.id),
        asn,
        dhcp_servers: api.eth_data.dhcp_servers.clone(),
        route_servers,
        // TODO: Automatically add the prefix(es?) from the IPv4 loopback
        // pool to deny_prefixes. The database stores the pool in an
        // exploded representation, so we either need to reconstruct the
        // original prefix from what's in the database, or find some way to
        // store it when it's added or resized.
        deprecated_deny_prefixes,
        deny_prefixes,
        site_fabric_prefixes,
        anycast_site_prefixes: api
            .runtime_config
            .anycast_site_prefixes
            .iter()
            .map(|p| p.to_string())
            .collect(),
        tenant_host_asn: api.runtime_config.common_tenant_host_asn,
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
        site_global_vpc_vni: api.runtime_config.site_global_vpc_vni,
        managed_host_config: Some(network_config),
        managed_host_config_version: dpu_snapshot.network_config.version.version_string(),
        use_admin_network,
        admin_interface: Some(admin_interface_rpc),
        tenant_interfaces,
        network_security_policy_overrides: api
            .runtime_config
            .network_security_group
            .policy_overrides
            .iter()
            .map(|r| ethernet_virtualization::resolve_security_group_rule(r.clone()))
            .collect::<Result<Vec<rpc::ResolvedNetworkSecurityGroupRule>, CarbideError>>()?,
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
        min_dpu_functioning_links: api.runtime_config.min_dpu_functioning_links,
        dpu_network_pinger_type: api.runtime_config.dpu_network_monitor_pinger_type.clone(),
        internet_l3_vni: Some(api.runtime_config.internet_l3_vni), // Deprecated.  Remove when all agents and controllers are on a version that doesn't expect this.
        common_internal_route_target: api.runtime_config.fnn.as_ref().and_then(|c| {
            c.common_internal_route_target
                .as_ref()
                .map(|rt| rpc_common::RouteTarget {
                    asn: rt.asn,
                    vni: rt.vni,
                })
        }),
        routing_profile: routing_profile.map(|p| rpc::RoutingProfile {
            route_target_imports: p
                .route_target_imports
                .iter()
                .map(|rt| rpc_common::RouteTarget {
                    asn: rt.asn,
                    vni: rt.vni,
                })
                .collect(),
            route_targets_on_exports: p
                .route_targets_on_exports
                .iter()
                .map(|rt| rpc_common::RouteTarget {
                    asn: rt.asn,
                    vni: rt.vni,
                })
                .collect(),
        }),
        traffic_intercept_config: api.runtime_config.vmaas_config.as_ref().map(|c| {
            rpc::TrafficInterceptConfig {
                bridging: c.bridging.as_ref().map(|b| rpc::TrafficInterceptBridging {
                    internal_bridge_routing_prefix: b.internal_bridge_routing_prefix.to_string(),
                    host_intercept_bridge_name: b.host_intercept_bridge_name.clone(),
                    vf_intercept_bridge_name: b.vf_intercept_bridge_name.clone(),
                    vf_intercept_bridge_port: b.vf_intercept_bridge_port.clone(),
                    host_intercept_bridge_port: b.host_intercept_bridge_port.clone(),
                    vf_intercept_bridge_sf: b.vf_intercept_bridge_sf.clone(),
                }),
                public_prefixes: c.public_prefixes.iter().map(|p| p.to_string()).collect(),
                additional_overlay_vtep_ip: dpu_snapshot
                    .network_config
                    .secondary_overlay_vtep_ip
                    .map(|i| i.to_string()),
            }
        }),

        additional_route_target_imports: api
            .runtime_config
            .fnn
            .as_ref()
            .map(|c| {
                c.additional_route_target_imports
                    .iter()
                    .map(|i| rpc_common::RouteTarget {
                        asn: i.asn,
                        vni: i.vni,
                    })
                    .collect()
            })
            .unwrap_or_default(),
        instance: maybe_instance,
        dpu_extension_services: extension_services,
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

    let resp = get_managed_host_network_config_inner(api, dpu_machine_id).await?;

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
        let mut txn = api.txn_begin().await?;

        let inventory =
            MachineInventory::try_from(inventory.clone()).map_err(CarbideError::from)?;
        db::machine::update_agent_reported_inventory(&mut txn, &dpu_machine_id, &inventory).await?;

        txn.commit().await?;
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

    let mut txn = api.txn_begin().await?;

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
    .await?
    .ok_or_else(|| CarbideError::NotFoundError {
        kind: "machine",
        id: dpu_machine_id.to_string(),
    })?;

    let machine_obs = {
        let mut obs = MachineNetworkStatusObservation::try_from(request.clone())
            .map_err(CarbideError::from)?;
        if let Some(agent_version) = obs.agent_version.as_ref() {
            obs.agent_version_superseded_at =
                db::carbide_version::date_superseded(&mut txn, agent_version.as_str()).await?;
        }
        obs
    };

    let any_observed_version_changed = match dpu_machine.network_status_observation {
        None => true,
        Some(old_observation) => old_observation.any_observed_version_changed(&machine_obs),
    };

    // Instance network observation is the part of network observation now.
    db::machine::update_network_status_observation(&mut txn, &dpu_machine_id, &machine_obs).await?;
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

    db::machine::update_dpu_agent_health_report(&mut txn, &dpu_machine_id, &health_report).await?;

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
            *host_interface_id,
            Some(timestamp.parse().map_err(|e| {
                Status::invalid_argument(format!("Failed parsing dhcp timestamp: {e}"))
            })?),
        )
        .await?;
    }

    txn.commit().await?;

    // Check if we need to flag this forge-dpu-agent for upgrade or mark an upgrade completed
    // We do this here because we just learnt about which version of forge-dpu-agent is
    // running.
    let mut txn = api.txn_begin().await?;

    if let Some(policy) = dpu_agent_upgrade_policy::get(&mut txn).await? {
        let _needs_upgrade =
            db::machine::apply_agent_upgrade_policy(&mut txn, policy, &dpu_machine_id).await?;
    }

    txn.commit().await?;

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

    // After everything else is done and the transaction is actually committed - wakeup
    // the host state handler to speed up reaction on the state change.
    // We only do this wakeup in case anything interesting changed to avoid the
    // state handler running unnecessarily.
    if any_observed_version_changed
        && let Err(err) = wakeup_host_state_handler_by_dpu_id(api, &dpu_machine_id).await
    {
        tracing::warn!(%err, %dpu_machine_id, "Failed to wakeup state handler for host machine");
    }

    Ok(Response::new(()))
}

async fn wakeup_host_state_handler_by_dpu_id(
    api: &Api,
    dpu_machine_id: &MachineId,
) -> Result<(), DatabaseError> {
    let mut txn = api.txn_begin().await?;
    let host_machine =
        db::machine::lookup_host_machine_ids_by_dpu_ids(&mut txn, &[*dpu_machine_id]).await?;
    txn.rollback().await?;

    if let Some(host_machine_id) = host_machine.first() {
        api.machine_state_handler_enqueuer
            .enqueue_object(host_machine_id)
            .await?;
    }

    Ok(())
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

    let all_status = api
        .with_txn(|txn| db::machine::get_all_network_status_observation(txn, 2000).boxed())
        .await??;

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
    let server_version = carbide_version::v!(build_version);
    BuildVersion::try_from(server_version)
        .map_err(|_| Status::internal("Invalid server version, cannot check for upgrade"))?;

    let mut txn = api.txn_begin().await?;

    let machine =
        db::machine::find_one(&mut txn, &machine_id, MachineSearchConfig::default()).await?;
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
    txn.commit().await?;

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

    let mut txn = api.txn_begin().await?;

    let req = request.into_inner();
    let mut did_change = false;
    if let Some(new_policy) = req.new_policy {
        let policy: AgentUpgradePolicy = new_policy.into();

        dpu_agent_upgrade_policy::set(&mut txn, policy).await?;
        did_change = true;
    }

    let Some(active_policy) = dpu_agent_upgrade_policy::get(&mut txn).await? else {
        return Err(tonic::Status::not_found("No agent upgrade policy"));
    };
    txn.commit().await?;

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

    let mut txn = api.txn_begin().await?;

    let snapshot = db::managed_host::load_snapshot(
        &mut txn,
        &machine_id,
        LoadSnapshotOptions {
            include_history: false,
            include_instance_data: false,
            host_health_config: api.runtime_config.host_health,
        },
    )
    .await?
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
                .await?;
            } else {
                for dpu_snapshot in &snapshot.dpu_snapshots {
                    db::machine::trigger_dpu_reprovisioning_request(
                        &dpu_snapshot.id,
                        &mut txn,
                        initiator,
                        req.update_firmware,
                    )
                    .await?;
                }
            }
        }
        Mode::Clear => {
            if machine_id.machine_type().is_dpu() {
                db::machine::clear_dpu_reprovisioning_request(&mut txn, &machine_id, true).await?;
            } else {
                for dpu_snapshot in &snapshot.dpu_snapshots {
                    db::machine::clear_dpu_reprovisioning_request(&mut txn, &dpu_snapshot.id, true)
                        .await?;
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

            db::machine::restart_dpu_reprovisioning(&mut txn, &ids, req.update_firmware).await?;
        }
    }

    txn.commit().await?;

    Ok(Response::new(()))
}

// List DPUs waiting for reprovisioning
pub(crate) async fn list_dpu_waiting_for_reprovisioning(
    api: &Api,
    request: Request<rpc::DpuReprovisioningListRequest>,
) -> Result<Response<rpc::DpuReprovisioningListResponse>, Status> {
    log_request_data(&request);

    let dpus = api
        .with_txn(|txn| db::machine::list_machines_requested_for_reprovisioning(txn).boxed())
        .await??
        .into_iter()
        .map(
            |x| rpc::dpu_reprovisioning_list_response::DpuReprovisioningListItem {
                id: Some(x.id),
                state: x.current_state().to_string(),
                requested_at: x
                    .reprovision_requested
                    .as_ref()
                    .map(|a| a.requested_at.into()),
                initiator: x
                    .reprovision_requested
                    .as_ref()
                    .map(|a| a.initiator.clone())
                    .unwrap_or_default(),
                update_firmware: x
                    .reprovision_requested
                    .as_ref()
                    .map(|a| a.update_firmware)
                    .unwrap_or_default(),
                initiated_at: x
                    .reprovision_requested
                    .as_ref()
                    .map(|a| a.started_at.map(|x| x.into()))
                    .unwrap_or_default(),
                user_approval_received: x
                    .reprovision_requested
                    .as_ref()
                    .map(|x| x.user_approval_received)
                    .unwrap_or_default(),
            },
        )
        .collect_vec();

    Ok(Response::new(rpc::DpuReprovisioningListResponse { dpus }))
}
