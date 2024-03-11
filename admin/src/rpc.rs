/*
 * SPDX-FileCopyrightText: Copyright (c) 2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::future::Future;
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;

use ::rpc::forge::dpu_reprovisioning_request::Mode;
use ::rpc::forge::{
    self as rpc, MachineBootOverride, MachineSearchConfig, MachineType, NetworkSegmentSearchConfig,
};
use ::rpc::forge_tls_client::{self, ApiConfig, ForgeClientT};
use ::rpc::{MachineId, Uuid};

use super::{CarbideCliError, CarbideCliResult};
use crate::cfg::carbide_options::ForceDeleteMachineQuery;
pub async fn with_forge_client<'a, T, F>(
    api_config: &ApiConfig<'a>,
    callback: impl FnOnce(ForgeClientT) -> F,
) -> CarbideCliResult<T>
where
    F: Future<Output = CarbideCliResult<T>>,
{
    let client = forge_tls_client::ForgeTlsClient::retry_build(api_config)
        .await
        .map_err(|err| CarbideCliError::ApiConnectFailed(err.to_string()))?;

    callback(client).await
}

pub async fn get_machine(id: String, api_config: &ApiConfig<'_>) -> CarbideCliResult<rpc::Machine> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::MachineId { id });
        let machine_details = client
            .get_machine(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;

        Ok(machine_details)
    })
    .await
}

pub async fn get_network_device_topology(
    id: Option<String>,
    api_config: &ApiConfig<'_>,
) -> CarbideCliResult<rpc::NetworkTopologyData> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::NetworkTopologyRequest { id });
        let topology = client
            .get_network_topology(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;

        Ok(topology)
    })
    .await
}

// this uses deprecated APIs and should not be used.
// exists for backwards compatability with older APIs
pub async fn get_all_machines_deprecated(
    api_config: &ApiConfig<'_>,
    machine_type: Option<MachineType>,
    only_maintenance: bool,
) -> CarbideCliResult<rpc::MachineList> {
    let include_dpus = machine_type.map(|t| t == MachineType::Dpu).unwrap_or(true);
    let exclude_hosts = machine_type
        .map(|t| t != MachineType::Host)
        .unwrap_or(false);
    let include_predicted_host = machine_type.map(|t| t == MachineType::Host).unwrap_or(true);

    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::MachineSearchQuery {
            id: None,
            fqdn: None,
            search_config: Some(rpc::MachineSearchConfig {
                include_dpus,
                include_history: true,
                include_predicted_host,
                only_maintenance,
                include_associated_machine_id: false,
                exclude_hosts,
            }),
        });
        let machine_details = client
            .find_machines(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;

        let machines = machine_details
            .machines
            .into_iter()
            .filter(|m| {
                if only_maintenance && m.maintenance_reference.is_none() {
                    return false;
                }
                if !include_dpus
                    && m.id
                        .as_ref()
                        .map_or(false, |id| id.id.starts_with("fm100d"))
                {
                    return false;
                }
                if !include_predicted_host
                    && m.id
                        .as_ref()
                        .map_or(false, |id| id.id.starts_with("fm100p"))
                {
                    return false;
                }
                if exclude_hosts
                    && m.id
                        .as_ref()
                        .map_or(false, |id| !id.id.starts_with("fm100d"))
                {
                    return false;
                }
                true
            })
            .collect();
        Ok(rpc::MachineList { machines })
    })
    .await
}

pub async fn get_all_machines(
    api_config: &ApiConfig<'_>,
    machine_type: Option<MachineType>,
    only_maintenance: bool,
) -> CarbideCliResult<rpc::MachineList> {
    let all_machine_ids = match find_machine_ids(api_config, machine_type, only_maintenance).await {
        Ok(all_machine_ids) => all_machine_ids,
        Err(CarbideCliError::ApiInvocationError(status))
            if status.code() == tonic::Code::Unimplemented =>
        {
            return get_all_machines_deprecated(api_config, machine_type, only_maintenance).await;
        }
        Err(e) => return Err(e),
    };
    let mut all_machines = rpc::MachineList {
        machines: Vec::with_capacity(all_machine_ids.machine_ids.len()),
    };

    for machine_ids in all_machine_ids.machine_ids.chunks(100) {
        let machines = get_machines_by_ids(api_config, machine_ids).await?;
        all_machines.machines.extend(machines.machines);
    }

    Ok(all_machines)
}

pub async fn reboot_instance(
    api_config: &ApiConfig<'_>,
    machine_id: MachineId,
    boot_with_custom_ipxe: bool,
    apply_updates_on_reboot: bool,
) -> CarbideCliResult<()> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::InstancePowerRequest {
            machine_id: Some(machine_id),
            operation: rpc::instance_power_request::Operation::PowerReset as i32,
            boot_with_custom_ipxe,
            apply_updates_on_reboot,
        });

        client
            .invoke_instance_power(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;

        Ok(())
    })
    .await
}

pub async fn release_instance(
    api_config: &ApiConfig<'_>,
    instance_id: rpc::Uuid,
) -> CarbideCliResult<()> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::InstanceReleaseRequest {
            id: Some(instance_id),
        });
        client
            .release_instance(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;
        Ok(())
    })
    .await
}

pub async fn get_instances(
    api_config: &ApiConfig<'_>,
    id: Option<String>,
) -> CarbideCliResult<rpc::InstanceList> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::InstanceSearchQuery {
            id: id.map(|x| rpc::Uuid { value: x }),
        });
        let instance_details = client
            .find_instances(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;

        Ok(instance_details)
    })
    .await
}

pub async fn get_instances_by_machine_id(
    api_config: &ApiConfig<'_>,
    id: String,
) -> CarbideCliResult<rpc::InstanceList> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::MachineId { id });
        let instance_details = client
            .find_instance_by_machine_id(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;

        Ok(instance_details)
    })
    .await
}

pub async fn get_segments(
    id: Option<rpc::Uuid>,
    api_config: &ApiConfig<'_>,
) -> CarbideCliResult<rpc::NetworkSegmentList> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::NetworkSegmentQuery {
            id,
            search_config: Some(NetworkSegmentSearchConfig {
                include_history: true,
            }),
        });
        let networks = client
            .find_network_segments(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;

        Ok(networks)
    })
    .await
}

pub async fn get_domains(
    id: Option<rpc::Uuid>,
    api_config: &ApiConfig<'_>,
) -> CarbideCliResult<rpc::DomainList> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::DomainSearchQuery { id, name: None });
        let networks = client
            .find_domain(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;

        Ok(networks)
    })
    .await
}

pub async fn get_dpu_ssh_credential(
    query: String,
    api_config: &ApiConfig<'_>,
) -> CarbideCliResult<rpc::CredentialResponse> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::CredentialRequest { host_id: query });
        let cred = client
            .get_dpu_ssh_credential(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;

        Ok(cred)
    })
    .await
}

pub async fn get_all_managed_host_network_status(
    api_config: &ApiConfig<'_>,
) -> CarbideCliResult<rpc::ManagedHostNetworkStatusResponse> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::ManagedHostNetworkStatusRequest {});
        let all = client
            .get_all_managed_host_network_status(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;

        Ok(all)
    })
    .await
}

pub async fn get_managed_host_network_config(
    id: String,
    api_config: &ApiConfig<'_>,
) -> CarbideCliResult<rpc::ManagedHostNetworkConfigResponse> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::ManagedHostNetworkConfigRequest {
            dpu_machine_id: Some(rpc::MachineId { id }),
        });
        let all = client
            .get_managed_host_network_config(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;

        Ok(all)
    })
    .await
}

pub async fn machine_admin_force_delete(
    query: ForceDeleteMachineQuery,
    api_config: &ApiConfig<'_>,
) -> CarbideCliResult<::rpc::forge::AdminForceDeleteMachineResponse> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(::rpc::forge::AdminForceDeleteMachineRequest {
            host_query: query.machine,
        });
        let response = client
            .admin_force_delete_machine(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;

        Ok(response)
    })
    .await
}

// How will we find the BMC credentials to perform the reboot?
pub enum RebootAuth {
    // User provided them directly on command line
    Direct { user: String, password: String },
    // Carbide should look them up in Vault
    Indirect { machine_id: String },
}

pub type ResetAuth = RebootAuth;

pub async fn reboot(
    api_config: &ApiConfig<'_>,
    ip: String,
    port: Option<u32>,
    auth: RebootAuth,
) -> CarbideCliResult<rpc::AdminRebootResponse> {
    with_forge_client(api_config, |mut client| async move {
        let (user, password, machine_id) = match auth {
            RebootAuth::Direct { user, password } => (Some(user), Some(password), None),
            RebootAuth::Indirect { machine_id } => (None, None, Some(machine_id)),
        };
        let request = tonic::Request::new(rpc::AdminRebootRequest {
            ip,
            port,
            user,
            password,
            machine_id,
        });
        let out = client
            .admin_reboot(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;
        Ok(out)
    })
    .await
}

pub async fn grow_resource_pool(
    req: rpc::GrowResourcePoolRequest,
    api_config: &ApiConfig<'_>,
) -> CarbideCliResult<rpc::GrowResourcePoolResponse> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(req);
        let out = client
            .admin_grow_resource_pool(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;
        Ok(out)
    })
    .await
}

pub async fn list_resource_pools(
    req: rpc::ListResourcePoolsRequest,
    api_config: &ApiConfig<'_>,
) -> CarbideCliResult<rpc::ResourcePools> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(req);
        let out = client
            .admin_list_resource_pools(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;
        Ok(out)
    })
    .await
}

pub async fn version(
    api_config: &ApiConfig<'_>,
    display_config: bool,
) -> CarbideCliResult<rpc::BuildInfo> {
    with_forge_client(api_config, |mut client| async move {
        let out = client
            .version(tonic::Request::new(rpc::VersionRequest { display_config }))
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;
        Ok(out)
    })
    .await
}

pub async fn set_maintenance(
    req: rpc::MaintenanceRequest,
    api_config: &ApiConfig<'_>,
) -> CarbideCliResult<()> {
    with_forge_client(api_config, |mut client| async move {
        client
            .set_maintenance(tonic::Request::new(req))
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;
        Ok(())
    })
    .await
}

pub async fn find_ip_address(
    req: rpc::FindIpAddressRequest,
    api_config: &ApiConfig<'_>,
) -> CarbideCliResult<rpc::FindIpAddressResponse> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(req);
        let out = client
            .find_ip_address(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;
        Ok(out)
    })
    .await
}

pub async fn migrate_vpc_vni(
    api_config: &ApiConfig<'_>,
) -> CarbideCliResult<rpc::MigrateVpcVniResponse> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(());
        let out = client
            .migrate_vpc_vni(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;
        Ok(out)
    })
    .await
}

pub async fn trigger_dpu_reprovisioning(
    id: String,
    set: bool,
    update_firmware: bool,
    api_config: &ApiConfig<'_>,
) -> CarbideCliResult<()> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::DpuReprovisioningRequest {
            dpu_id: Some(rpc::MachineId { id }),
            mode: if set { Mode::Set } else { Mode::Clear } as i32,
            initiator: ::rpc::forge::UpdateInitiator::AdminCli as i32,
            update_firmware,
        });
        client
            .trigger_dpu_reprovisioning(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;

        Ok(())
    })
    .await?;

    Ok(())
}

pub async fn list_dpu_pending_for_reprovisioning(
    api_config: &ApiConfig<'_>,
) -> CarbideCliResult<rpc::DpuReprovisioningListResponse> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::DpuReprovisioningListRequest {});
        let data = client
            .list_dpu_waiting_for_reprovisioning(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;

        Ok(data)
    })
    .await
}

pub async fn get_boot_override(
    api_config: &ApiConfig<'_>,
    machine_interface_id: Uuid,
) -> CarbideCliResult<MachineBootOverride> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(machine_interface_id);

        client
            .get_machine_boot_override(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)
    })
    .await
}

pub async fn set_boot_override(
    api_config: &ApiConfig<'_>,
    machine_interface_id: Uuid,
    custom_pxe_path: Option<&Path>,
    custom_user_data_path: Option<&Path>,
) -> CarbideCliResult<()> {
    let custom_pxe = match custom_pxe_path {
        Some(custom_pxe_path) => Some(std::fs::read_to_string(custom_pxe_path)?),
        None => None,
    };

    let custom_user_data = match custom_user_data_path {
        Some(custom_user_data_path) => Some(std::fs::read_to_string(custom_user_data_path)?),
        None => None,
    };

    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(MachineBootOverride {
            machine_interface_id: Some(machine_interface_id),
            custom_pxe,
            custom_user_data,
        });

        client
            .set_machine_boot_override(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)
    })
    .await
}

pub async fn clear_boot_override(
    api_config: &ApiConfig<'_>,
    machine_interface_id: Uuid,
) -> CarbideCliResult<()> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(machine_interface_id);

        client
            .clear_machine_boot_override(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)
    })
    .await
}

pub async fn bmc_reset(
    api_config: &ApiConfig<'_>,
    ip: String,
    port: Option<u32>,
    auth: ResetAuth,
) -> CarbideCliResult<rpc::AdminBmcResetResponse> {
    with_forge_client(api_config, |mut client| async move {
        let (user, password, machine_id) = match auth {
            ResetAuth::Direct { user, password } => (Some(user), Some(password), None),
            ResetAuth::Indirect { machine_id } => (None, None, Some(machine_id)),
        };
        let request = tonic::Request::new(rpc::AdminBmcResetRequest {
            ip,
            port,
            user,
            password,
            machine_id,
        });
        let out = client
            .admin_bmc_reset(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;
        Ok(out)
    })
    .await
}

pub async fn dpu_agent_upgrade_policy_action(
    api_config: &ApiConfig<'_>,
    new_policy: Option<rpc::AgentUpgradePolicy>,
) -> CarbideCliResult<rpc::DpuAgentUpgradePolicyResponse> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::DpuAgentUpgradePolicyRequest {
            new_policy: new_policy.map(|p| p as i32),
        });
        client
            .dpu_agent_upgrade_policy_action(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)
    })
    .await
}

pub async fn add_credential(
    api_config: &ApiConfig<'_>,
    req: rpc::CredentialCreationRequest,
) -> CarbideCliResult<rpc::CredentialCreationResult> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(req);

        client
            .create_credential(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)
    })
    .await
}

pub async fn delete_credential(
    api_config: &ApiConfig<'_>,
    req: rpc::CredentialDeletionRequest,
) -> CarbideCliResult<rpc::CredentialDeletionResult> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(req);

        client
            .delete_credential(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)
    })
    .await
}

pub async fn get_route_servers(api_config: &ApiConfig<'_>) -> CarbideCliResult<Vec<IpAddr>> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(());
        let route_servers = client
            .get_route_servers(request)
            .await
            .map(|response: tonic::Response<rpc::RouteServers>| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;
        route_servers
            .route_servers
            .iter()
            .map(|rs| {
                IpAddr::from_str(rs).map_err(|e| CarbideCliError::GenericError(e.to_string()))
            })
            .collect()
    })
    .await
}

pub async fn add_route_server(
    api_config: &ApiConfig<'_>,
    addr: std::net::Ipv4Addr,
) -> CarbideCliResult<()> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::RouteServers {
            route_servers: vec![addr.to_string()],
        });
        client
            .add_route_servers(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)?;
        Ok(())
    })
    .await?;

    Ok(())
}

pub async fn remove_route_server(
    api_config: &ApiConfig<'_>,
    addr: std::net::Ipv4Addr,
) -> CarbideCliResult<()> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::RouteServers {
            route_servers: vec![addr.to_string()],
        });
        client
            .remove_route_servers(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)?;
        Ok(())
    })
    .await?;

    Ok(())
}
pub async fn get_all_machines_interfaces(
    api_config: &ApiConfig<'_>,
    id: Option<Uuid>,
) -> CarbideCliResult<rpc::InterfaceList> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::InterfaceSearchQuery { id, ip: None });
        let machine_interfaces = client
            .find_interfaces(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;

        Ok(machine_interfaces)
    })
    .await
}

pub async fn get_site_exploration_report(
    api_config: &ApiConfig<'_>,
) -> CarbideCliResult<::rpc::site_explorer::SiteExplorationReport> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::GetSiteExplorationRequest {});
        Ok(client
            .get_site_exploration_report(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)?
            .into_inner())
    })
    .await
}

pub async fn find_machine_ids(
    api_config: &ApiConfig<'_>,
    machine_type: Option<MachineType>,
    only_maintenance: bool,
) -> CarbideCliResult<rpc::MachineIdList> {
    with_forge_client(api_config, |mut client| async move {
        let include_dpus = machine_type.map(|t| t == MachineType::Dpu).unwrap_or(true);
        let exclude_hosts = machine_type
            .map(|t| t != MachineType::Host)
            .unwrap_or(false);
        let include_predicted_host = machine_type.map(|t| t == MachineType::Host).unwrap_or(true);

        let request = tonic::Request::new(MachineSearchConfig {
            include_dpus,
            include_history: false,
            include_predicted_host,
            only_maintenance,
            include_associated_machine_id: false,
            exclude_hosts,
        });
        let machine_ids = client
            .find_machine_ids(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;
        Ok(machine_ids)
    })
    .await
}

pub async fn get_machines_by_ids(
    api_config: &ApiConfig<'_>,
    machine_ids: &[rpc::MachineId],
) -> CarbideCliResult<rpc::MachineList> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::MachineIdList {
            machine_ids: Vec::from(machine_ids),
        });
        let machine_details = client
            .find_machines_by_ids(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;

        Ok(machine_details)
    })
    .await
}
