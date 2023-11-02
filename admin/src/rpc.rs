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
use ::rpc::forge::{self as rpc, MachineBootOverride, MachineType, NetworkSegmentSearchConfig};
use ::rpc::forge_tls_client::{self, ForgeClientT};
use ::rpc::{MachineId, Uuid};

use super::{CarbideCliError, CarbideCliResult};
use crate::cfg::carbide_options::ForceDeleteMachineQuery;
use crate::Config;
pub async fn with_forge_client<T, F>(
    api_config: Config,
    callback: impl FnOnce(ForgeClientT) -> F,
) -> CarbideCliResult<T>
where
    F: Future<Output = CarbideCliResult<T>>,
{
    let client = forge_tls_client::ForgeTlsClient::new(api_config.forge_tls_config)
        .connect(api_config.carbide_api_url)
        .await
        .map_err(|err| CarbideCliError::ApiConnectFailed(err.to_string()))?;

    callback(client).await
}

pub async fn get_machine(id: String, api_config: Config) -> CarbideCliResult<rpc::Machine> {
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
    api_config: Config,
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

pub async fn get_host_machine(id: String, api_config: Config) -> CarbideCliResult<rpc::Machine> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::MachineSearchQuery {
            id: Some(rpc::MachineId { id: id.clone() }),
            fqdn: None,
            search_config: Some(rpc::MachineSearchConfig {
                include_predicted_host: true,
                ..Default::default()
            }),
        });

        let machine_details = client
            .find_machines(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;

        machine_details
            .machines
            .first()
            .ok_or(CarbideCliError::MachineNotFound(rpc::MachineId { id }))
            .cloned()
    })
    .await
}

pub async fn get_dpu_machine(id: String, api_config: Config) -> CarbideCliResult<rpc::Machine> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::MachineSearchQuery {
            id: Some(rpc::MachineId { id: id.clone() }),
            fqdn: None,
            search_config: Some(rpc::MachineSearchConfig {
                include_dpus: true,
                ..Default::default()
            }),
        });

        let machine_details = client
            .find_machines(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;

        let machine = machine_details
            .machines
            .into_iter()
            .next()
            .ok_or(CarbideCliError::MachineNotFound(rpc::MachineId { id }))?;

        if machine.machine_type() == MachineType::Dpu {
            Ok(machine)
        } else {
            Err(CarbideCliError::UnexpectedMachineType(
                rpc::MachineType::Dpu,
                machine.machine_type(),
            ))
        }
    })
    .await
}

pub async fn get_all_machines(
    api_config: Config,
    only_maintenance: bool,
) -> CarbideCliResult<rpc::MachineList> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::MachineSearchQuery {
            id: None,
            fqdn: None,
            search_config: Some(rpc::MachineSearchConfig {
                include_dpus: true,
                include_history: true,
                include_predicted_host: true,
                only_maintenance,
            }),
        });
        let machine_details = client
            .find_machines(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;

        Ok(machine_details)
    })
    .await
}

pub async fn reboot_instance(
    api_config: Config,
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

pub async fn release_instance(api_config: Config, instance_id: rpc::Uuid) -> CarbideCliResult<()> {
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
    api_config: Config,
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
    api_config: Config,
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
    api_config: Config,
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
    api_config: Config,
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
    api_config: Config,
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
    api_config: Config,
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
    api_config: Config,
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
    api_config: Config,
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
    api_config: Config,
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
    api_config: Config,
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
    api_config: Config,
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

pub async fn version(api_config: &Config) -> CarbideCliResult<rpc::BuildInfo> {
    with_forge_client(api_config.clone(), |mut client| async move {
        let out = client
            .version(tonic::Request::new(()))
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;
        Ok(out)
    })
    .await
}

pub async fn set_maintenance(
    req: rpc::MaintenanceRequest,
    api_config: Config,
) -> CarbideCliResult<()> {
    with_forge_client(api_config.clone(), |mut client| async move {
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
    api_config: Config,
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

pub async fn migrate_vpc_vni(api_config: &Config) -> CarbideCliResult<rpc::MigrateVpcVniResponse> {
    with_forge_client(api_config.clone(), |mut client| async move {
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
    api_config: Config,
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
    api_config: Config,
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
    api_config: &Config,
    machine_interface_id: Uuid,
) -> CarbideCliResult<MachineBootOverride> {
    with_forge_client(api_config.clone(), |mut client| async move {
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
    api_config: &Config,
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

    with_forge_client(api_config.clone(), |mut client| async move {
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
    api_config: &Config,
    machine_interface_id: Uuid,
) -> CarbideCliResult<()> {
    with_forge_client(api_config.clone(), |mut client| async move {
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
    api_config: Config,
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
    api_config: &Config,
    new_policy: Option<rpc::AgentUpgradePolicy>,
) -> CarbideCliResult<rpc::DpuAgentUpgradePolicyResponse> {
    with_forge_client(api_config.clone(), |mut client| async move {
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
    api_config: &Config,
    req: rpc::CredentialCreationRequest,
) -> CarbideCliResult<rpc::CredentialCreationResult> {
    with_forge_client(api_config.clone(), |mut client| async move {
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
    api_config: &Config,
    req: rpc::CredentialDeletionRequest,
) -> CarbideCliResult<rpc::CredentialDeletionResult> {
    with_forge_client(api_config.clone(), |mut client| async move {
        let request = tonic::Request::new(req);

        client
            .delete_credential(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)
    })
    .await
}

pub async fn get_route_servers(api_config: &Config) -> CarbideCliResult<Vec<IpAddr>> {
    with_forge_client(api_config.clone(), |mut client| async move {
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
    api_config: &Config,
    addr: std::net::Ipv4Addr,
) -> CarbideCliResult<()> {
    with_forge_client(api_config.clone(), |mut client| async move {
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
    api_config: &Config,
    addr: std::net::Ipv4Addr,
) -> CarbideCliResult<()> {
    with_forge_client(api_config.clone(), |mut client| async move {
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
    api_config: Config,
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
