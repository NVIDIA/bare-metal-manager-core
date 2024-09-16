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

use ::rpc::forge::{
    self as rpc, BmcEndpointRequest, MachineBootOverride, MachineSearchConfig, MachineType,
    NetworkDeviceIdList, NetworkSegmentSearchConfig, VpcVirtualizationType,
};
use ::rpc::forge_tls_client::{self, ApiConfig, ForgeClientT};
use mac_address::MacAddress;

use crate::cfg::carbide_options::{self, ForceDeleteMachineQuery, MachineAutoupdate, MachineQuery};
use utils::admin_cli::{CarbideCliError, CarbideCliResult};

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
        let request = tonic::Request::new(::rpc::common::MachineId { id });
        let mut machine_details = client
            .get_machine(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;

        // Note: The field going forward is `associated_dpu_machine_ids`, but if we're talking to
        // an older version of the API which doesn't support it, fall back on building our own Vec
        // out of the `associated_dpu_machine_id` field.
        if machine_details.associated_dpu_machine_ids.is_empty() {
            if let Some(ref dpu_id) = machine_details.associated_dpu_machine_id {
                machine_details.associated_dpu_machine_ids = vec![dpu_id.clone()];
            }
        }

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
async fn get_all_machines_deprecated(
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
    page_size: usize,
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

    for machine_ids in all_machine_ids.machine_ids.chunks(page_size) {
        let machines = get_machines_by_ids(api_config, machine_ids).await?;
        all_machines.machines.extend(machines.machines);
    }

    Ok(all_machines)
}

pub async fn reboot_instance(
    api_config: &ApiConfig<'_>,
    machine_id: ::rpc::common::MachineId,
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

pub async fn release_instances(
    api_config: &ApiConfig<'_>,
    instance_ids: Vec<::rpc::common::Uuid>,
) -> CarbideCliResult<()> {
    with_forge_client(api_config, |mut client| async move {
        for instance_id in instance_ids {
            let request = tonic::Request::new(rpc::InstanceReleaseRequest {
                id: Some(instance_id),
            });
            client
                .release_instance(request)
                .await
                .map(|response| response.into_inner())
                .map_err(CarbideCliError::ApiInvocationError)?;
        }
        Ok(())
    })
    .await
}

// TODO: remove when all sites updated to carbide-api with find_instance_ids and find_instances_by_ids implemented
async fn get_instances_deprecated(
    api_config: &ApiConfig<'_>,
    id: Option<String>,
    label_key: Option<String>,
    label_value: Option<String>,
) -> CarbideCliResult<rpc::InstanceList> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::InstanceSearchQuery {
            id: id.map(|x| ::rpc::common::Uuid { value: x }),
            label: if label_key.is_none() && label_value.is_none() {
                None
            } else {
                Some(rpc::Label {
                    key: label_key.unwrap_or_default().to_string(),
                    value: label_value,
                })
            },
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

pub async fn identify_uuid(
    api_config: &ApiConfig<'_>,
    u: uuid::Uuid,
) -> CarbideCliResult<rpc::UuidType> {
    let req = rpc::IdentifyUuidRequest {
        uuid: Some(u.into()),
    };

    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(req);
        let uuid_details = match client
            .identify_uuid(request)
            .await
            .map(|response| response.into_inner())
        {
            Ok(m) => m,
            Err(status) if status.code() == tonic::Code::NotFound => {
                return Err(CarbideCliError::UuidNotFound);
            }
            Err(err) => {
                tracing::error!(%err, "identify_uuid error calling grpc identify_uuid");
                return Err(CarbideCliError::GenericError(err.to_string()));
            }
        };
        let object_type = match rpc::UuidType::try_from(uuid_details.object_type) {
            Ok(ot) => ot,
            Err(e) => {
                tracing::error!(
                    "Invalid UuidType from carbide api: {}",
                    uuid_details.object_type
                );
                return Err(CarbideCliError::GenericError(e.to_string()));
            }
        };

        Ok(object_type)
    })
    .await
}

pub async fn identify_mac(
    api_config: &ApiConfig<'_>,
    mac_address: MacAddress,
) -> CarbideCliResult<(rpc::MacOwner, String)> {
    let req = rpc::IdentifyMacRequest {
        mac_address: mac_address.to_string(),
    };

    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(req);
        let mac_details = match client
            .identify_mac(request)
            .await
            .map(|response| response.into_inner())
        {
            Ok(m) => m,
            Err(status) if status.code() == tonic::Code::NotFound => {
                return Err(CarbideCliError::MacAddressNotFound);
            }
            Err(err) => {
                tracing::error!(%err, "identify_mac error calling grpc identify_mac");
                return Err(CarbideCliError::GenericError(err.to_string()));
            }
        };
        let object_type = match rpc::MacOwner::try_from(mac_details.object_type) {
            Ok(ot) => ot,
            Err(e) => {
                tracing::error!(
                    "Invalid MachineOwner from carbide api: {}",
                    mac_details.object_type
                );
                return Err(CarbideCliError::GenericError(e.to_string()));
            }
        };

        Ok((object_type, mac_details.primary_key))
    })
    .await
}

pub async fn identify_serial(
    api_config: &ApiConfig<'_>,
    serial_number: String,
) -> CarbideCliResult<::rpc::common::MachineId> {
    let req = rpc::IdentifySerialRequest { serial_number };

    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(req);
        let serial_details = match client
            .identify_serial(request)
            .await
            .map(|response| response.into_inner())
        {
            Ok(m) => m,
            Err(status) if status.code() == tonic::Code::NotFound => {
                return Err(CarbideCliError::SerialNumberNotFound);
            }
            Err(err) => {
                tracing::error!(%err, "identify_serial error calling grpc identify_serial");
                return Err(CarbideCliError::GenericError(err.to_string()));
            }
        };

        serial_details
            .machine_id
            .ok_or(CarbideCliError::GenericError(
                "Serial number found without associated machine ID".to_string(),
            ))
    })
    .await
}

pub async fn get_all_instances(
    api_config: &ApiConfig<'_>,
    tenant_org_id: Option<String>,
    vpc_id: Option<String>,
    label_key: Option<String>,
    label_value: Option<String>,
    page_size: usize,
) -> CarbideCliResult<rpc::InstanceList> {
    let all_ids = match get_instance_ids(
        api_config,
        tenant_org_id.clone(),
        vpc_id.clone(),
        label_key.clone(),
        label_value.clone(),
    )
    .await
    {
        Ok(all_ids) => all_ids,
        Err(CarbideCliError::ApiInvocationError(status))
            if status.code() == tonic::Code::Unimplemented =>
        {
            if tenant_org_id.is_some() {
                return Err(CarbideCliError::GenericError(
                    "Filtering by Tenant Org or VPC ID is not supported for this site.\
                        \nIt does not have a required version of the Carbide API."
                        .to_string(),
                ));
            }
            return get_instances_deprecated(api_config, None, label_key, label_value).await;
        }
        Err(e) => return Err(e),
    };
    let mut all_list = rpc::InstanceList {
        instances: Vec::with_capacity(all_ids.instance_ids.len()),
    };

    for ids in all_ids.instance_ids.chunks(page_size) {
        let list = get_instances_by_ids(api_config, ids).await?;
        all_list.instances.extend(list.instances);
    }

    Ok(all_list)
}

pub async fn get_one_instance(
    api_config: &ApiConfig<'_>,
    instance_id: ::rpc::common::Uuid,
) -> CarbideCliResult<rpc::InstanceList> {
    let instances = match get_instances_by_ids(api_config, &[instance_id.clone()]).await {
        Ok(instances) => instances,
        Err(CarbideCliError::ApiInvocationError(status))
            if status.code() == tonic::Code::Unimplemented =>
        {
            return get_instances_deprecated(api_config, Some(instance_id.value), None, None).await;
        }
        Err(e) => return Err(e),
    };

    Ok(instances)
}

async fn get_instance_ids(
    api_config: &ApiConfig<'_>,
    tenant_org_id: Option<String>,
    vpc_id: Option<String>,
    label_key: Option<String>,
    label_value: Option<String>,
) -> CarbideCliResult<rpc::InstanceIdList> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::InstanceSearchFilter {
            tenant_org_id,
            vpc_id,
            label: if label_key.is_none() && label_value.is_none() {
                None
            } else {
                Some(rpc::Label {
                    key: label_key.unwrap_or_default().to_string(),
                    value: label_value,
                })
            },
        });
        let instance_ids = client
            .find_instance_ids(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;
        Ok(instance_ids)
    })
    .await
}

async fn get_instances_by_ids(
    api_config: &ApiConfig<'_>,
    instance_ids: &[::rpc::common::Uuid],
) -> CarbideCliResult<rpc::InstanceList> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::InstancesByIdsRequest {
            instance_ids: Vec::from(instance_ids),
        });
        let instances = client
            .find_instances_by_ids(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;

        Ok(instances)
    })
    .await
}

pub async fn get_instances_by_machine_id(
    api_config: &ApiConfig<'_>,
    id: String,
) -> CarbideCliResult<rpc::InstanceList> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(::rpc::common::MachineId { id });
        let instance_details = client
            .find_instance_by_machine_id(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;

        Ok(instance_details)
    })
    .await
}

pub async fn get_all_segments(
    api_config: &ApiConfig<'_>,
    tenant_org_id: Option<String>,
    name: Option<String>,
    page_size: usize,
) -> CarbideCliResult<rpc::NetworkSegmentList> {
    let all_ids = match get_segment_ids(api_config, tenant_org_id.clone(), name.clone()).await {
        Ok(all_ids) => all_ids,
        Err(CarbideCliError::ApiInvocationError(status))
            if status.code() == tonic::Code::Unimplemented =>
        {
            if tenant_org_id.is_some() || name.is_some() {
                return Err(CarbideCliError::GenericError(
                    "Filtering by Tenant Org ID or Name is not supported for this site.\
                \nIt does not have a required version of the Carbide API."
                        .to_string(),
                ));
            }
            return get_segments_deprecated(None, api_config).await;
        }
        Err(e) => return Err(e),
    };
    let mut all_list = rpc::NetworkSegmentList {
        network_segments: Vec::with_capacity(all_ids.network_segments_ids.len()),
    };

    for ids in all_ids.network_segments_ids.chunks(page_size) {
        let list = get_segments_by_ids(api_config, ids).await?;
        all_list.network_segments.extend(list.network_segments);
    }

    Ok(all_list)
}

pub async fn get_one_segment(
    api_config: &ApiConfig<'_>,
    segment_id: ::rpc::common::Uuid,
) -> CarbideCliResult<rpc::NetworkSegmentList> {
    let segments = match get_segments_by_ids(api_config, &[segment_id.clone()]).await {
        Ok(segments) => segments,
        Err(CarbideCliError::ApiInvocationError(status))
            if status.code() == tonic::Code::Unimplemented =>
        {
            return get_segments_deprecated(Some(segment_id), api_config).await;
        }
        Err(e) => return Err(e),
    };

    Ok(segments)
}

async fn get_segment_ids(
    api_config: &ApiConfig<'_>,
    tenant_org_id: Option<String>,
    name: Option<String>,
) -> CarbideCliResult<rpc::NetworkSegmentIdList> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::NetworkSegmentSearchFilter {
            tenant_org_id,
            name,
        });
        let segment_ids = client
            .find_network_segment_ids(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;
        Ok(segment_ids)
    })
    .await
}

async fn get_segments_by_ids(
    api_config: &ApiConfig<'_>,
    segment_ids: &[::rpc::common::Uuid],
) -> CarbideCliResult<rpc::NetworkSegmentList> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::NetworkSegmentsByIdsRequest {
            network_segments_ids: Vec::from(segment_ids),
            include_history: segment_ids.len() == 1, // only request it when getting data for single resource
            include_num_free_ips: true,
        });
        let segments = client
            .find_network_segments_by_ids(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;

        Ok(segments)
    })
    .await
}

// TODO: remove when all sites updated to carbide-api with find_network_segment_ids and find_network_segments_by_ids implemented
async fn get_segments_deprecated(
    id: Option<::rpc::common::Uuid>,
    api_config: &ApiConfig<'_>,
) -> CarbideCliResult<rpc::NetworkSegmentList> {
    with_forge_client(api_config, |mut client| async move {
        // Return the number of free ips only when client is asking for segment info
        // of a specific segment id.
        let ret_free_ips = id.is_some();

        let request = tonic::Request::new(rpc::NetworkSegmentQuery {
            id,
            search_config: Some(NetworkSegmentSearchConfig {
                include_history: true,
                include_num_free_ips: ret_free_ips,
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
    id: Option<::rpc::common::Uuid>,
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
            dpu_machine_id: Some(::rpc::common::MachineId { id }),
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
pub async fn machine_list_health_report_overrides(
    id: String,
    api_config: &ApiConfig<'_>,
) -> CarbideCliResult<rpc::ListHealthReportOverrideResponse> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(::rpc::MachineId { id });
        let result = client
            .list_health_report_overrides(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;

        Ok(result)
    })
    .await
}

pub async fn machine_insert_health_report_override(
    id: String,
    report: ::rpc::health::HealthReport,
    r#override: bool,
    api_config: &ApiConfig<'_>,
) -> CarbideCliResult<()> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(::rpc::forge::InsertHealthReportOverrideRequest {
            machine_id: Some(::rpc::MachineId { id }),
            r#override: Some(rpc::HealthReportOverride {
                report: Some(report),
                mode: if r#override {
                    rpc::OverrideMode::Override
                } else {
                    rpc::OverrideMode::Merge
                } as i32,
            }),
        });
        client
            .insert_health_report_override(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;

        Ok(())
    })
    .await
}

pub async fn machine_remove_health_report_override(
    id: String,
    source: String,
    api_config: &ApiConfig<'_>,
) -> CarbideCliResult<()> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(::rpc::forge::RemoveHealthReportOverrideRequest {
            machine_id: Some(::rpc::MachineId { id }),
            source,
        });
        client
            .remove_health_report_override(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;

        Ok(())
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
            delete_interfaces: query.delete_interfaces,
            delete_bmc_interfaces: query.delete_bmc_interfaces,
            delete_bmc_credentials: query.delete_bmc_credentials,
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

pub async fn set_host_uefi_password(
    query: MachineQuery,
    api_config: &ApiConfig<'_>,
) -> CarbideCliResult<::rpc::forge::SetHostUefiPasswordResponse> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::SetHostUefiPasswordRequest {
            host_id: Some(::rpc::common::MachineId { id: query.query }),
        });
        let response = client
            .set_host_uefi_password(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;

        Ok(response)
    })
    .await
}

pub async fn clear_host_uefi_password(
    query: MachineQuery,
    api_config: &ApiConfig<'_>,
) -> CarbideCliResult<::rpc::forge::ClearHostUefiPasswordResponse> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::ClearHostUefiPasswordRequest {
            host_id: Some(::rpc::common::MachineId { id: query.query }),
        });
        let response = client
            .clear_host_uefi_password(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;

        Ok(response)
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

pub async fn trigger_dpu_reprovisioning(
    id: String,
    mode: ::rpc::forge::dpu_reprovisioning_request::Mode,
    update_firmware: bool,
    api_config: &ApiConfig<'_>,
) -> CarbideCliResult<()> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::DpuReprovisioningRequest {
            dpu_id: Some(::rpc::common::MachineId { id: id.clone() }),
            machine_id: Some(::rpc::common::MachineId { id }),
            mode: mode as i32,
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
    machine_interface_id: ::rpc::common::Uuid,
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
    machine_interface_id: ::rpc::common::Uuid,
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
    machine_interface_id: ::rpc::common::Uuid,
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
    bmc_endpoint_request: Option<BmcEndpointRequest>,
    machine_id: Option<String>,
    use_ipmitool: bool,
) -> CarbideCliResult<rpc::AdminBmcResetResponse> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::AdminBmcResetRequest {
            bmc_endpoint_request,
            machine_id,
            use_ipmitool,
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

pub async fn admin_power_control(
    api_config: &ApiConfig<'_>,
    bmc_endpoint_request: Option<BmcEndpointRequest>,
    machine_id: Option<String>,
    action: ::rpc::forge::admin_power_control_request::SystemPowerControl,
) -> CarbideCliResult<rpc::AdminPowerControlResponse> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::AdminPowerControlRequest {
            bmc_endpoint_request,
            machine_id,
            action: action.into(),
        });
        let out = client
            .admin_power_control(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;
        Ok(out)
    })
    .await
}

pub async fn identify_bmc(
    api_config: &ApiConfig<'_>,
    address: String,
) -> CarbideCliResult<rpc::IdentifyBmcResponse> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::IdentifyBmcRequest { address });
        let out = client
            .identify_bmc(request)
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
    id: Option<::rpc::common::Uuid>,
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

pub async fn delete_machine_interface(
    api_config: &ApiConfig<'_>,
    id: Option<::rpc::common::Uuid>,
) -> CarbideCliResult<()> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::InterfaceDeleteQuery { id });
        client
            .delete_interface(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;

        Ok(())
    })
    .await
}

// DEPRECATED: use get_site_exploration_report
async fn get_site_exploration_report_deprecated(
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

pub async fn get_site_exploration_report(
    api_config: &ApiConfig<'_>,
    page_size: usize,
) -> CarbideCliResult<::rpc::site_explorer::SiteExplorationReport> {
    // grab endpoints
    let endpoint_ids = match get_explored_endpoint_ids(api_config).await {
        Ok(endpoint_ids) => endpoint_ids,
        Err(CarbideCliError::ApiInvocationError(status))
            if status.code() == tonic::Code::Unimplemented =>
        {
            return get_site_exploration_report_deprecated(api_config).await;
        }
        Err(e) => return Err(e),
    };
    let mut all_endpoints = ::rpc::site_explorer::ExploredEndpointList {
        endpoints: Vec::with_capacity(endpoint_ids.endpoint_ids.len()),
    };
    for ids in endpoint_ids.endpoint_ids.chunks(page_size) {
        let list = get_explored_endpoints_by_ids(api_config, ids).await?;
        all_endpoints.endpoints.extend(list.endpoints);
    }

    // grab managed hosts
    let all_hosts = match get_all_explored_managed_hosts(api_config, page_size).await {
        Ok(all_hosts) => all_hosts,
        Err(e) => return Err(e),
    };

    Ok(::rpc::site_explorer::SiteExplorationReport {
        endpoints: all_endpoints.endpoints,
        managed_hosts: all_hosts,
    })
}

async fn get_explored_endpoint_ids(
    api_config: &ApiConfig<'_>,
) -> CarbideCliResult<::rpc::site_explorer::ExploredEndpointIdList> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(::rpc::site_explorer::ExploredEndpointSearchFilter {});
        let endpoint_ids = client
            .find_explored_endpoint_ids(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;
        Ok(endpoint_ids)
    })
    .await
}

pub async fn get_explored_endpoints_by_ids(
    api_config: &ApiConfig<'_>,
    endpoint_ids: &[String],
) -> CarbideCliResult<::rpc::site_explorer::ExploredEndpointList> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(::rpc::site_explorer::ExploredEndpointsByIdsRequest {
            endpoint_ids: Vec::from(endpoint_ids),
        });
        let endpoints = client
            .find_explored_endpoints_by_ids(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;
        Ok(endpoints)
    })
    .await
}

#[allow(dead_code)]
pub async fn get_all_explored_managed_hosts(
    api_config: &ApiConfig<'_>,
    page_size: usize,
) -> CarbideCliResult<Vec<::rpc::site_explorer::ExploredManagedHost>> {
    let host_ids = match get_explored_managed_host_ids(api_config).await {
        Ok(host_ids) => host_ids,
        Err(CarbideCliError::ApiInvocationError(status))
            if status.code() == tonic::Code::Unimplemented =>
        {
            let hosts = get_site_exploration_report_deprecated(api_config)
                .await?
                .managed_hosts;
            return Ok(hosts);
        }
        Err(e) => return Err(e),
    };
    let mut all_hosts = ::rpc::site_explorer::ExploredManagedHostList {
        managed_hosts: Vec::with_capacity(host_ids.host_ids.len()),
    };
    for ids in host_ids.host_ids.chunks(page_size) {
        let list = get_explored_managed_host_by_ids(api_config, ids).await?;
        all_hosts.managed_hosts.extend(list.managed_hosts);
    }
    Ok(all_hosts.managed_hosts)
}

#[allow(dead_code)]
async fn get_explored_managed_host_ids(
    api_config: &ApiConfig<'_>,
) -> CarbideCliResult<::rpc::site_explorer::ExploredManagedHostIdList> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(::rpc::site_explorer::ExploredManagedHostSearchFilter {});
        let host_ids = client
            .find_explored_managed_host_ids(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;
        Ok(host_ids)
    })
    .await
}

#[allow(dead_code)]
pub async fn get_explored_managed_host_by_ids(
    api_config: &ApiConfig<'_>,
    host_ids: &[String],
) -> CarbideCliResult<::rpc::site_explorer::ExploredManagedHostList> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(::rpc::site_explorer::ExploredManagedHostsByIdsRequest {
            host_ids: Vec::from(host_ids),
        });
        let hosts = client
            .find_explored_managed_hosts_by_ids(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;
        Ok(hosts)
    })
    .await
}

pub async fn explore(
    api_config: &ApiConfig<'_>,
    address: &str,
    mac_address: Option<MacAddress>,
) -> CarbideCliResult<::rpc::site_explorer::EndpointExplorationReport> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::BmcEndpointRequest {
            ip_address: address.to_string(),
            mac_address: mac_address.map(|mac| mac.to_string()),
        });
        Ok(client
            .explore(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)?
            .into_inner())
    })
    .await
}

pub async fn re_explore_endpoint(
    api_config: &ApiConfig<'_>,
    address: &str,
) -> CarbideCliResult<()> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::ReExploreEndpointRequest {
            ip_address: address.to_string(),
            if_version_match: None,
        });
        client
            .re_explore_endpoint(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)?
            .into_inner();
        Ok(())
    })
    .await
}

pub async fn clear_site_explorer_last_known_error(
    api_config: &ApiConfig<'_>,
    ip_address: String,
) -> CarbideCliResult<()> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::ClearSiteExplorationErrorRequest { ip_address });
        client
            .clear_site_exploration_error(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)?
            .into_inner();
        Ok(())
    })
    .await
}

pub async fn is_bmc_in_managed_host(
    api_config: &ApiConfig<'_>,
    address: &str,
    mac_address: Option<MacAddress>,
) -> CarbideCliResult<()> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::BmcEndpointRequest {
            ip_address: address.to_string(),
            mac_address: mac_address.map(|mac| mac.to_string()),
        });
        client
            .is_bmc_in_managed_host(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)?
            .into_inner();
        Ok(())
    })
    .await
}

pub async fn find_machine_ids(
    api_config: &ApiConfig<'_>,
    machine_type: Option<MachineType>,
    only_maintenance: bool,
) -> CarbideCliResult<::rpc::common::MachineIdList> {
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
    machine_ids: &[::rpc::common::MachineId],
) -> CarbideCliResult<rpc::MachineList> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(::rpc::forge::MachinesByIdsRequest {
            machine_ids: Vec::from(machine_ids),
            ..Default::default()
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

pub async fn get_machines_ids_by_bmc_ips(
    api_config: &ApiConfig<'_>,
    bmc_ips: &[String],
) -> CarbideCliResult<rpc::MachineIdBmcIpPairs> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(::rpc::forge::BmcIpList {
            bmc_ips: Vec::from(bmc_ips),
        });
        let machine_details = client
            .find_machine_ids_by_bmc_ips(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;

        Ok(machine_details)
    })
    .await
}

pub async fn set_dynamic_config(
    api_config: &ApiConfig<'_>,
    feature: rpc::ConfigSetting,
    value: String,
    expiry: Option<String>,
) -> CarbideCliResult<()> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::SetDynamicConfigRequest {
            setting: feature.into(),
            value,
            expiry,
        });
        client
            .set_dynamic_config(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)?;
        Ok(())
    })
    .await
}

pub async fn find_connected_devices_by_dpu_machine_ids(
    api_config: &ApiConfig<'_>,
    machine_ids: Vec<::rpc::common::MachineId>,
) -> CarbideCliResult<rpc::ConnectedDeviceList> {
    with_forge_client(api_config, |mut client| async move {
        let machine_id_list = ::rpc::common::MachineIdList { machine_ids };
        client
            .find_connected_devices_by_dpu_machine_ids(machine_id_list)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)
    })
    .await
}

pub async fn find_network_devices_by_device_ids(
    api_config: &ApiConfig<'_>,
    device_ids: Vec<String>,
) -> CarbideCliResult<rpc::NetworkTopologyData> {
    with_forge_client(api_config, |mut client| async move {
        let network_device_id_list = NetworkDeviceIdList {
            network_device_ids: device_ids.to_vec(),
        };
        client
            .find_network_devices_by_device_ids(network_device_id_list)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)
    })
    .await
}

pub async fn get_all_expected_machines(
    api_config: &ApiConfig<'_>,
) -> Result<rpc::ExpectedMachineList, CarbideCliError> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(());

        client
            .get_all_expected_machines(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)
    })
    .await
}

pub async fn get_expected_machine(
    bmc_mac_address: MacAddress,
    api_config: &ApiConfig<'_>,
) -> Result<rpc::ExpectedMachine, CarbideCliError> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::ExpectedMachineRequest {
            bmc_mac_address: bmc_mac_address.to_string(),
        });

        client
            .get_expected_machine(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)
    })
    .await
}

pub async fn delete_expected_machine(
    bmc_mac_address: MacAddress,
    api_config: &ApiConfig<'_>,
) -> Result<(), CarbideCliError> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::ExpectedMachineRequest {
            bmc_mac_address: bmc_mac_address.to_string(),
        });

        client
            .delete_expected_machine(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)
    })
    .await
}

pub async fn add_expected_machine(
    bmc_mac_address: MacAddress,
    bmc_username: String,
    bmc_password: String,
    chassis_serial_number: String,
    fallback_dpu_serial_numbers: Option<Vec<String>>,
    api_config: &ApiConfig<'_>,
) -> Result<(), CarbideCliError> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::ExpectedMachine {
            bmc_mac_address: bmc_mac_address.to_string(),
            bmc_username,
            bmc_password,
            chassis_serial_number,
            fallback_dpu_serial_numbers: fallback_dpu_serial_numbers.unwrap_or_default(),
        });

        client
            .add_expected_machine(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)
    })
    .await
}

pub async fn update_expected_machine(
    bmc_mac_address: MacAddress,
    bmc_username: Option<String>,
    bmc_password: Option<String>,
    chassis_serial_number: Option<String>,
    fallback_dpu_serial_numbers: Option<Vec<String>>,
    api_config: &ApiConfig<'_>,
) -> Result<(), CarbideCliError> {
    let expected_machine = get_expected_machine(bmc_mac_address, api_config).await?;
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::ExpectedMachine {
            bmc_mac_address: bmc_mac_address.to_string(),
            bmc_username: bmc_username.unwrap_or(expected_machine.bmc_username),
            bmc_password: bmc_password.unwrap_or(expected_machine.bmc_password),
            chassis_serial_number: chassis_serial_number
                .unwrap_or(expected_machine.chassis_serial_number),
            fallback_dpu_serial_numbers: fallback_dpu_serial_numbers
                .unwrap_or(expected_machine.fallback_dpu_serial_numbers),
        });

        client
            .update_expected_machine(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)
    })
    .await
}

pub async fn replace_all_expected_machines(
    expected_machine_list: Vec<carbide_options::ExpectedMachine>,
    api_config: &ApiConfig<'_>,
) -> Result<(), CarbideCliError> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::ExpectedMachineList {
            expected_machines: expected_machine_list
                .into_iter()
                .map(|machine| rpc::ExpectedMachine {
                    bmc_mac_address: machine.bmc_mac_address.to_string(),
                    bmc_username: machine.bmc_username,
                    bmc_password: machine.bmc_password,
                    chassis_serial_number: machine.chassis_serial_number,
                    fallback_dpu_serial_numbers: machine
                        .fallback_dpu_serial_numbers
                        .unwrap_or_default(),
                })
                .collect(),
        });

        client
            .replace_all_expected_machines(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)
    })
    .await
}

pub async fn delete_all_expected_machines(
    api_config: &ApiConfig<'_>,
) -> Result<(), CarbideCliError> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(());

        client
            .delete_all_expected_machines(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)
    })
    .await
}

pub async fn get_all_vpcs(
    api_config: &ApiConfig<'_>,
    tenant_org_id: Option<String>,
    name: Option<String>,
    page_size: usize,
    label_key: Option<String>,
    label_value: Option<String>,
) -> CarbideCliResult<rpc::VpcList> {
    let all_ids = match get_vpc_ids(
        api_config,
        tenant_org_id.clone(),
        name.clone(),
        label_key,
        label_value,
    )
    .await
    {
        Ok(all_ids) => all_ids,
        Err(CarbideCliError::ApiInvocationError(status))
            if status.code() == tonic::Code::Unimplemented =>
        {
            if tenant_org_id.is_some() {
                return Err(CarbideCliError::GenericError(
                    "Filtering by Tenant Org ID is not supported for this site.\
                \nIt does not have a required version of the Carbide API."
                        .to_string(),
                ));
            }
            return get_vpcs_deprecated(api_config, None, name).await;
        }
        Err(e) => return Err(e),
    };
    let mut all_list = rpc::VpcList {
        vpcs: Vec::with_capacity(all_ids.vpc_ids.len()),
    };

    for ids in all_ids.vpc_ids.chunks(page_size) {
        let list = get_vpcs_by_ids(api_config, ids).await?;
        all_list.vpcs.extend(list.vpcs);
    }

    Ok(all_list)
}

pub async fn get_one_vpc(
    api_config: &ApiConfig<'_>,
    vpc_id: ::rpc::common::Uuid,
) -> CarbideCliResult<rpc::VpcList> {
    let vpcs = match get_vpcs_by_ids(api_config, &[vpc_id.clone()]).await {
        Ok(vpcs) => vpcs,
        Err(CarbideCliError::ApiInvocationError(status))
            if status.code() == tonic::Code::Unimplemented =>
        {
            return get_vpcs_deprecated(api_config, Some(vpc_id), None).await;
        }
        Err(e) => return Err(e),
    };

    Ok(vpcs)
}

async fn get_vpc_ids(
    api_config: &ApiConfig<'_>,
    tenant_org_id: Option<String>,
    name: Option<String>,
    label_key: Option<String>,
    label_value: Option<String>,
) -> CarbideCliResult<rpc::VpcIdList> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::VpcSearchFilter {
            tenant_org_id,
            name,
            label: if label_key.is_none() && label_value.is_none() {
                None
            } else {
                Some(rpc::Label {
                    key: label_key.unwrap_or_default().to_string(),
                    value: label_value,
                })
            },
        });
        let ids = client
            .find_vpc_ids(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;
        Ok(ids)
    })
    .await
}

async fn get_vpcs_by_ids(
    api_config: &ApiConfig<'_>,
    ids: &[::rpc::common::Uuid],
) -> CarbideCliResult<rpc::VpcList> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::VpcsByIdsRequest {
            vpc_ids: Vec::from(ids),
        });
        let instances = client
            .find_vpcs_by_ids(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;

        Ok(instances)
    })
    .await
}

// TODO: remove when all sites have been upgraded to include find_vpc_ids and find_vpcs_by_ids methods
async fn get_vpcs_deprecated(
    api_config: &ApiConfig<'_>,
    id: Option<::rpc::common::Uuid>,
    name: Option<String>,
) -> CarbideCliResult<rpc::VpcList> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::VpcSearchQuery { id, name });
        let details = client
            .find_vpcs(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;

        Ok(details)
    })
    .await
}

/// set_vpc_network_virtualization_type sends out a `VpcUpdateVirtualizationRequest`
/// to the API, with the purpose of being able to modify the underlying
/// VpcVirtualizationType (or NetworkVirtualizationType) of the VPC. This will
/// return an error if there are configured instances in the VPC (you can only
/// do this with an empty VPC).
pub async fn set_vpc_network_virtualization_type(
    api_config: &ApiConfig<'_>,
    vpc: rpc::Vpc,
    virtualizer: VpcVirtualizationType,
) -> CarbideCliResult<()> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::VpcUpdateVirtualizationRequest {
            id: vpc.id,
            if_version_match: None,
            network_virtualization_type: Some(virtualizer as i32),
        });
        client
            .update_vpc_virtualization(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;

        Ok(())
    })
    .await
}

pub async fn get_all_ib_partitions(
    api_config: &ApiConfig<'_>,
    tenant_org_id: Option<String>,
    name: Option<String>,
    page_size: usize,
) -> CarbideCliResult<rpc::IbPartitionList> {
    let all_ids = match get_ib_partition_ids(api_config, tenant_org_id.clone(), name.clone()).await
    {
        Ok(all_ids) => all_ids,
        Err(CarbideCliError::ApiInvocationError(status))
            if status.code() == tonic::Code::Unimplemented =>
        {
            if tenant_org_id.is_some() || name.is_some() {
                return Err(CarbideCliError::GenericError(
                    "Filtering by Tenant Org ID or Name is not supported for this site.\
                \nIt does not have a required version of the Carbide API."
                        .to_string(),
                ));
            }
            return get_ib_partitions_deprecated(api_config, None).await;
        }
        Err(e) => return Err(e),
    };
    let mut all_list = rpc::IbPartitionList {
        ib_partitions: Vec::with_capacity(all_ids.ib_partition_ids.len()),
    };

    for ids in all_ids.ib_partition_ids.chunks(page_size) {
        let list = get_ib_partitions_by_ids(api_config, ids).await?;
        all_list.ib_partitions.extend(list.ib_partitions);
    }

    Ok(all_list)
}

pub async fn get_one_ib_partition(
    api_config: &ApiConfig<'_>,
    ib_partition_id: ::rpc::common::Uuid,
) -> CarbideCliResult<rpc::IbPartitionList> {
    let partitions = match get_ib_partitions_by_ids(api_config, &[ib_partition_id.clone()]).await {
        Ok(partitions) => partitions,
        Err(CarbideCliError::ApiInvocationError(status))
            if status.code() == tonic::Code::Unimplemented =>
        {
            return get_ib_partitions_deprecated(api_config, Some(ib_partition_id)).await;
        }
        Err(e) => return Err(e),
    };

    Ok(partitions)
}

async fn get_ib_partition_ids(
    api_config: &ApiConfig<'_>,
    tenant_org_id: Option<String>,
    name: Option<String>,
) -> CarbideCliResult<rpc::IbPartitionIdList> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::IbPartitionSearchFilter {
            tenant_org_id,
            name,
        });
        let ids = client
            .find_ib_partition_ids(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;
        Ok(ids)
    })
    .await
}

async fn get_ib_partitions_by_ids(
    api_config: &ApiConfig<'_>,
    ids: &[::rpc::common::Uuid],
) -> CarbideCliResult<rpc::IbPartitionList> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::IbPartitionsByIdsRequest {
            ib_partition_ids: Vec::from(ids),
            include_history: ids.len() == 1,
        });
        let instances = client
            .find_ib_partitions_by_ids(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;

        Ok(instances)
    })
    .await
}

// TODO: remove when all sites have been upgraded to include find_ib_partition_ids and find_ib_partitions_by_ids methods
async fn get_ib_partitions_deprecated(
    api_config: &ApiConfig<'_>,
    id: Option<::rpc::common::Uuid>,
) -> CarbideCliResult<rpc::IbPartitionList> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::IbPartitionQuery {
            id: id.clone(),
            search_config: Some(rpc::IbPartitionSearchConfig {
                include_history: id.is_some(),
            }),
        });
        let details = client
            .find_ib_partitions(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;

        Ok(details)
    })
    .await
}

pub async fn get_all_keysets(
    api_config: &ApiConfig<'_>,
    tenant_org_id: Option<String>,
    page_size: usize,
) -> CarbideCliResult<rpc::TenantKeySetList> {
    let all_ids = match get_keyset_ids(api_config, tenant_org_id.clone()).await {
        Ok(all_ids) => all_ids,
        Err(CarbideCliError::ApiInvocationError(status))
            if status.code() == tonic::Code::Unimplemented =>
        {
            return get_keysets_deprecated(api_config, tenant_org_id, None).await;
        }
        Err(e) => return Err(e),
    };
    let mut all_list = rpc::TenantKeySetList {
        keyset: Vec::with_capacity(all_ids.keyset_ids.len()),
    };

    for ids in all_ids.keyset_ids.chunks(page_size) {
        let list = get_keysets_by_ids(api_config, ids).await?;
        all_list.keyset.extend(list.keyset);
    }

    Ok(all_list)
}

pub async fn get_one_keyset(
    api_config: &ApiConfig<'_>,
    keyset_id: rpc::TenantKeysetIdentifier,
) -> CarbideCliResult<rpc::TenantKeySetList> {
    let keysets = match get_keysets_by_ids(api_config, &[keyset_id.clone()]).await {
        Ok(keysets) => keysets,
        Err(CarbideCliError::ApiInvocationError(status))
            if status.code() == tonic::Code::Unimplemented =>
        {
            return get_keysets_deprecated(api_config, None, Some(keyset_id)).await;
        }
        Err(e) => return Err(e),
    };

    Ok(keysets)
}

async fn get_keyset_ids(
    api_config: &ApiConfig<'_>,
    tenant_org_id: Option<String>,
) -> CarbideCliResult<rpc::TenantKeysetIdList> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::TenantKeysetSearchFilter { tenant_org_id });
        let ids = client
            .find_tenant_keyset_ids(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;
        Ok(ids)
    })
    .await
}

async fn get_keysets_by_ids(
    api_config: &ApiConfig<'_>,
    identifiers: &[rpc::TenantKeysetIdentifier],
) -> CarbideCliResult<rpc::TenantKeySetList> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::TenantKeysetsByIdsRequest {
            keyset_ids: Vec::from(identifiers),
            include_key_data: true,
        });
        let instances = client
            .find_tenant_keysets_by_ids(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;

        Ok(instances)
    })
    .await
}

// TODO: remove when all sites have been upgraded to include find_ids and find_by_ids methods
async fn get_keysets_deprecated(
    api_config: &ApiConfig<'_>,
    tenant_org_id: Option<String>,
    identifier: Option<rpc::TenantKeysetIdentifier>,
) -> CarbideCliResult<rpc::TenantKeySetList> {
    let (mut organization_id, keyset_id) = match identifier.clone() {
        Some(id) => (Some(id.organization_id), Some(id.keyset_id)),
        None => (None, None),
    };
    if tenant_org_id.is_some() {
        organization_id = tenant_org_id;
    }
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::FindTenantKeysetRequest {
            organization_id,
            keyset_id,
            include_key_data: true,
        });
        let details = client
            .find_tenant_keyset(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;

        Ok(details)
    })
    .await
}

pub async fn machine_set_auto_update(
    req: MachineAutoupdate,
    api_config: &ApiConfig<'_>,
) -> CarbideCliResult<::rpc::forge::MachineSetAutoUpdateResponse> {
    let action = if req.enable {
        ::rpc::forge::machine_set_auto_update_request::SetAutoupdateAction::Enable
    } else if req.disable {
        ::rpc::forge::machine_set_auto_update_request::SetAutoupdateAction::Disable
    } else {
        ::rpc::forge::machine_set_auto_update_request::SetAutoupdateAction::Clear
    };
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(::rpc::forge::MachineSetAutoUpdateRequest {
            machine_id: Some(::rpc::MachineId {
                id: req.machine.to_string(),
            }),
            action: action.into(),
        });
        let response = client
            .machine_set_auto_update(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;

        Ok(response)
    })
    .await
}

pub async fn allocate_instance(
    api_config: &ApiConfig<'_>,
    host_machine_id: &str,
    network_segment_name: &String, // This is the same string passed as Subnet argument in the CLI.
    instance_name: &String,
    label_key: &Option<String>,
    label_value: &Option<String>,
) -> CarbideCliResult<rpc::Instance> {
    with_forge_client(api_config, |mut client| async move {
        let segment_request = tonic::Request::new(rpc::NetworkSegmentSearchFilter {
            name: Some(network_segment_name.clone()),
            tenant_org_id: None,
        });

        let network_segment_ids = match client.find_network_segment_ids(segment_request).await {
            Ok(response) => response.into_inner(),

            Err(e) => {
                return Err(CarbideCliError::GenericError(format!(
                    "network segment: {} retrieval error {}",
                    network_segment_name, e
                )));
            }
        };

        if network_segment_ids.network_segments_ids.is_empty() {
            return Err(CarbideCliError::GenericError(format!(
                "network segment: {} not found.",
                network_segment_name
            )));
        } else if network_segment_ids.network_segments_ids.len() >= 2 {
            tracing::warn!(
                "More than one {} network segments exist.",
                network_segment_name
            );
        }
        let network_segment_id = network_segment_ids.network_segments_ids.first();

        let interface_config = rpc::InstanceInterfaceConfig {
            function_type: rpc::InterfaceFunctionType::Physical as i32,
            network_segment_id: network_segment_id.cloned(),
        };

        let tenant_config = rpc::TenantConfig {
            user_data: None,
            custom_ipxe: "Non-existing-ipxe".to_string(),
            phone_home_enabled: false,
            always_boot_with_custom_ipxe: false,
            tenant_organization_id: "Forge-simulation-tenant".to_string(),
            tenant_keyset_ids: vec![],
            hostname: None,
        };

        let instance_config = rpc::InstanceConfig {
            tenant: Some(tenant_config),
            os: None,
            network: Some(rpc::InstanceNetworkConfig {
                interfaces: vec![interface_config],
            }),
            infiniband: None,
            storage: None,
        };

        let mut labels = vec![rpc::Label {
            key: "cloud-unsafe-op".to_string(),
            value: Some("true".to_string()),
        }];

        match (label_key, label_value) {
            (None, Some(_)) => {
                tracing::error!("label key cannot be empty while value is not empty.");
            }
            (Some(key), _) => labels.push(rpc::Label {
                key: key.to_string(),
                value: label_value.clone(),
            }),
            (None, None) => {}
        }

        let instance_request = tonic::Request::new(rpc::InstanceAllocationRequest {
            instance_id: None,
            machine_id: Some(::rpc::common::MachineId {
                id: host_machine_id.to_owned(),
            }),
            config: Some(instance_config),
            metadata: Some(rpc::Metadata {
                name: instance_name.to_string(),
                description: "instance created from admin-cli".to_string(),
                labels,
            }),
        });

        client
            .allocate_instance(instance_request)
            .await
            .map(|response: tonic::Response<rpc::Instance>| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)
    })
    .await
}

pub async fn get_machine_validation_external_config(
    name: String,
    api_config: &ApiConfig<'_>,
) -> CarbideCliResult<rpc::GetMachineValidationExternalConfigResponse> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::GetMachineValidationExternalConfigRequest { name });
        let result = client
            .get_machine_validation_external_config(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;

        Ok(result)
    })
    .await
}

pub async fn add_update_machine_validation_external_config(
    name: String,
    description: String,
    config: Vec<u8>,
    api_config: &ApiConfig<'_>,
) -> CarbideCliResult<()> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::AddUpdateMachineValidationExternalConfigRequest {
            config: Some(rpc::MachineValidationExternalConfig {
                name,
                description: Some(description),
                config,
            }),
        });
        client
            .add_update_machine_validation_external_config(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;

        Ok(())
    })
    .await
}

pub async fn get_machine_validation_results(
    api_config: &ApiConfig<'_>,
    machine_id: String,
    history: bool,
) -> CarbideCliResult<rpc::MachineValidationResultList> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::MachineValidationGetRequest {
            machine_id: Some(::rpc::common::MachineId { id: machine_id }),
            include_history: history,
        });
        let details = client
            .get_machine_validation_results(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;

        Ok(details)
    })
    .await
}

pub async fn get_machine_validation_runs(
    api_config: &ApiConfig<'_>,
    machine_id: Option<String>,
) -> CarbideCliResult<rpc::MachineValidationRunList> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::MachineValidationRunListGetRequest {
            machine_id: Some(::rpc::common::MachineId {
                id: machine_id.unwrap_or_default(),
            }),
            include_history: false,
        });
        let details = client
            .get_machine_validation_runs(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;

        Ok(details)
    })
    .await
}
