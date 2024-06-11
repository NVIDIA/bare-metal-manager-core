/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

pub use ::rpc::forge as rpc;
use ::rpc::protos::forge::{
    EchoRequest, EchoResponse, InstanceList, InstancePhoneHomeLastContactRequest,
    InstancePhoneHomeLastContactResponse, MachineCredentialsUpdateRequest,
    MachineCredentialsUpdateResponse,
};
use ::rpc::protos::measured_boot as measured_boot_pb;
use forge_secrets::certificates::CertificateProvider;
use forge_secrets::credentials::{CredentialKey, CredentialProvider, CredentialType, Credentials};
use itertools::Itertools;
use libredfish::SystemPowerControl;
use mac_address::MacAddress;
use sqlx::{Postgres, Transaction};
use tokio::net::lookup_host;
use tokio::time::{sleep, Instant};
use tonic::{Request, Response, Status};
use tss_esapi::structures::{Attest, Public as TssPublic, Signature};
use tss_esapi::traits::UnMarshall;
use uuid::Uuid;

use self::rpc::forge_server::Forge;
use crate::attestation as attest;
use crate::cfg::CarbideConfig;
use crate::db::bmc_metadata::UserRoles;
use crate::db::dpu_agent_upgrade_policy::DpuAgentUpgradePolicy;
use crate::db::expected_machine::ExpectedMachine;
use crate::db::ib_partition::IBPartition;
use crate::db::instance_address::InstanceAddress;
use crate::db::machine::{MachineSearchConfig, MaintenanceMode};
use crate::db::machine_boot_override::MachineBootOverride;
use crate::db::network_devices::NetworkDeviceSearchConfig;
use crate::db::site_exploration_report::DbSiteExplorationReport;
use crate::dynamic_settings;
use crate::ib::{IBFabricManager, DEFAULT_IB_FABRIC_NAME};
use crate::ip_finder;
use crate::ipmitool::IPMITool;
use crate::ipxe::PxeInstructions;
use crate::logging::log_limiter::LogLimiter;
use crate::measured_boot;
use crate::model::instance::status::network::InstanceInterfaceStatusObservation;
use crate::model::machine::machine_id::try_parse_machine_id;
use crate::model::machine::network::MachineNetworkStatusObservation;
use crate::model::machine::upgrade_policy::{AgentUpgradePolicy, BuildVersion};
use crate::model::machine::{
    FailureCause, FailureDetails, FailureSource, InstanceState, ManagedHostState, ReprovisionState,
};
use crate::model::network_devices::{DpuToNetworkDeviceMap, NetworkDevice, NetworkTopologyData};
use crate::model::os::OperatingSystemVariant;
use crate::model::RpcDataConversionError;
use crate::redfish::RedfishAuth;
use crate::redfish::{host_power_control, poll_redfish_job, set_host_uefi_password};
use crate::resource_pool::common::CommonPools;
use crate::site_explorer::EndpointExplorer;
use crate::state_controller::snapshot_loader::{MachineStateSnapshotLoader, SnapshotLoaderError};
use crate::{
    auth,
    credentials::UpdateCredentials,
    db::{
        attestation::SecretAkPub,
        bmc_metadata::{BmcMetaDataGetRequest, BmcMetaDataUpdateRequest},
        domain::Domain,
        instance::{DeleteInstance, Instance},
        machine::Machine,
        machine_interface::MachineInterface,
        machine_topology::MachineTopology,
        resource_record::DnsQuestion,
        route_servers::RouteServer,
        vpc::Vpc,
        DatabaseError, ObjectFilter, UuidKeyedObjectFilter,
    },
    ethernet_virtualization,
    model::{
        hardware_info::{HardwareInfo, MachineInventory},
        instance::status::network::InstanceNetworkStatusObservation,
        machine::{machine_id::MachineId, MachineState, MeasuringState},
    },
    redfish::RedfishClientPool,
    state_controller::snapshot_loader::DbSnapshotLoader,
    CarbideError, CarbideResult,
};
use crate::{resource_pool, site_explorer};

/// Username for debug SSH access to DPU. Created by cloud-init on boot. Password in Vault.
const DPU_ADMIN_USERNAME: &str = "forge";

/// Username for default site-wide BMC username.
const FORGE_SITE_WIDE_BMC_USERNAME: &str = "root";

// vxlan5555 is special HBN single vxlan device. It handles networking between machines on the
// same subnet. It handles the encapsulation into VXLAN and VNI for cross-host comms.
const HBN_SINGLE_VLAN_DEVICE: &str = "vxlan5555";

pub struct Api {
    pub(crate) database_connection: sqlx::PgPool,
    credential_provider: Arc<dyn CredentialProvider>,
    certificate_provider: Arc<dyn CertificateProvider>,
    pub(crate) redfish_pool: Arc<dyn RedfishClientPool>,
    pub(crate) eth_data: ethernet_virtualization::EthVirtData,
    pub(crate) common_pools: Arc<CommonPools>,
    pub(crate) ib_fabric_manager: Arc<dyn IBFabricManager>,
    pub(crate) runtime_config: Arc<CarbideConfig>,
    dpu_health_log_limiter: LogLimiter<MachineId>,
    pub dynamic_settings: dynamic_settings::DynamicSettings,
    ipmi_tool: Arc<dyn IPMITool>,
}

#[tonic::async_trait]
impl Forge for Api {
    async fn version(
        &self,
        request: tonic::Request<rpc::VersionRequest>,
    ) -> Result<Response<rpc::BuildInfo>, Status> {
        log_request_data(&request);
        let version_request = request.into_inner();

        let v = rpc::BuildInfo {
            build_version: forge_version::v!(build_version).to_string(),
            build_date: forge_version::v!(build_date).to_string(),
            git_sha: forge_version::v!(git_sha).to_string(),
            rust_version: forge_version::v!(rust_version).to_string(),
            build_user: forge_version::v!(build_user).to_string(),
            build_hostname: forge_version::v!(build_hostname).to_string(),

            runtime_config: if version_request.display_config {
                Some((*self.runtime_config).clone().into())
            } else {
                None
            },
        };
        Ok(Response::new(v))
    }

    async fn create_domain(
        &self,
        request: Request<rpc::Domain>,
    ) -> Result<Response<rpc::Domain>, Status> {
        crate::handlers::domain::create(self, request).await
    }

    async fn update_domain(
        &self,
        request: Request<rpc::Domain>,
    ) -> Result<Response<rpc::Domain>, Status> {
        crate::handlers::domain::update(self, request).await
    }

    async fn delete_domain(
        &self,
        request: Request<rpc::DomainDeletion>,
    ) -> Result<Response<rpc::DomainDeletionResult>, Status> {
        crate::handlers::domain::delete(self, request).await
    }

    async fn find_domain(
        &self,
        request: Request<rpc::DomainSearchQuery>,
    ) -> Result<Response<rpc::DomainList>, Status> {
        crate::handlers::domain::find(self, request).await
    }

    async fn create_vpc(
        &self,
        request: Request<rpc::VpcCreationRequest>,
    ) -> Result<Response<rpc::Vpc>, Status> {
        crate::handlers::vpc::create(self, request).await
    }

    async fn update_vpc(
        &self,
        request: Request<rpc::VpcUpdateRequest>,
    ) -> Result<Response<rpc::VpcUpdateResult>, Status> {
        crate::handlers::vpc::update(self, request).await
    }

    async fn delete_vpc(
        &self,
        request: Request<rpc::VpcDeletionRequest>,
    ) -> Result<Response<rpc::VpcDeletionResult>, Status> {
        crate::handlers::vpc::delete(self, request).await
    }

    async fn find_vpcs(
        &self,
        request: Request<rpc::VpcSearchQuery>,
    ) -> Result<Response<rpc::VpcList>, Status> {
        crate::handlers::vpc::find(self, request).await
    }

    async fn find_ib_partitions(
        &self,
        request: Request<rpc::IbPartitionQuery>,
    ) -> Result<Response<rpc::IbPartitionList>, Status> {
        crate::handlers::ib_partition::find(self, request).await
    }

    async fn create_ib_partition(
        &self,
        request: Request<rpc::IbPartitionCreationRequest>,
    ) -> Result<Response<rpc::IbPartition>, Status> {
        crate::handlers::ib_partition::create(self, request).await
    }

    async fn delete_ib_partition(
        &self,
        request: Request<rpc::IbPartitionDeletionRequest>,
    ) -> Result<Response<rpc::IbPartitionDeletionResult>, Status> {
        crate::handlers::ib_partition::delete(self, request).await
    }

    async fn ib_partitions_for_tenant(
        &self,
        request: Request<rpc::TenantSearchQuery>,
    ) -> Result<Response<rpc::IbPartitionList>, Status> {
        crate::handlers::ib_partition::for_tenant(self, request).await
    }

    async fn find_network_segments(
        &self,
        request: Request<rpc::NetworkSegmentQuery>,
    ) -> Result<Response<rpc::NetworkSegmentList>, Status> {
        crate::handlers::network_segment::find(self, request).await
    }

    async fn create_network_segment(
        &self,
        request: Request<rpc::NetworkSegmentCreationRequest>,
    ) -> Result<Response<rpc::NetworkSegment>, Status> {
        crate::handlers::network_segment::create(self, request).await
    }

    async fn delete_network_segment(
        &self,
        request: Request<rpc::NetworkSegmentDeletionRequest>,
    ) -> Result<Response<rpc::NetworkSegmentDeletionResult>, Status> {
        crate::handlers::network_segment::delete(self, request).await
    }

    async fn network_segments_for_vpc(
        &self,
        request: Request<rpc::VpcSearchQuery>,
    ) -> Result<Response<rpc::NetworkSegmentList>, Status> {
        crate::handlers::network_segment::for_vpc(self, request).await
    }

    async fn allocate_instance(
        &self,
        request: Request<rpc::InstanceAllocationRequest>,
    ) -> Result<Response<rpc::Instance>, Status> {
        crate::handlers::instance::allocate(self, request).await
    }

    async fn find_instances(
        &self,
        request: Request<rpc::InstanceSearchQuery>,
    ) -> Result<Response<rpc::InstanceList>, Status> {
        crate::handlers::instance::find(self, request).await
    }

    async fn find_instance_by_machine_id(
        &self,
        request: Request<rpc::MachineId>,
    ) -> Result<Response<InstanceList>, Status> {
        crate::handlers::instance::find_by_machine_id(self, request).await
    }

    async fn release_instance(
        &self,
        request: Request<rpc::InstanceReleaseRequest>,
    ) -> Result<Response<rpc::InstanceReleaseResult>, Status> {
        crate::handlers::instance::release(self, request).await
    }

    async fn record_observed_instance_network_status(
        &self,
        request: Request<rpc::InstanceNetworkStatusObservation>,
    ) -> Result<Response<rpc::ObservedInstanceNetworkStatusRecordResult>, tonic::Status> {
        crate::handlers::instance::record_observed_network_status(self, request).await
    }

    async fn update_instance_phone_home_last_contact(
        &self,
        request: Request<InstancePhoneHomeLastContactRequest>,
    ) -> Result<Response<InstancePhoneHomeLastContactResponse>, Status> {
        crate::handlers::instance::update_phone_home_last_contact(self, request).await
    }

    async fn get_managed_host_network_config(
        &self,
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
        let mut txn = self.database_connection.begin().await.map_err(|e| {
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

        // TODO: multidpu: Fix it for multiple dpus.
        let loopback_ip = match snapshot.dpu_snapshots[0].loopback_ip() {
            Some(ip) => ip,
            None => {
                return Err(Status::failed_precondition(format!(
                    "DPU {} needs discovery. Does not have a loopback IP yet.",
                    snapshot.dpu_snapshots[0].machine_id
                )));
            }
        };
        let use_admin_network = snapshot.dpu_snapshots[0].use_admin_network();

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
            asn: self.eth_data.asn,
            dhcp_servers: self.eth_data.dhcp_servers.clone(),
            route_servers: self.eth_data.route_servers.clone(),
            // TODO: Automatically add the prefix(es?) from the IPv4 loopback
            // pool to deny_prefixes. The database stores the pool in an
            // exploded representation, so we either need to reconstruct the
            // original prefix from what's in the database, or find some way to
            // store it when it's added or resized.
            deny_prefixes: self
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
            instance_config_version: if use_admin_network {
                "".to_string()
            } else {
                snapshot
                    .instance
                    .unwrap()
                    .network_config_version
                    .version_string()
            },
            remote_id: dpu_machine_id.remote_id(),
            network_virtualization_type: Some(if self.runtime_config.nvue_enabled {
                // new
                rpc::VpcVirtualizationType::EthernetVirtualizerWithNvue as i32
            } else {
                // old
                rpc::VpcVirtualizationType::EthernetVirtualizer as i32
            }),
            vpc_vni: vpc_vni.map(|vni| vni as u32),
            enable_dhcp: self.runtime_config.dpu_dhcp_server_enabled,
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

    async fn update_agent_reported_inventory(
        &self,
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
            let mut txn = self.database_connection.begin().await.map_err(|e| {
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

    async fn record_dpu_network_status(
        &self,
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

        let mut txn = self.database_connection.begin().await.map_err(|e| {
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

        let machine_obs = MachineNetworkStatusObservation::try_from(request.clone())
            .map_err(CarbideError::from)?;
        Machine::update_network_status_observation(&mut txn, &dpu_machine_id, &machine_obs)
            .await
            .map_err(CarbideError::from)?;
        tracing::trace!(
            machine_id = %dpu_machine_id,
            machine_network_config = ?request.network_config_version,
            instance_network_config = ?request.instance_config_version,
            agent_version = machine_obs.agent_version,
            "Applied network configs",
        );

        // We already persisted the machine parts of applied_config in
        // update_network_status_observation above. Now do the instance parts.
        if let Some(version_string) = request.instance_config_version {
            let Ok(version) = version_string.as_str().parse() else {
                return Err(CarbideError::InvalidArgument(
                    "applied_config.instance_config_version".to_string(),
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
            let Some(instance_id_rpc) = request.instance_id else {
                return Err(CarbideError::MissingArgument("applied_config.instance_id").into());
            };
            let instance_id = Uuid::try_from(instance_id_rpc).map_err(CarbideError::from)?;
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
        let mut txn = self.database_connection.begin().await.map_err(|e| {
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
                Machine::apply_agent_upgrade_policy(&mut txn, policy, &dpu_machine_id)
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
            || !self
                .dpu_health_log_limiter
                .should_log(&dpu_machine_id, &suppress_log_key)
        {
            tracing::Span::current().record("logfmt.suppress", true);
        }

        Ok(Response::new(()))
    }

    async fn lookup_record(
        &self,
        request: Request<rpc::dns_message::DnsQuestion>,
    ) -> Result<Response<rpc::dns_message::DnsResponse>, Status> {
        log_request_data(&request);

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin lookup_record",
                e,
            ))
        })?;

        let rpc::dns_message::DnsQuestion {
            q_name,
            q_type,
            q_class,
        } = request.into_inner();

        let question = match q_name.clone() {
            Some(q_name) => DnsQuestion {
                query_name: Some(q_name),
                query_type: q_type,
                query_class: q_class,
            },
            None => {
                return Err(Status::invalid_argument(
                    "A valid q_name, q_type and q_class are required",
                ));
            }
        };

        let response = DnsQuestion::find_record(&mut txn, question)
            .await
            .map(|dnsrr| rpc::dns_message::DnsResponse {
                rcode: dnsrr.response_code,
                rrs: dnsrr
                    .resource_records
                    .into_iter()
                    .map(|r| r.into())
                    .collect(),
            })
            .map_err(CarbideError::from)?;
        tracing::info!(DnsResponse = ?response, "lookup_record dns responded");

        Ok(Response::new(response))
    }

    async fn invoke_instance_power(
        &self,
        request: Request<rpc::InstancePowerRequest>,
    ) -> Result<Response<rpc::InstancePowerResult>, Status> {
        crate::handlers::instance::invoke_power(self, request).await
    }

    async fn echo(&self, request: Request<EchoRequest>) -> Result<Response<EchoResponse>, Status> {
        log_request_data(&request);

        let reply = EchoResponse {
            message: request.into_inner().message,
        };

        Ok(Response::new(reply))
    }

    /// Tenant-related actions
    async fn create_tenant(
        &self,
        request: Request<rpc::CreateTenantRequest>,
    ) -> Result<Response<rpc::CreateTenantResponse>, Status> {
        crate::handlers::tenant::create(self, request).await
    }

    async fn find_tenant(
        &self,
        request: Request<rpc::FindTenantRequest>,
    ) -> Result<Response<rpc::FindTenantResponse>, Status> {
        crate::handlers::tenant::find(self, request).await
    }

    async fn update_tenant(
        &self,
        request: Request<rpc::UpdateTenantRequest>,
    ) -> Result<Response<rpc::UpdateTenantResponse>, Status> {
        crate::handlers::tenant::update(self, request).await
    }

    async fn create_tenant_keyset(
        &self,
        request: Request<rpc::CreateTenantKeysetRequest>,
    ) -> Result<Response<rpc::CreateTenantKeysetResponse>, Status> {
        crate::handlers::tenant_keyset::create(self, request).await
    }

    async fn find_tenant_keyset(
        &self,
        request: Request<rpc::FindTenantKeysetRequest>,
    ) -> Result<Response<rpc::TenantKeySetList>, Status> {
        crate::handlers::tenant_keyset::find(self, request).await
    }

    async fn update_tenant_keyset(
        &self,
        request: Request<rpc::UpdateTenantKeysetRequest>,
    ) -> Result<Response<rpc::UpdateTenantKeysetResponse>, Status> {
        crate::handlers::tenant_keyset::update(self, request).await
    }

    async fn delete_tenant_keyset(
        &self,
        request: Request<rpc::DeleteTenantKeysetRequest>,
    ) -> Result<Response<rpc::DeleteTenantKeysetResponse>, Status> {
        crate::handlers::tenant_keyset::delete(self, request).await
    }

    async fn validate_tenant_public_key(
        &self,
        request: Request<rpc::ValidateTenantPublicKeyRequest>,
    ) -> Result<Response<rpc::ValidateTenantPublicKeyResponse>, Status> {
        crate::handlers::tenant_keyset::validate_public_key(self, request).await
    }

    async fn renew_machine_certificate(
        &self,
        request: Request<rpc::MachineCertificateRenewRequest>,
    ) -> Result<Response<rpc::MachineCertificateResult>, Status> {
        if let Some(machine_identity) = request
            .extensions()
            .get::<auth::AuthContext>()
            // XXX: Does a machine's certificate resemble a service's
            // certificate enough for this to work?
            .and_then(|auth_context| auth_context.get_spiffe_machine_id())
        {
            let certificate = self
                .certificate_provider
                .get_certificate(machine_identity)
                .await
                .map_err(|err| CarbideError::ClientCertificateError(err.to_string()))?;

            return Ok(Response::new(rpc::MachineCertificateResult {
                machine_certificate: Some(certificate.into()),
            }));
        }

        Err(
            CarbideError::ClientCertificateError("no client certificate presented?".to_string())
                .into(),
        )
    }

    async fn discover_machine(
        &self,
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

        let interface_id = machine_discovery_info
            .machine_interface_id
            .and_then(|id| Uuid::try_from(id).ok());

        let discovery_data = machine_discovery_info
            .discovery_data
            .map(|data| match data {
                rpc::machine_discovery_info::DiscoveryData::Info(info) => info,
            })
            .ok_or_else(|| Status::invalid_argument("Discovery data is not populated"))?;
        let hardware_info = HardwareInfo::try_from(discovery_data).map_err(CarbideError::from)?;

        // Generate a stable Machine ID based on the hardware information
        let stable_machine_id = MachineId::from_hardware_info(&hardware_info).map_err(|e| {
            CarbideError::InvalidArgument(
                format!("Insufficient HardwareInfo to derive a Stable Machine ID for Machine on InterfaceId {:?}: {e}", interface_id),
            )
        })?;
        log_machine_id(&stable_machine_id);

        if !hardware_info.is_dpu() && hardware_info.tpm_ek_certificate.is_none() {
            return Err(CarbideError::InvalidArgument(format!(
                "Ignoring DiscoverMachine request for non-tpm enabled host with InterfaceId {:?}",
                interface_id
            ))
            .into());
        }

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin discover_machine",
                e,
            ))
        })?;

        tracing::debug!(
            ?remote_ip,
            ?interface_id,
            "discover_machine loading interface"
        );

        let interface =
            MachineInterface::find_by_ip_or_id(&mut txn, remote_ip, interface_id).await?;
        let machine = if hardware_info.is_dpu() {
            let (db_machine, is_new) = if machine_discovery_info.create_machine {
                Machine::get_or_create(&mut txn, &stable_machine_id, &interface).await?
            } else {
                let machine = Machine::find_one(
                    &mut txn,
                    &stable_machine_id,
                    MachineSearchConfig {
                        include_dpus: true,
                        ..MachineSearchConfig::default()
                    },
                )
                .await
                .map_err(CarbideError::from)?
                .ok_or_else(|| {
                    Status::invalid_argument(format!("Machine id {stable_machine_id} not found."))
                })?;
                (machine, false)
            };

            interface
                .associate_interface_with_dpu_machine(&mut txn, &stable_machine_id)
                .await
                .map_err(CarbideError::from)?;
            if is_new {
                let loopback_ip = self
                    .allocate_loopback_ip(&mut txn, &stable_machine_id.to_string())
                    .await?;
                let (mut network_config, version) = db_machine.network_config().clone().take();
                network_config.loopback_ip = Some(loopback_ip);
                network_config.use_admin_network = Some(true);
                Machine::try_update_network_config(
                    &mut txn,
                    &stable_machine_id,
                    version,
                    &network_config,
                )
                .await
                .map_err(CarbideError::from)?;
            }
            db_machine
        } else {
            // Now we know stable machine id for host. Let's update it in db.
            Machine::try_sync_stable_id_with_current_machine_id_for_host(
                &mut txn,
                &interface.machine_id,
                &stable_machine_id,
            )
            .await?
        };

        MachineTopology::create_or_update(&mut txn, &stable_machine_id, &hardware_info).await?;

        if hardware_info.is_dpu() {
            // Create Host proactively.
            // In case host interface is created, this method will return existing one, instead
            // creating new everytime.
            let machine_interface = MachineInterface::create_host_machine_interface_proactively(
                &mut txn,
                Some(&hardware_info),
                machine.id(),
            )
            .await?;

            // Create host machine with temporary ID if no machine is attached.
            if machine_interface.machine_id.is_none() {
                let predicted_machine_id =
                    MachineId::host_id_from_dpu_hardware_info(&hardware_info).map_err(|e| {
                        CarbideError::InvalidArgument(format!("hardware info missing: {e}"))
                    })?;
                let mi_id = machine_interface.id;
                let (proactive_machine, _) =
                    Machine::get_or_create(&mut txn, &predicted_machine_id, &machine_interface)
                        .await?;
                tracing::info!(
                    ?mi_id,
                    machine_id = %proactive_machine.id(),
                    "Created host machine proactively",
                );
            }
        }

        let id_str = stable_machine_id.to_string();
        let certificate = if std::env::var("UNSUPPORTED_CERTIFICATE_PROVIDER").is_ok() {
            forge_secrets::certificates::Certificate::default()
        } else {
            self.certificate_provider
                .get_certificate(id_str.as_str())
                .await
                .map_err(|err| CarbideError::ClientCertificateError(err.to_string()))?
        };

        let response = Ok(Response::new(rpc::MachineDiscoveryResult {
            machine_id: Some(id_str.into()),
            machine_certificate: Some(certificate.into()),
        }));

        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "commit discover_machine",
                e,
            ))
        })?;

        if hardware_info.is_dpu() {
            // WARNING: DONOT REUSE OLD TXN HERE. IT WILL CREATE DEADLOCK.
            //
            // Create a new transaction here for network devices. Inner transaction is not so
            // helpful in postgres and using same transaction creates deadlock with
            // machine_interface table.
            let mut txn = self.database_connection.begin().await.map_err(|e| {
                CarbideError::from(DatabaseError::new(
                    file!(),
                    line!(),
                    "begin discover_machine",
                    e,
                ))
            })?;
            // Create DPU and LLDP Association.
            if let Some(dpu_info) = hardware_info.dpu_info.as_ref() {
                DpuToNetworkDeviceMap::create_dpu_network_device_association(
                    &mut txn,
                    &dpu_info.switches,
                    &stable_machine_id,
                )
                .await
                .map_err(CarbideError::from)?;
            }
            txn.commit().await.map_err(|e| {
                CarbideError::from(DatabaseError::new(
                    file!(),
                    line!(),
                    "commit new txn discover_machine",
                    e,
                ))
            })?;
        }

        response
    }

    // Host has completed discovery
    async fn discovery_completed(
        &self,
        request: Request<rpc::MachineDiscoveryCompletedRequest>,
    ) -> Result<Response<rpc::MachineDiscoveryCompletedResponse>, Status> {
        log_request_data(&request);

        let req = request.into_inner();

        // Extract and check UUID
        let machine_id = match &req.machine_id {
            Some(id) => try_parse_machine_id(id).map_err(CarbideError::from)?,
            None => {
                return Err(Status::invalid_argument("A machine UUID is required"));
            }
        };
        log_machine_id(&machine_id);

        let (machine, mut txn) = self
            .load_machine(&machine_id, MachineSearchConfig::default())
            .await?;
        machine
            .update_discovery_time(&mut txn)
            .await
            .map_err(CarbideError::from)?;

        let discovery_result = match req.discovery_error {
            Some(discovery_error) => {
                machine
                    .update_failure_details(
                        &mut txn,
                        FailureDetails {
                            cause: FailureCause::Discovery {
                                err: discovery_error.clone(),
                            },
                            failed_at: chrono::Utc::now(),
                            source: FailureSource::Scout,
                        },
                    )
                    .await
                    .map_err(CarbideError::from)?;
                discovery_error
            }
            None => "Success".to_owned(),
        };

        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "commit discovery_completed",
                e,
            ))
        })?;

        tracing::info!(
            %machine_id,
            discovery_result, "discovery_completed",
        );
        Ok(Response::new(rpc::MachineDiscoveryCompletedResponse {}))
    }

    // Transitions the machine to Ready state.
    // Called by 'forge-scout discovery' once cleanup succeeds.
    async fn cleanup_machine_completed(
        &self,
        request: Request<rpc::MachineCleanupInfo>,
    ) -> Result<Response<rpc::MachineCleanupResult>, Status> {
        log_request_data(&request);

        let cleanup_info = request.into_inner();
        tracing::info!(?cleanup_info, "cleanup_machine_completed");

        // Extract and check UUID
        let machine_id = match &cleanup_info.machine_id {
            Some(id) => try_parse_machine_id(id).map_err(CarbideError::from)?,
            None => {
                return Err(Status::invalid_argument("A machine UUID is required"));
            }
        };
        log_machine_id(&machine_id);

        // Load machine from DB
        let (machine, mut txn) = self
            .load_machine(&machine_id, MachineSearchConfig::default())
            .await?;
        machine
            .update_cleanup_time(&mut txn)
            .await
            .map_err(CarbideError::from)?;

        if let Some(nvme_result) = cleanup_info.nvme {
            if rpc::machine_cleanup_info::CleanupResult::Error as i32 == nvme_result.result {
                // NVME Cleanup failed. Move machine to failed state.
                machine
                    .update_failure_details(
                        &mut txn,
                        FailureDetails {
                            cause: FailureCause::NVMECleanFailed {
                                err: nvme_result.message.to_string(),
                            },
                            failed_at: chrono::Utc::now(),
                            source: FailureSource::Scout,
                        },
                    )
                    .await
                    .map_err(CarbideError::from)?;
            }
        }

        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "commit cleanup_machine_completed",
                e,
            ))
        })?;

        // State handler should mark Machine as Adopted and reboot host for bios/bmc lockdown.
        Ok(Response::new(rpc::MachineCleanupResult {}))
    }

    /// Invoked by forge-scout whenever a certain Machine can not be properly acted on
    async fn report_forge_scout_error(
        &self,
        request: tonic::Request<rpc::ForgeScoutErrorReport>,
    ) -> Result<tonic::Response<rpc::ForgeScoutErrorReportResult>, tonic::Status> {
        log_request_data(&request);
        if let Some(machine_id) = request.get_ref().machine_id.as_ref() {
            let machine_id = try_parse_machine_id(machine_id).map_err(CarbideError::from)?;
            log_machine_id(&machine_id);
        }

        // `log_request_data` will already provide us the error message
        // Therefore we don't have to do anything else
        Ok(Response::new(rpc::ForgeScoutErrorReportResult {}))
    }

    async fn discover_dhcp(
        &self,
        request: Request<rpc::DhcpDiscovery>,
    ) -> Result<Response<rpc::DhcpRecord>, Status> {
        log_request_data(&request);

        Ok(crate::dhcp::discover::discover_dhcp(&self.database_connection, request).await?)
    }

    async fn get_machine(
        &self,
        request: Request<rpc::MachineId>,
    ) -> Result<Response<rpc::Machine>, Status> {
        log_request_data(&request);

        let machine_id = try_parse_machine_id(&request.into_inner()).map_err(CarbideError::from)?;
        log_machine_id(&machine_id);
        let (machine, _) = self
            .load_machine(
                &machine_id,
                MachineSearchConfig {
                    include_dpus: false,
                    include_history: true,
                    include_predicted_host: false,
                    only_maintenance: false,
                    include_associated_machine_id: true,
                    exclude_hosts: false,
                },
            )
            .await?;

        Ok(Response::new(rpc::Machine::from(machine)))
    }

    async fn find_machine_ids(
        &self,
        request: Request<rpc::MachineSearchConfig>,
    ) -> Result<Response<rpc::MachineIdList>, Status> {
        log_request_data(&request);
        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin find_machines",
                e,
            ))
        })?;

        let search_config = request.into_inner().into();

        let machine_ids = Machine::find_machine_ids(&mut txn, search_config)
            .await
            .map_err(CarbideError::from)?;

        Ok(tonic::Response::new(rpc::MachineIdList {
            machine_ids: machine_ids
                .into_iter()
                .map(|id| rpc::MachineId { id: id.to_string() })
                .collect(),
        }))
    }

    async fn find_machines_by_ids(
        &self,
        request: Request<rpc::MachineIdList>,
    ) -> Result<Response<rpc::MachineList>, Status> {
        log_request_data(&request);
        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin find_machines_by_ids",
                e,
            ))
        })?;
        let search_config = MachineSearchConfig {
            include_associated_machine_id: true,
            ..Default::default()
        };

        let machine_ids: Result<Vec<MachineId>, CarbideError> = request
            .into_inner()
            .machine_ids
            .iter()
            .map(|id| {
                MachineId::from_str(&id.id).map_err(|_| {
                    CarbideError::from(RpcDataConversionError::InvalidMachineId(id.id.clone()))
                })
            })
            .collect();

        let machine_ids = machine_ids?;

        let max_find_by_ids = self.runtime_config.max_find_by_ids as usize;
        if machine_ids.len() > max_find_by_ids {
            return Err(CarbideError::InvalidArgument(format!(
                "no more than {max_find_by_ids} IDs can be accepted"
            ))
            .into());
        }

        let machines: Vec<Machine> =
            Machine::find(&mut txn, ObjectFilter::List(&machine_ids), search_config)
                .await
                .map_err(CarbideError::from)?;

        Ok(tonic::Response::new(rpc::MachineList {
            machines: machines.into_iter().map(Machine::into).collect(),
        }))
    }

    // DEPRECATED: use GetMachineIds and FindMachinesByIds instead
    async fn find_machines(
        &self,
        request: Request<rpc::MachineSearchQuery>,
    ) -> Result<Response<rpc::MachineList>, Status> {
        log_request_data(&request);

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin find_machines",
                e,
            ))
        })?;

        let rpc::MachineSearchQuery {
            id,
            fqdn,
            search_config,
            ..
        } = request.into_inner();
        let include_dpus = search_config
            .as_ref()
            .map(|x| x.include_dpus)
            .unwrap_or(false);

        let include_ph = search_config
            .as_ref()
            .map(|x| x.include_predicted_host)
            .unwrap_or(false);

        let search_config = search_config
            .map(MachineSearchConfig::from)
            .unwrap_or(MachineSearchConfig::default());

        let machines: Result<Vec<Machine>, DatabaseError> = match (id, fqdn) {
            (Some(id), _) => {
                let machine_id = try_parse_machine_id(&id).map_err(CarbideError::from)?;
                log_machine_id(&machine_id);
                Machine::find(&mut txn, ObjectFilter::One(machine_id), search_config).await
            }
            (None, Some(fqdn)) => Machine::find_by_fqdn(&mut txn, &fqdn, search_config).await,
            (None, None) => Machine::find(&mut txn, ObjectFilter::All, search_config).await,
        };

        let result = machines
            .map(|machine| rpc::MachineList {
                machines: machine
                    .into_iter()
                    .filter(|x| {
                        let ty = x.machine_type();
                        // We never return PredictedHost
                        ty.is_host()
                            || (ty.is_dpu() && include_dpus)
                            || (ty.is_predicted_host() && include_ph)
                    })
                    .map(rpc::Machine::from)
                    .collect(),
            })
            .map(Response::new)
            .map_err(CarbideError::from)?;

        Ok(result)
    }

    async fn find_interfaces(
        &self,
        request: Request<rpc::InterfaceSearchQuery>,
    ) -> Result<Response<rpc::InterfaceList>, Status> {
        log_request_data(&request);

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin find_interfaces",
                e,
            ))
        })?;

        let rpc::InterfaceSearchQuery { id, ip } = request.into_inner();

        let response = match (id, ip) {
            (Some(id), _) if id.value.chars().count() > 0 => match Uuid::try_from(id) {
                Ok(uuid) => Ok(rpc::InterfaceList {
                    interfaces: vec![MachineInterface::find_one(&mut txn, uuid).await?.into()],
                }),
                Err(_) => Err(CarbideError::GenericError(
                    "Could not marshall an ID from the request".to_string(),
                )
                .into()),
            },
            (None, Some(ip)) => match Ipv4Addr::from_str(ip.as_ref()) {
                Ok(ip) => {
                    match MachineInterface::find_by_ip(&mut txn, IpAddr::V4(ip))
                        .await
                        .map_err(CarbideError::from)?
                    {
                        Some(interface) => Ok(rpc::InterfaceList {
                            interfaces: vec![interface.into()],
                        }),
                        None => {
                            return Err(CarbideError::GenericError(format!(
                                "No machine interface with IP {ip} was found"
                            ))
                            .into());
                        }
                    }
                }
                Err(_) => Err(CarbideError::GenericError(
                    "Could not marshall an IP from the request".to_string(),
                )
                .into()),
            },
            (None, None) => {
                match MachineInterface::find_all(&mut txn)
                    .await
                    .map_err(CarbideError::from)
                {
                    Ok(machine_interfaces) => Ok(rpc::InterfaceList {
                        interfaces: machine_interfaces
                            .into_iter()
                            .map(|i| i.into())
                            .collect_vec(),
                    }),
                    Err(error) => return Err(error.into()),
                }
            }
            _ => Err(CarbideError::GenericError(
                "Could not find an ID or IP in the request".to_string(),
            )
            .into()),
        };

        response.map(Response::new)
    }

    async fn delete_interface(
        &self,
        request: Request<rpc::InterfaceDeleteQuery>,
    ) -> Result<Response<()>, Status> {
        log_request_data(&request);

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin find_interfaces",
                e,
            ))
        })?;

        let rpc::InterfaceDeleteQuery { id } = request.into_inner();
        let Some(id) = id else {
            return Err(CarbideError::MissingArgument("delete interface.interface_id").into());
        };

        let interface = match Uuid::try_from(id) {
            Ok(uuid) => MachineInterface::find_one(&mut txn, uuid).await?,
            Err(_) => {
                return Err(CarbideError::GenericError(
                    "Could not marshall an ID from the request".to_string(),
                )
                .into())
            }
        };

        // There should not be any machine associated with this interface.
        if let Some(machine_id) = interface.machine_id {
            return Err(Status::invalid_argument(format!(
                "Already a machine {machine_id} is attached to this interface. Delete that first."
            )));
        }

        // There should not be any BMC information associated with any machine.
        for address in interface.addresses() {
            let machine_id =
                MachineTopology::find_machine_id_by_bmc_ip(&mut txn, &address.address.to_string())
                    .await
                    .map_err(CarbideError::from)?;

            if let Some(machine_id) = machine_id {
                return Err(Status::invalid_argument(
                    format!("This looks like a BMC interface and attached with machine: {machine_id}. Delete that first."),
                ));
            }
        }

        interface
            .delete(&mut txn)
            .await
            .map_err(CarbideError::from)?;

        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "commit delete interface",
                e,
            ))
        })?;

        Ok(Response::new(()))
    }

    // Fetch the DPU admin SSH password from Vault.
    // "host_id" can be any of:
    //  - UUID (primary key)
    //  - IPv4 address
    //  - MAC address
    //  - Hostname
    //
    // Usage:
    //  grpcurl -d '{"host_id": "neptune-bravo"}' -insecure 127.0.0.1:1079 forge.Forge/GetDpuSSHCredential | jq -r -j ".password"
    // That should evaluate to exactly the password, ready for inclusion in a script.
    //
    async fn get_dpu_ssh_credential(
        &self,
        request: Request<rpc::CredentialRequest>,
    ) -> Result<Response<rpc::CredentialResponse>, Status> {
        log_request_data(&request);

        let query = request.into_inner().host_id;

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin get_dpu_ssh_credential",
                e,
            ))
        })?;
        let machine_id = match Machine::find_by_query(&mut txn, &query)
            .await
            .map_err(CarbideError::from)?
        {
            Some(machine) => {
                log_machine_id(machine.id());
                if !machine.is_dpu() {
                    return Err(Status::not_found(format!(
                        "Searching for machine {} was found for '{query}', but it is not a DPU",
                        machine.id()
                    )));
                }
                machine.id().clone()
            }
            None => {
                return Err(CarbideError::NotFoundError {
                    kind: "machine",
                    id: query,
                }
                .into());
            }
        };

        // We don't need this transaction
        let _ = txn.rollback().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "rollback get_dpu_ssh_credential",
                e,
            ))
        })?;

        // Load credentials from Vault
        let credentials = self
            .credential_provider
            .get_credentials(CredentialKey::DpuSsh {
                machine_id: machine_id.to_string(),
            })
            .await
            .map_err(|err| match err.downcast::<vaultrs::error::ClientError>() {
                Ok(vaultrs::error::ClientError::APIError { code: 404, .. }) => {
                    CarbideError::NotFoundError {
                        kind: "dpu-ssh-cred",
                        id: machine_id.to_string(),
                    }
                }
                Ok(ce) => CarbideError::GenericError(format!("Vault error: {}", ce)),
                Err(err) => CarbideError::GenericError(format!(
                    "Error getting SSH credentials for DPU: {:?}",
                    err
                )),
            })?;

        let (username, password) = match credentials {
            Credentials::UsernamePassword { username, password } => (username, password),
        };

        // UpdateMachineCredentials only allows a single account currently so warn if it's
        // not the correct one.
        if username != DPU_ADMIN_USERNAME {
            tracing::warn!(
                expected = DPU_ADMIN_USERNAME,
                found = username,
                "Unexpected username in Vault"
            );
        }

        Ok(Response::new(rpc::CredentialResponse {
            username,
            password,
        }))
    }

    // Network status of each managed host, as reported by forge-dpu-agent.
    // For use by forge-admin-cli
    //
    // Currently: Status of HBN on each DPU
    async fn get_all_managed_host_network_status(
        &self,
        request: Request<rpc::ManagedHostNetworkStatusRequest>,
    ) -> Result<Response<rpc::ManagedHostNetworkStatusResponse>, Status> {
        log_request_data(&request);

        let mut txn = self.database_connection.begin().await.map_err(|e| {
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

    async fn admin_reboot(
        &self,
        request: Request<rpc::AdminRebootRequest>,
    ) -> Result<Response<rpc::AdminRebootResponse>, Status> {
        log_request_data(&request);

        let req = request.into_inner();
        let (user, password) = match (req.user, req.password, req.machine_id) {
            // User provided username and password
            (Some(u), Some(p), _) => (u, p),

            // User provided machine_id
            (_, _, Some(machine_id)) => {
                let machine_id = MachineId::from_str(&machine_id).map_err(|_| {
                    CarbideError::from(RpcDataConversionError::InvalidMachineId(machine_id.clone()))
                })?;
                log_machine_id(&machine_id);

                // Load credentials from Vault
                let credentials = self
                    .credential_provider
                    .get_credentials(CredentialKey::Bmc {
                        user_role: UserRoles::Administrator.to_string(),
                        machine_id: machine_id.to_string(),
                    })
                    .await
                    .map_err(|err| match err.downcast::<vaultrs::error::ClientError>() {
                        Ok(vaultrs::error::ClientError::APIError { code: 404, .. }) => {
                            CarbideError::GenericError(format!(
                                "Vault key not found: bmc-metadata-items for machine_id {}",
                                machine_id
                            ))
                        }
                        Ok(ce) => CarbideError::GenericError(format!("Vault error: {}", ce)),
                        Err(err) => CarbideError::GenericError(format!(
                            "Error getting credentials for BMC: {:?}",
                            err
                        )),
                    })?;
                let (username, password) = match credentials {
                    Credentials::UsernamePassword { username, password } => (username, password),
                };
                (username, password)
            }

            _ => {
                return Err(Status::invalid_argument(
                    "Please provider either machine_id, or both user and password",
                ));
            }
        };

        let endpoint = libredfish::Endpoint {
            user: Some(user),
            password: Some(password),
            host: req.ip.clone(),
            // Option<u32> -> Option<u16> because no uint16 in protobuf
            port: req.port.map(|p| p as u16),
        };

        let pool = libredfish::RedfishClientPool::builder()
            .build()
            .map_err(CarbideError::from)?;
        let redfish = pool
            .create_client(endpoint)
            .await
            .map_err(CarbideError::from)?;

        // Lenovo does not have BMC lockdown, so a user could switch the boot order. We need
        // to switch it back. On other vendors the call will fail so ignore errors.
        tracing::info!(ip = req.ip, "Switching boot order");
        let _ = redfish.boot_once(libredfish::Boot::Pxe).await;

        tracing::info!(ip = req.ip, "Force restarting");
        redfish
            .power(libredfish::SystemPowerControl::ForceRestart)
            .await
            .map_err(CarbideError::from)?;
        tracing::info!(ip = req.ip, "Reboot request succeeded");

        Ok(Response::new(rpc::AdminRebootResponse {}))
    }

    async fn get_bmc_meta_data(
        &self,
        request: Request<rpc::BmcMetaDataGetRequest>,
    ) -> Result<Response<rpc::BmcMetaDataGetResponse>, Status> {
        log_request_data(&request);
        let request = BmcMetaDataGetRequest::try_from(request.into_inner())?;
        log_machine_id(&request.machine_id);

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin get_bmc_meta_data",
                e,
            ))
        })?;

        let response = Ok(request
            .get_bmc_meta_data(&mut txn, self.credential_provider.as_ref())
            .await
            .map(Response::new)?);

        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "commit get_bmc_meta_data",
                e,
            ))
        })?;

        response
    }

    async fn update_bmc_meta_data(
        &self,
        request: Request<rpc::BmcMetaDataUpdateRequest>,
    ) -> Result<Response<rpc::BmcMetaDataUpdateResponse>, Status> {
        let Some(bmc_info) = request.get_ref().bmc_info.clone() else {
            return Err(CarbideError::InvalidArgument("Missing BMC Information".to_owned()).into());
        };

        // Note: Be *careful* when logging this request: do not log the password!
        tracing::Span::current().record(
            "request",
            format!(
                "BmcMetadataUpdateRequest machine_id: {:?} ip: {:?} request_type: {:?}",
                request.get_ref().machine_id,
                bmc_info.ip,
                request.get_ref().request_type
            ),
        );

        let request = BmcMetaDataUpdateRequest::try_from(request.into_inner())?;
        log_machine_id(&request.machine_id);

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin update_bmc_meta_data",
                e,
            ))
        })?;

        let response = Ok(request
            .update_bmc_meta_data(&mut txn, self.credential_provider.as_ref())
            .await
            .map(Response::new)?);

        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "commit update_bmc_meta_data",
                e,
            ))
        })?;

        response
    }

    async fn update_machine_credentials(
        &self,
        request: Request<MachineCredentialsUpdateRequest>,
    ) -> Result<Response<MachineCredentialsUpdateResponse>, Status> {
        // Note that we don't log the request here via `log_request_data`.
        // Doing that would make credentials show up in the log stream
        tracing::Span::current().record("request", "MachineCredentialsUpdateRequest { }");

        let request =
            UpdateCredentials::try_from(request.into_inner()).map_err(CarbideError::from)?;
        log_machine_id(&request.machine_id);

        Ok(request
            .update(self.credential_provider.as_ref())
            .await
            .map(Response::new)?)
    }

    // The carbide pxe server makes this RPC call
    async fn get_pxe_instructions(
        &self,
        request: Request<rpc::PxeInstructionRequest>,
    ) -> Result<Response<rpc::PxeInstructions>, Status> {
        log_request_data(&request);

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin get_pxe_instructions",
                e,
            ))
        })?;

        let request = request.into_inner();

        let interface_id = match request.interface_id {
            None => {
                return Err(Status::invalid_argument("Interface ID is missing."));
            }
            Some(interface_id) => Uuid::try_from(interface_id)
                .map_err(|e| Status::invalid_argument(format!("Interface ID is invalid: {}", e)))?,
        };

        let arch = rpc::MachineArchitecture::try_from(request.arch)
            .map_err(|_| Status::invalid_argument("Unknown arch received."))?;
        let pxe_script =
            PxeInstructions::get_pxe_instructions(&mut txn, interface_id, arch).await?;

        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "commit get_pxe_instructions",
                e,
            ))
        })?;

        Ok(Response::new(rpc::PxeInstructions { pxe_script }))
    }

    async fn get_cloud_init_instructions(
        &self,
        request: Request<rpc::CloudInitInstructionsRequest>,
    ) -> Result<Response<rpc::CloudInitInstructions>, Status> {
        log_request_data(&request);
        let cloud_name = "nvidia".to_string();
        let platform = "forge".to_string();

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin get_cloud_init_instructions",
                e,
            ))
        })?;

        let ip_str = &request.into_inner().ip;
        let ip: IpAddr = ip_str
            .parse()
            .map_err(|e| Status::invalid_argument(format!("Failed parsing IP '{ip_str}': {e}")))?;
        if ip.is_ipv6() {
            return Err(CarbideError::GenericError("IPv6 not supported".to_string()).into());
        }

        let instructions = match InstanceAddress::find_by_address(&mut txn, ip)
            .await
            .map_err(CarbideError::from)?
        {
            None => {
                // assume there is no instance associated with this IP and check if there is an interface associated with it
                let machine_interface = MachineInterface::find_by_ip(&mut txn, ip)
                    .await
                    .map_err(CarbideError::from)?
                    .ok_or_else(|| {
                        CarbideError::GenericError(format!(
                            "No machine interface with IP {ip} was found"
                        ))
                    })?;

                let domain_id = machine_interface.domain_id.ok_or_else(|| {
                    CarbideError::GenericError(format!(
                        "Machine Interface did not have an associated domain {}",
                        machine_interface.id
                    ))
                })?;

                let domain = Domain::find(&mut txn, UuidKeyedObjectFilter::One(domain_id))
                    .await
                    .map_err(CarbideError::from)?
                    .first()
                    .ok_or_else(|| {
                        CarbideError::GenericError(format!(
                            "Could not find a domain for {}",
                            domain_id
                        ))
                    })?
                    .to_owned();

                // This custom pxe is different from a customer instance of pxe. It is more for testing one off
                // changes until a real dev env is established and we can just override our existing code to test
                // It is possible for the user data to be null if we are only trying to test the pxe, and this will
                // follow the same code path and retrieve the non custom user data
                let custom_cloud_init =
                    match MachineBootOverride::find_optional(&mut txn, machine_interface.id).await?
                    {
                        Some(machine_boot_override) => machine_boot_override.custom_user_data,
                        None => None,
                    };

                // we update DPU firmware on first boot every time (determined by a missing machine id) or during reprovisioning.
                let update_firmware = match &machine_interface.machine_id {
                    None => self.runtime_config.dpu_nic_firmware_initial_update_enabled,
                    Some(machine_id) => {
                        let machine =
                            Machine::find_one(&mut txn, machine_id, MachineSearchConfig::default())
                                .await
                                .map_err(CarbideError::from)?;

                        if let Some(machine) = machine {
                            if let Some(reprov_state) =
                                machine.current_state().as_reprovision_state()
                            {
                                matches!(reprov_state, ReprovisionState::FirmwareUpgrade,)
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    }
                };

                let metadata: Option<rpc::CloudInitMetaData> = machine_interface
                    .machine_id
                    .as_ref()
                    .map(|machine_id| rpc::CloudInitMetaData {
                        instance_id: machine_id.to_string(),
                        cloud_name,
                        platform,
                    });

                rpc::CloudInitInstructions {
                    custom_cloud_init,
                    discovery_instructions: Some(rpc::CloudInitDiscoveryInstructions {
                        machine_interface: Some(machine_interface.into()),
                        domain: Some(domain.into()),
                        update_firmware,
                    }),
                    metadata,
                }
            }

            Some(instance_address) => {
                let instance = Instance::find_by_id(&mut txn, instance_address.instance_id)
                    .await
                    .map_err(CarbideError::from)?
                    .ok_or_else(|| {
                        // Note that this isn't a NotFound error since it indicates an
                        // inconsistent data model
                        CarbideError::GenericError(format!(
                            "Could not find an instance for {}",
                            instance_address.instance_id
                        ))
                    })?
                    .to_owned();

                let user_data = match instance.os.variant {
                    OperatingSystemVariant::Ipxe(ipxe) => ipxe.user_data,
                };

                rpc::CloudInitInstructions {
                    custom_cloud_init: user_data,
                    discovery_instructions: None,
                    metadata: Some(rpc::CloudInitMetaData {
                        instance_id: instance.id.to_string(),
                        cloud_name,
                        platform,
                    }),
                }
            }
        };

        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "commit get_cloud_init_instructions",
                e,
            ))
        })?;

        Ok(Response::new(instructions))
    }

    async fn get_site_exploration_report(
        &self,
        request: tonic::Request<::rpc::forge::GetSiteExplorationRequest>,
    ) -> Result<Response<::rpc::site_explorer::SiteExplorationReport>, Status> {
        log_request_data(&request);

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin get_site_exploration_report",
                e,
            ))
        })?;

        let report = DbSiteExplorationReport::fetch(&mut txn)
            .await
            .map_err(CarbideError::from)?;

        txn.rollback().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "end get_site_exploration_report",
                e,
            ))
        })?;

        Ok(tonic::Response::new(report.into()))
    }

    // Ad-hoc BMC exploration
    async fn explore(
        &self,
        request: tonic::Request<::rpc::forge::ExploreRequest>,
    ) -> Result<Response<::rpc::site_explorer::EndpointExplorationReport>, Status> {
        log_request_data(&request);
        let req = request.into_inner();
        let address = if req.address.contains(':') {
            req.address.clone()
        } else {
            format!("{}:443", req.address)
        };

        let mut addrs = lookup_host(address).await?;
        let Some(bmc_addr) = addrs.next() else {
            return Err(tonic::Status::invalid_argument(format!(
                "Could not resolve {}. Must be hostname[:port] or IPv4[:port]",
                req.address
            )));
        };

        let maybe_mac = if let Some(mac_str) = req.mac_address {
            let mac = mac_str.parse::<MacAddress>().map_err(CarbideError::from)?;

            let mut txn = self.database_connection.begin().await.map_err(|e| {
                CarbideError::from(DatabaseError::new(
                    file!(),
                    line!(),
                    "begin find_many_by_bmc_mac_address",
                    e,
                ))
            })?;
            let mut expected =
                ExpectedMachine::find_many_by_bmc_mac_address(&mut txn, &[mac]).await?;
            txn.commit().await.map_err(|e| {
                CarbideError::from(DatabaseError::new(
                    file!(),
                    line!(),
                    "commit find_many_by_bmc_mac_address",
                    e,
                ))
            })?;

            expected.remove(&mac)
        } else {
            None
        };

        let explorer = crate::site_explorer::RedfishEndpointExplorer::new(
            self.redfish_pool.clone(),
            self.credential_provider.clone(),
        );
        let report = explorer
            .explore_endpoint(bmc_addr, &Default::default(), maybe_mac, None)
            .await
            .map_err(|e| CarbideError::GenericError(e.to_string()))?;

        Ok(tonic::Response::new(report.into()))
    }

    #[allow(rustdoc::invalid_html_tags)]
    /// Called on x86 boot by 'forge-scout auto-detect --uuid=<uuid>'.
    /// Tells it whether to discover or cleanup based on current machine state.
    async fn forge_agent_control(
        &self,
        request: Request<rpc::ForgeAgentControlRequest>,
    ) -> Result<Response<rpc::ForgeAgentControlResponse>, Status> {
        log_request_data(&request);

        use ::rpc::forge_agent_control_response::Action;

        let machine_id = match request.into_inner().machine_id {
            Some(id) => try_parse_machine_id(&id).map_err(CarbideError::from)?,
            None => {
                tracing::warn!("forge agent control: missing machine ID");
                return Err(Status::invalid_argument("Missing machine ID"));
            }
        };
        log_machine_id(&machine_id);

        let (machine, mut txn) = self
            .load_machine(&machine_id, MachineSearchConfig::default())
            .await?;

        // Treat this message as signal from machine that reboot is finished. Update reboot time.
        machine
            .update_reboot_time(&mut txn)
            .await
            .map_err(CarbideError::from)?;

        let is_dpu = machine.is_dpu();
        let host_machine = if !is_dpu {
            machine.clone()
        } else {
            Machine::find_host_by_dpu_machine_id(&mut txn, &machine_id)
                .await?
                .ok_or(CarbideError::NotFoundError {
                    kind: "machine",
                    id: machine_id.to_string(),
                })?
        };

        // Respond based on machine current state
        let state = host_machine.current_state();
        let action = if is_dpu {
            match state {
                ManagedHostState::DPUReprovision {
                    reprovision_state: ReprovisionState::BufferTime,
                } => Action::Retry,
                ManagedHostState::DPUNotReady {
                    machine_state: MachineState::Init,
                }
                | ManagedHostState::DPUReprovision {
                    reprovision_state: ReprovisionState::WaitingForNetworkInstall,
                }
                | ManagedHostState::Assigned {
                    instance_state:
                        InstanceState::DPUReprovision {
                            reprovision_state: ReprovisionState::WaitingForNetworkInstall,
                        },
                } => Action::Discovery,
                _ => {
                    // Later this might go to site admin dashboard for manual intervention
                    tracing::info!(
                        machine_id = %machine.id(),
                        machine_type = "DPU",
                        %state,
                        "forge agent control",
                    );
                    Action::Noop
                }
            }
        } else {
            match state {
                ManagedHostState::HostNotReady {
                    machine_state: MachineState::Init,
                } => Action::Retry,
                ManagedHostState::HostNotReady {
                    machine_state: MachineState::WaitingForDiscovery,
                }
                | ManagedHostState::Failed {
                    details:
                        FailureDetails {
                            cause: FailureCause::Discovery { .. },
                            ..
                        },
                    ..
                } => Action::Discovery,
                // If the API is configured with attestation_enabled, and
                // the machine has been Discovered (and progressed on to the
                // point where it is WaitingForMeasurements), then let Scout (or
                // whoever the caller is) know that it's time for measurements
                // to be sent.
                ManagedHostState::Measuring {
                    measuring_state: MeasuringState::WaitingForMeasurements,
                } => Action::Measure,
                ManagedHostState::WaitingForCleanup { .. }
                | ManagedHostState::Failed {
                    details:
                        FailureDetails {
                            cause: FailureCause::NVMECleanFailed { .. },
                            ..
                        },
                    ..
                } => Action::Reset,
                _ => {
                    // Later this might go to site admin dashboard for manual intervention
                    tracing::info!(
                        machine_id = %machine.id(),
                        machine_type = "Host",
                        %state,
                        "forge agent control",
                    );
                    Action::Noop
                }
            }
        };
        tracing::info!(
            machine_id = %machine.id(),
            action = action.as_str_name(),
            "forge agent control",
        );
        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "commit forge_agent_control",
                e,
            ))
        })?;
        Ok(Response::new(rpc::ForgeAgentControlResponse {
            action: action as i32,
        }))
    }

    async fn admin_force_delete_machine(
        &self,
        request: Request<rpc::AdminForceDeleteMachineRequest>,
    ) -> Result<Response<rpc::AdminForceDeleteMachineResponse>, Status> {
        log_request_data(&request);

        let request = request.into_inner();
        let query = request.host_query;

        let mut response = rpc::AdminForceDeleteMachineResponse {
            all_done: true,
            ..Default::default()
        };
        // This is the default
        // If we can't delete something in one go - we will reset it
        response.all_done = true;
        response.initial_lockdown_state = "".to_string();
        response.machine_unlocked = false;

        tracing::info!("admin_force_delete_machine query='{query}'");

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin investigate admin_force_delete_machine",
                e,
            ))
        })?;

        let machine = match Machine::find_by_query(&mut txn, &query)
            .await
            .map_err(CarbideError::from)?
        {
            Some(machine) => machine,
            None => {
                // If the machine was already deleted, then there is nothing to do
                // and this is a success
                return Ok(Response::new(response));
            }
        };
        log_machine_id(machine.id());

        // TODO: This should maybe just use the snapshot loading functionality that the
        // state controller will use - which already contains the combined state
        let host_machine;
        let dpu_machines;
        if machine.is_dpu() {
            if let Some(host) = Machine::find_host_by_dpu_machine_id(&mut txn, machine.id()).await?
            {
                tracing::info!("Found host Machine {:?}", machine.id().to_string());
                // Get all DPUs attached to this host, in case there are more than one.
                dpu_machines = Machine::find_dpus_by_host_machine_id(&mut txn, host.id())
                    .await
                    .map_err(CarbideError::from)?;
                host_machine = Some(host);
            } else {
                host_machine = None;
                dpu_machines = vec![];
            }
        } else {
            dpu_machines = Machine::find_dpus_by_host_machine_id(&mut txn, machine.id())
                .await
                .map_err(CarbideError::from)?;
            tracing::info!(
                "Found dpu Machines {:?}",
                dpu_machines.iter().map(|m| m.id().to_string()).join(", ")
            );
            host_machine = Some(machine);
        }

        let mut instance_id = None;
        if let Some(host_machine) = &host_machine {
            instance_id = Instance::find_id_by_machine_id(&mut txn, host_machine.id())
                .await
                .map_err(CarbideError::from)?;
        }

        if let Some(host_machine) = &host_machine {
            response.managed_host_machine_id = host_machine.id().to_string();
            if let Some(iface) = host_machine.interfaces().first() {
                response.managed_host_machine_interface_id = iface.id().to_string();
            }
            if let Some(ip) = host_machine.bmc_info().ip.as_ref() {
                response.managed_host_bmc_ip = ip.to_string();
            }
        }
        if let Some(dpu_machine) = dpu_machines.first() {
            response.dpu_machine_ids = dpu_machines.iter().map(|m| m.id().to_string()).collect();
            // deprecated field:
            response.dpu_machine_id = dpu_machine.id().to_string();

            let dpu_interfaces = dpu_machines
                .iter()
                .flat_map(|m| m.interfaces().clone())
                .collect::<Vec<_>>();
            if let Some(iface) = dpu_interfaces.first() {
                response.dpu_machine_interface_ids =
                    dpu_interfaces.iter().map(|i| i.id().to_string()).collect();
                // deprecated field:
                response.dpu_machine_interface_id = iface.id().to_string();
            }
            if let Some(ip) = dpu_machine.bmc_info().ip.as_ref() {
                response.dpu_bmc_ip = ip.to_string();
            }
        }
        if let Some(instance_id) = &instance_id {
            response.instance_id = instance_id.to_string();
        }

        // So far we only inspected state - now we start the deletion process
        // TODO: In the new model we might just need to move one Machine to this state
        if let Some(host_machine) = &host_machine {
            host_machine
                .advance(&mut txn, ManagedHostState::ForceDeletion, None)
                .await
                .map_err(CarbideError::from)?;
        }
        for dpu_machine in dpu_machines.iter() {
            dpu_machine
                .advance(&mut txn, ManagedHostState::ForceDeletion, None)
                .await
                .map_err(CarbideError::from)?;
        }

        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "commit admin_force_delete_machine",
                e,
            ))
        })?;

        // We start a new transaction
        // This makeas the ForceDeletion state visible to other consumers

        // Note: The following deletion steps are all ordered in an idempotent fashion

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin delete host and instance in admin_force_delete_machine",
                e,
            ))
        })?;

        if let Some(instance_id) = instance_id {
            let instance = Instance::find_by_id(&mut txn, instance_id)
                .await
                .map_err(CarbideError::from)?
                .ok_or_else(|| {
                    CarbideError::GenericError(format!(
                        "Could not find an instance for {}",
                        instance_id
                    ))
                })?
                .to_owned();

            let ib_fabric = self
                .ib_fabric_manager
                .connect(DEFAULT_IB_FABRIC_NAME)
                .await?;

            // Collect the ib partition and ib ports information about this machine
            let mut ib_config_map: HashMap<Uuid, Vec<String>> = HashMap::new();
            let infiniband = instance.ib_config.value.ib_interfaces;
            for ib in &infiniband {
                let ib_partition_id = ib.ib_partition_id;
                if let Some(guid) = ib.guid.as_deref() {
                    ib_config_map
                        .entry(ib_partition_id)
                        .or_default()
                        .push(guid.to_string());
                }
            }

            response.ufm_unregistaration_pending = true;
            // unbind ib ports from UFM
            for (ib_partition_id, guids) in ib_config_map.iter() {
                if let Some(pkey) =
                    IBPartition::find_pkey_by_partition_id(&mut txn, *ib_partition_id)
                        .await
                        .map_err(CarbideError::from)?
                {
                    ib_fabric
                        .unbind_ib_ports(pkey.into(), guids.to_vec())
                        .await?;
                    response.ufm_unregistrations += 1;

                    //TODO: release VF GUID resource when VF supported.
                }
            }
            response.ufm_unregistaration_pending = false;

            // Delete the instance and allocated address
            // TODO: This might need some changes with the new state machine
            let delete_instance = DeleteInstance { instance_id };
            let _instance = delete_instance.delete(&mut txn).await?;
        }

        if let Some(machine) = &host_machine {
            if let Some(ip) = machine.bmc_info().ip.as_deref() {
                tracing::info!(
                    ip,
                    machine_id = %machine.id(),
                    "BMC ip for machine was found. Trying to perform Bios unlock",
                );

                match self
                    .redfish_pool
                    .create_client(
                        ip,
                        machine.bmc_info().port,
                        RedfishAuth::Key(CredentialKey::Bmc {
                            machine_id: machine.id().to_string(),
                            user_role: UserRoles::Administrator.to_string(),
                        }),
                        true,
                    )
                    .await
                {
                    Ok(client) => {
                        let machine_id = machine.id().clone();
                        match client.lockdown_status().await {
                            Ok(status) if status.is_fully_disabled() => {
                                tracing::info!(%machine_id, "Bios is not locked down");
                                response.initial_lockdown_state = status.to_string();
                                response.machine_unlocked = false;
                            }
                            Ok(status) => {
                                tracing::info!(%machine_id, ?status, "Unlocking BIOS");
                                if let Err(e) =
                                    client.lockdown(libredfish::EnabledDisabled::Disabled).await
                                {
                                    tracing::warn!(%machine_id, error = %e, "Failed to unlock");
                                    response.initial_lockdown_state = status.to_string();
                                    response.machine_unlocked = false;
                                } else {
                                    response.initial_lockdown_state = status.to_string();
                                    response.machine_unlocked = true;
                                }
                            }
                            Err(e) => {
                                tracing::warn!(%machine_id, error = %e, "Failed to fetch lockdown status");
                                response.initial_lockdown_state = "".to_string();
                                response.machine_unlocked = false;
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            machine_id = %machine.id(),
                            error = %e,
                            "Failed to create Redfish client. Skipping bios unlock",
                        );
                    }
                }
            }
        }

        if let Some(machine) = &host_machine {
            if request.delete_bmc_interfaces {
                if let Some(bmc_ip) = &machine.bmc_info().ip {
                    response.host_bmc_interface_associated = true;
                    if let Ok(ip_addr) = IpAddr::from_str(bmc_ip) {
                        if MachineInterface::delete_by_ip(&mut txn, ip_addr)
                            .await
                            .map_err(CarbideError::from)?
                            .is_some()
                        {
                            response.host_bmc_interface_deleted = true;
                        }
                    }
                }
            }
            Machine::force_cleanup(&mut txn, machine.id())
                .await
                .map_err(CarbideError::from)?;

            if request.delete_interfaces {
                for interface in machine.interfaces() {
                    interface
                        .delete(&mut txn)
                        .await
                        .map_err(CarbideError::from)?;
                }
                response.host_interfaces_deleted = true;
            }
        }

        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "end delete host and instance in admin_force_delete_machine",
                e,
            ))
        })?;

        for dpu_machine in dpu_machines.iter() {
            let mut txn = self.database_connection.begin().await.map_err(|e| {
                CarbideError::from(DatabaseError::new(
                    file!(),
                    line!(),
                    "begin delete dpu in admin_force_delete_machine",
                    e,
                ))
            })?;

            if let Some(loopback_ip) = dpu_machine.loopback_ip() {
                self.common_pools
                    .ethernet
                    .pool_loopback_ip
                    .release(&mut txn, loopback_ip)
                    .await
                    .map_err(CarbideError::from)?
            }
            DpuToNetworkDeviceMap::delete(&mut txn, dpu_machine.id())
                .await
                .map_err(CarbideError::from)?;

            if request.delete_bmc_interfaces {
                if let Some(bmc_ip) = &dpu_machine.bmc_info().ip {
                    response.dpu_bmc_interface_associated = true;
                    if let Ok(ip_addr) = IpAddr::from_str(bmc_ip) {
                        if MachineInterface::delete_by_ip(&mut txn, ip_addr)
                            .await
                            .map_err(CarbideError::from)?
                            .is_some()
                        {
                            response.dpu_bmc_interface_deleted = true;
                        }
                    }
                }
            }

            Machine::force_cleanup(&mut txn, dpu_machine.id())
                .await
                .map_err(CarbideError::from)?;

            if request.delete_interfaces {
                for interface in dpu_machine.interfaces() {
                    interface
                        .delete(&mut txn)
                        .await
                        .map_err(CarbideError::from)?;
                }
                response.dpu_interfaces_deleted = true;
            }
            txn.commit().await.map_err(|e| {
                CarbideError::from(DatabaseError::new(
                    file!(),
                    line!(),
                    "end delete dpu in admin_force_delete_machine",
                    e,
                ))
            })?;
        }

        Ok(Response::new(response))
    }

    /// Example TOML data in request.text:
    ///
    /// [lo-ip]
    /// type = "ipv4"
    /// prefix = "10.180.62.1/26"
    ///
    /// or
    ///
    /// [vlan-id]
    /// type = "integer"
    /// ranges = [{ start = "100", end = "501" }]
    ///
    async fn admin_grow_resource_pool(
        &self,
        request: Request<rpc::GrowResourcePoolRequest>,
    ) -> Result<Response<rpc::GrowResourcePoolResponse>, Status> {
        crate::handlers::resource_pool::grow(self, request).await
    }

    async fn admin_list_resource_pools(
        &self,
        request: Request<rpc::ListResourcePoolsRequest>,
    ) -> Result<tonic::Response<rpc::ResourcePools>, tonic::Status> {
        crate::handlers::resource_pool::list(self, request).await
    }

    /// Maintenance mode: Put a machine into maintenance mode or take it out.
    /// Switching a host into maintenance mode prevents an instance being assigned to it.
    async fn set_maintenance(
        &self,
        request: tonic::Request<rpc::MaintenanceRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        log_request_data(&request);
        let req = request.into_inner();

        let machine_id = match &req.host_id {
            Some(id) => try_parse_machine_id(id).map_err(CarbideError::from)?,
            None => {
                tracing::warn!("forge agent control: missing host ID");
                return Err(Status::invalid_argument("Missing host ID"));
            }
        };
        log_machine_id(&machine_id);

        let (host_machine, mut txn) = self
            .load_machine(&machine_id, MachineSearchConfig::default())
            .await?;
        if host_machine.is_dpu() {
            return Err(Status::invalid_argument(
                "DPU ID provided. Need managed host.",
            ));
        }
        let dpu_machines = Machine::find_dpus_by_host_machine_id(&mut txn, &machine_id)
            .await
            .map_err(CarbideError::from)?;

        // We set status on both host and dpu machine to make them easier to query from DB
        let mode = match req.operation() {
            rpc::MaintenanceOperation::Enable => {
                let Some(reference) = req.reference else {
                    return Err(Status::invalid_argument(
                        "Missing reference url".to_string(),
                    ));
                };

                let reference = reference.trim().to_string();
                if reference.len() < 5 {
                    return Err(Status::invalid_argument(
                        "Provide some valid reference. Minimum expected length is 5.".to_string(),
                    ));
                }

                MaintenanceMode::On { reference }
            }
            rpc::MaintenanceOperation::Disable => {
                for dpu_machine in dpu_machines.iter() {
                    if dpu_machine.reprovisioning_requested().is_some() {
                        return Err(Status::invalid_argument(format!(
                            "Reprovisioning request is set on DPU: {}. Clear it first.",
                            dpu_machine.id()
                        )));
                    }
                }
                MaintenanceMode::Off
            }
        };

        Machine::set_maintenance_mode(&mut txn, host_machine.id(), &mode)
            .await
            .map_err(CarbideError::from)?;

        for dpu_machine in &dpu_machines {
            Machine::set_maintenance_mode(&mut txn, dpu_machine.id(), &mode)
                .await
                .map_err(CarbideError::from)?;
        }

        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "end maintenance handler",
                e,
            ))
        })?;

        Ok(Response::new(()))
    }

    async fn find_ip_address(
        &self,
        request: tonic::Request<rpc::FindIpAddressRequest>,
    ) -> Result<tonic::Response<rpc::FindIpAddressResponse>, tonic::Status> {
        log_request_data(&request);
        let req = request.into_inner();

        let ip = req.ip;
        let (matches, errors) = ip_finder::find(self, &ip).await;
        if matches.is_empty() && errors.is_empty() {
            return Err(CarbideError::NotFoundError {
                kind: "ip",
                id: ip.to_string(),
            }
            .into());
        }
        Ok(Response::new(rpc::FindIpAddressResponse {
            matches,
            errors: errors.into_iter().map(|err| err.to_string()).collect(),
        }))
    }

    /// Trigger DPU reset.

    // This is temporary command added to support MC team. It must be removed once site-explorer
    // is enabled on all the envs. This command modifies state directly, which can cause conflicts
    // with state machine.
    async fn trigger_dpu_reset(
        &self,
        request: tonic::Request<rpc::DpuResetRequest>,
    ) -> Result<tonic::Response<rpc::DpuResetResponse>, tonic::Status> {
        log_request_data(&request);
        let req = request.into_inner();

        let dpu_id = try_parse_machine_id(
            req.dpu_id
                .as_ref()
                .ok_or_else(|| Status::invalid_argument("DPU ID is missing"))?,
        )
        .map_err(CarbideError::from)?;

        log_machine_id(&dpu_id);
        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin trigger_dpu_reset ",
                e,
            ))
        })?;

        let dpu = Machine::find_one(
            &mut txn,
            &dpu_id,
            MachineSearchConfig {
                include_dpus: true,
                ..MachineSearchConfig::default()
            },
        )
        .await
        .map_err(CarbideError::from)?
        .ok_or_else(|| Status::not_found(format!("DPU not found with machine id: {dpu_id}")))?;

        if !dpu.machine_type().is_dpu() {
            return Err(Status::invalid_argument("Only DPU id is expected."));
        }

        let host = Machine::find_host_by_dpu_machine_id(&mut txn, &dpu_id)
            .await
            .map_err(CarbideError::from)?
            .ok_or_else(|| {
                Status::not_found(format!("Host not found attached with dpu id: {dpu_id}"))
            })?;

        let state = ManagedHostState::DPUNotReady {
            machine_state: MachineState::Init,
        };

        let mut message = "Success";

        match dpu.current_state() {
            ManagedHostState::DPUNotReady { .. } => {
                MachineTopology::set_topology_update_needed(&mut txn, &dpu_id, true)
                    .await
                    .map_err(CarbideError::from)?;
                dpu.advance(&mut txn, state.clone(), None)
                    .await
                    .map_err(CarbideError::from)?;
                host.advance(&mut txn, state, None)
                    .await
                    .map_err(CarbideError::from)?;

                if let Some(ip) = dpu.bmc_info().ip.as_ref() {
                    self.ipmi_tool
                        .restart(&dpu_id, ip.to_string(), true)
                        .await
                        .map_err(|e: eyre::ErrReport| {
                            CarbideError::GenericError(format!("Failed to restart DPU: {}", e))
                        })?;
                } else {
                    message = "Can't fetch BMC IP. Reboot DPU manually to continue."
                }
            }
            _ => {
                return Err(Status::invalid_argument("DPU state is not DPUInit."));
            }
        }

        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "end trigger_dpu_reset",
                e,
            ))
        })?;

        Ok(Response::new(rpc::DpuResetResponse {
            msg: message.to_string(),
        }))
    }

    /// Trigger DPU reprovisioning
    async fn trigger_dpu_reprovisioning(
        &self,
        request: tonic::Request<rpc::DpuReprovisioningRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        log_request_data(&request);
        let req = request.into_inner();

        let dpu_id = try_parse_machine_id(
            req.dpu_id
                .as_ref()
                .ok_or_else(|| Status::invalid_argument("DPU ID is missing"))?,
        )
        .map_err(CarbideError::from)?;

        log_machine_id(&dpu_id);
        if !dpu_id.machine_type().is_dpu() {
            return Err(Status::invalid_argument(
                "Only DPU reprovisioning is supported.",
            ));
        }

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin trigger_dpu_reprovisioning ",
                e,
            ))
        })?;

        let machine = Machine::find_one(&mut txn, &dpu_id, MachineSearchConfig::default())
            .await
            .map_err(CarbideError::from)?;

        let machine = machine.ok_or(CarbideError::NotFoundError {
            kind: "dpu",
            id: dpu_id.to_string(),
        })?;

        // Start reprovisioning only machine is in maintenance mode.
        if !machine.is_maintenance_mode() {
            return Err(Status::invalid_argument(
                "Machine is not in maintenance mode. Set it first.",
            ));
        }

        if machine
            .reprovisioning_requested()
            .is_some_and(|r| r.started_at.is_some())
        {
            match req.mode() {
                rpc::dpu_reprovisioning_request::Mode::Restart => {}
                _ => {
                    return Err(CarbideError::GenericError(
                        "Reprovisioning is already started.".to_string(),
                    )
                    .into());
                }
            }
        }

        if let rpc::dpu_reprovisioning_request::Mode::Set = req.mode() {
            let initiator = req.initiator().as_str_name();
            machine
                .trigger_dpu_reprovisioning_request(&mut txn, initiator, req.update_firmware)
                .await
                .map_err(CarbideError::from)?;
        } else {
            let Some(_reprov_requested) = machine.reprovisioning_requested() else {
                return Err(CarbideError::NotFoundError {
                    kind: "Reprovision Request",
                    id: dpu_id.to_string(),
                }
                .into());
            };
            if let rpc::dpu_reprovisioning_request::Mode::Clear = req.mode() {
                Machine::clear_dpu_reprovisioning_request(&mut txn, &dpu_id, true)
                    .await
                    .map_err(CarbideError::from)?;
            } else if machine.reprovisioning_requested().is_some() {
                Machine::restart_dpu_reprovisioning(&mut txn, &dpu_id, req.update_firmware)
                    .await
                    .map_err(CarbideError::from)?;
            } else {
                return Err(CarbideError::InvalidArgument(format!(
                    "No reprovision is requested for DPU {}.",
                    dpu_id
                ))
                .into());
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

    /// List DPUs waiting for reprovisioning
    async fn list_dpu_waiting_for_reprovisioning(
        &self,
        request: tonic::Request<rpc::DpuReprovisioningListRequest>,
    ) -> Result<tonic::Response<rpc::DpuReprovisioningListResponse>, tonic::Status> {
        log_request_data(&request);

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin trigger_dpu_reprovisioning ",
                e,
            ))
        })?;

        let dpus = Machine::list_machines_requested_for_reprovisioning(&mut txn)
            .await
            .map_err(CarbideError::from)?
            .into_iter()
            .map(
                |x| rpc::dpu_reprovisioning_list_response::DpuReprovisioningListItem {
                    id: Some(rpc::MachineId {
                        id: x.id().to_string(),
                    }),
                    state: x.current_state().to_string(),
                    requested_at: x.reprovisioning_requested().map(|a| a.requested_at.into()),
                    initiator: x
                        .reprovisioning_requested()
                        .map(|a| a.initiator)
                        .unwrap_or_default(),
                    update_firmware: x
                        .reprovisioning_requested()
                        .map(|a| a.update_firmware)
                        .unwrap_or_default(),
                    initiated_at: x
                        .reprovisioning_requested()
                        .map(|a| a.started_at.map(|x| x.into()))
                        .unwrap_or_default(),
                    user_approval_received: x
                        .reprovisioning_requested()
                        .map(|x| x.user_approval_received)
                        .unwrap_or_default(),
                },
            )
            .collect_vec();

        Ok(Response::new(rpc::DpuReprovisioningListResponse { dpus }))
    }

    async fn get_machine_boot_override(
        &self,
        request: tonic::Request<rpc::Uuid>,
    ) -> Result<tonic::Response<rpc::MachineBootOverride>, tonic::Status> {
        crate::handlers::boot_override::get(self, request).await
    }

    async fn set_machine_boot_override(
        &self,
        request: tonic::Request<rpc::MachineBootOverride>,
    ) -> Result<tonic::Response<()>, Status> {
        crate::handlers::boot_override::set(self, request).await
    }

    async fn clear_machine_boot_override(
        &self,
        request: tonic::Request<rpc::Uuid>,
    ) -> Result<tonic::Response<()>, Status> {
        crate::handlers::boot_override::clear(self, request).await
    }

    async fn get_network_topology(
        &self,
        request: tonic::Request<rpc::NetworkTopologyRequest>,
    ) -> Result<tonic::Response<rpc::NetworkTopologyData>, tonic::Status> {
        log_request_data(&request);
        let req = request.into_inner();

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin get_lldp_topology ",
                e,
            ))
        })?;

        let query = match &req.id {
            Some(x) => ObjectFilter::One(x.as_str()),
            None => ObjectFilter::All,
        };

        let data = NetworkTopologyData::get_topology(&mut txn, query)
            .await
            .map_err(CarbideError::from)?;

        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "end get_lldp_topology handler",
                e,
            ))
        })?;

        Ok(Response::new(data.into()))
    }

    async fn admin_bmc_reset(
        &self,
        request: tonic::Request<rpc::AdminBmcResetRequest>,
    ) -> Result<tonic::Response<rpc::AdminBmcResetResponse>, tonic::Status> {
        log_request_data(&request);

        let req = request.into_inner();
        let (user, password) = match (req.user, req.password, req.machine_id) {
            // User provided username and password
            (Some(u), Some(p), _) => (u, p),

            // User provided machine_id
            (_, _, Some(machine_id)) => {
                let machine_id = MachineId::from_str(&machine_id).map_err(|_| {
                    CarbideError::from(RpcDataConversionError::InvalidMachineId(machine_id.clone()))
                })?;
                log_machine_id(&machine_id);

                // Load credentials from Vault
                let credentials = self
                    .credential_provider
                    .get_credentials(CredentialKey::Bmc {
                        user_role: UserRoles::Administrator.to_string(),
                        machine_id: machine_id.to_string(),
                    })
                    .await
                    .map_err(|err| match err.downcast::<vaultrs::error::ClientError>() {
                        Ok(vaultrs::error::ClientError::APIError { code: 404, .. }) => {
                            CarbideError::GenericError(format!(
                                "Vault key not found: bmc-metadata-items for machine_id {machine_id}"
                            ))
                        }
                        Ok(ce) => CarbideError::GenericError(format!("Vault error: {}", ce)),
                        Err(err) => CarbideError::GenericError(format!(
                            "Error getting credentials for BMC: {err:?}"
                        )),
                    })?;
                let (username, password) = match credentials {
                    Credentials::UsernamePassword { username, password } => (username, password),
                };
                (username, password)
            }

            _ => {
                return Err(Status::invalid_argument(
                    "Please provider either machine_id, or both user and password",
                ));
            }
        };

        let endpoint = libredfish::Endpoint {
            user: Some(user),
            password: Some(password),
            host: req.ip.clone(),
            // Option<u32> -> Option<u16> because no uint16 in protobuf
            port: req.port.map(|p| p as u16),
        };

        let pool = libredfish::RedfishClientPool::builder()
            .build()
            .map_err(CarbideError::from)?;
        let redfish = pool
            .create_client(endpoint)
            .await
            .map_err(CarbideError::from)?;
        tracing::info!(ip = req.ip, "BMC reseting");
        redfish.bmc_reset().await.map_err(CarbideError::from)?;
        tracing::info!(ip = req.ip, "Reset request succeeded");

        Ok(Response::new(rpc::AdminBmcResetResponse {}))
    }

    /// Should this DPU upgrade it's forge-dpu-agent?
    /// Once the upgrade is complete record_dpu_network_status will receive the updated
    /// version and write the DB to say our upgrade is complete.
    async fn dpu_agent_upgrade_check(
        &self,
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

        let mut txn = self.database_connection.begin().await.map_err(|e| {
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
    async fn dpu_agent_upgrade_policy_action(
        &self,
        request: tonic::Request<rpc::DpuAgentUpgradePolicyRequest>,
    ) -> Result<tonic::Response<rpc::DpuAgentUpgradePolicyResponse>, Status> {
        log_request_data(&request);
        let mut txn = self.database_connection.begin().await.map_err(|e| {
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

    async fn create_credential(
        &self,
        request: tonic::Request<rpc::CredentialCreationRequest>,
    ) -> Result<tonic::Response<rpc::CredentialCreationResult>, tonic::Status> {
        log_request_data(&request);
        let req = request.into_inner();
        let password = req.password;

        let credential_type = rpc::CredentialType::try_from(req.credential_type).map_err(|_| {
            CarbideError::NotFoundError {
                kind: "credential_type",
                id: req.credential_type.to_string(),
            }
        })?;

        match credential_type {
            rpc::CredentialType::HostBmc => {
                if (self
                    .credential_provider
                    .get_credentials(CredentialKey::HostRedfish {
                        credential_type: CredentialType::SiteDefault,
                    })
                    .await)
                    .is_ok()
                {
                    // TODO: support reset credential
                    return Err(tonic::Status::already_exists(
                        "Not support to reset host BMC credential",
                    ));
                }

                self.credential_provider
                    .set_credentials(
                        CredentialKey::HostRedfish {
                            credential_type: CredentialType::SiteDefault,
                        },
                        Credentials::UsernamePassword {
                            username: FORGE_SITE_WIDE_BMC_USERNAME.to_string(),
                            password: password.clone(),
                        },
                    )
                    .await
                    .map_err(|e| {
                        CarbideError::GenericError(format!(
                            "Error setting credential for Host Bmc: {:?} ",
                            e
                        ))
                    })?
            }
            rpc::CredentialType::Dpubmc => {
                if (self
                    .credential_provider
                    .get_credentials(CredentialKey::DpuRedfish {
                        credential_type: CredentialType::SiteDefault,
                    })
                    .await)
                    .is_ok()
                {
                    // TODO: support reset credential
                    return Err(tonic::Status::already_exists(
                        "Not support to reset DPU BMC credential",
                    ));
                }
                self.credential_provider
                    .set_credentials(
                        CredentialKey::DpuRedfish {
                            credential_type: CredentialType::SiteDefault,
                        },
                        Credentials::UsernamePassword {
                            username: FORGE_SITE_WIDE_BMC_USERNAME.to_string(),
                            password: password.clone(),
                        },
                    )
                    .await
                    .map_err(|e| {
                        CarbideError::GenericError(format!(
                            "Error setting credential for DPU Bmc: {:?} ",
                            e
                        ))
                    })?
            }
            rpc::CredentialType::Ufm => {
                if let Some(username) = req.username {
                    self.credential_provider
                        .set_credentials(
                            CredentialKey::UfmAuth {
                                fabric: DEFAULT_IB_FABRIC_NAME.to_string(),
                            },
                            Credentials::UsernamePassword {
                                username: username.clone(),
                                password: password.clone(),
                            },
                        )
                        .await
                        .map_err(|e| {
                            CarbideError::GenericError(format!(
                                "Error setting credential for Ufm {}: {:?} ",
                                username.clone(),
                                e
                            ))
                        })?;
                } else {
                    return Err(tonic::Status::invalid_argument("missing UFM Url"));
                }
            }
            rpc::CredentialType::DpuUefi => {
                if (self
                    .credential_provider
                    .get_credentials(CredentialKey::DpuUefi {
                        credential_type: CredentialType::SiteDefault,
                    })
                    .await)
                    .is_ok()
                {
                    // TODO: support reset credential
                    return Err(tonic::Status::already_exists(
                        "Not support to reset DPU UEFI credential",
                    ));
                }
                self.credential_provider
                    .set_credentials(
                        CredentialKey::DpuUefi {
                            credential_type: CredentialType::SiteDefault,
                        },
                        Credentials::UsernamePassword {
                            username: "".to_string(),
                            password: password.clone(),
                        },
                    )
                    .await
                    .map_err(|e| {
                        CarbideError::GenericError(format!(
                            "Error setting credential for DPU UEFI: {:?} ",
                            e
                        ))
                    })?
            }
            rpc::CredentialType::HostUefi => {
                if self
                    .credential_provider
                    .get_credentials(CredentialKey::HostUefi {
                        credential_type: CredentialType::SiteDefault,
                    })
                    .await
                    .is_ok()
                {
                    // TODO: support reset credential
                    return Err(tonic::Status::already_exists(
                        "Resetting the Host UEFI credentials in Vault is not supported",
                    ));
                }
                self.credential_provider
                    .set_credentials(
                        CredentialKey::HostUefi {
                            credential_type: CredentialType::SiteDefault,
                        },
                        Credentials::UsernamePassword {
                            username: "".to_string(),
                            password: password.clone(),
                        },
                    )
                    .await
                    .map_err(|e| {
                        CarbideError::GenericError(format!(
                            "Error setting credential for Host UEFI: {e:?}"
                        ))
                    })?
            }
            rpc::CredentialType::HostBmcFactoryDefault => {
                let Some(username) = req.username else {
                    return Err(tonic::Status::invalid_argument("missing username"));
                };
                let Some(vendor) = req.vendor else {
                    return Err(tonic::Status::invalid_argument("missing vendor"));
                };
                let vendor: bmc_vendor::BMCVendor = vendor.as_str().into();
                self.credential_provider
                    .set_credentials(
                        CredentialKey::HostRedfish {
                            credential_type: CredentialType::HostHardwareDefault { vendor },
                        },
                        Credentials::UsernamePassword { username, password },
                    )
                    .await
                    .map_err(|e| {
                        CarbideError::GenericError(format!(
                            "Error setting Host factory default credential: {e:?}"
                        ))
                    })?
            }
            rpc::CredentialType::DpuBmcFactoryDefault => {
                let Some(username) = req.username else {
                    return Err(tonic::Status::invalid_argument("missing username"));
                };
                self.credential_provider
                    .set_credentials(
                        CredentialKey::DpuRedfish {
                            credential_type: CredentialType::DpuHardwareDefault,
                        },
                        Credentials::UsernamePassword { username, password },
                    )
                    .await
                    .map_err(|e| {
                        CarbideError::GenericError(format!(
                            "Error setting DPU factory default credential: {e:?}"
                        ))
                    })?
            }
        };

        Ok(Response::new(rpc::CredentialCreationResult {}))
    }

    async fn delete_credential(
        &self,
        request: tonic::Request<rpc::CredentialDeletionRequest>,
    ) -> Result<tonic::Response<rpc::CredentialDeletionResult>, tonic::Status> {
        log_request_data(&request);
        let req = request.into_inner();

        let credential_type = rpc::CredentialType::try_from(req.credential_type).map_err(|_| {
            CarbideError::NotFoundError {
                kind: "credential_type",
                id: req.credential_type.to_string(),
            }
        })?;

        match credential_type {
            rpc::CredentialType::Ufm => {
                if let Some(username) = req.username {
                    self.credential_provider
                        .set_credentials(
                            CredentialKey::UfmAuth {
                                fabric: DEFAULT_IB_FABRIC_NAME.to_string(),
                            },
                            Credentials::UsernamePassword {
                                username: username.clone(),
                                password: "".to_string(),
                            },
                        )
                        .await
                        .map_err(|e| {
                            CarbideError::GenericError(format!(
                                "Error deleting credential for Ufm {}: {:?} ",
                                username.clone(),
                                e
                            ))
                        })?;
                } else {
                    return Err(tonic::Status::invalid_argument("missing UFM Url"));
                }
            }
            rpc::CredentialType::HostBmc
            | rpc::CredentialType::Dpubmc
            | rpc::CredentialType::DpuUefi
            | rpc::CredentialType::HostUefi
            | rpc::CredentialType::HostBmcFactoryDefault
            | rpc::CredentialType::DpuBmcFactoryDefault => {
                // Not support delete credential for these types
            }
        };

        Ok(Response::new(rpc::CredentialDeletionResult {}))
    }

    /// Returns a list of all configured route server addresses
    async fn get_route_servers(
        &self,
        request: tonic::Request<()>,
    ) -> Result<tonic::Response<rpc::RouteServers>, Status> {
        log_request_data(&request);

        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(|e| {
                CarbideError::from(DatabaseError::new(
                    file!(),
                    line!(),
                    "begin get_route_servers",
                    e,
                ))
            })
            .map_err(CarbideError::from)?;

        let route_servers = RouteServer::get(&mut txn).await?;

        Ok(tonic::Response::new(rpc::RouteServers {
            route_servers: route_servers
                .into_iter()
                .map(|rs| rs.address.to_string())
                .collect(),
        }))
    }

    /// Overwrites all existing route server entries with the provided list
    async fn add_route_servers(
        &self,
        request: tonic::Request<rpc::RouteServers>,
    ) -> Result<tonic::Response<()>, Status> {
        log_request_data(&request);

        if !self.eth_data.route_servers_enabled {
            return Err(
                CarbideError::InvalidArgument("Route servers are disabled".to_string()).into(),
            );
        }
        let route_servers: Vec<IpAddr> = request
            .into_inner()
            .route_servers
            .iter()
            .map(|rs| IpAddr::from_str(rs))
            .collect::<Result<Vec<IpAddr>, _>>()
            .map_err(CarbideError::AddressParseError)?;

        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(|e| {
                CarbideError::from(DatabaseError::new(
                    file!(),
                    line!(),
                    "begin get_route_servers",
                    e,
                ))
            })
            .map_err(CarbideError::from)?;

        RouteServer::add(&mut txn, &route_servers).await?;

        txn.commit()
            .await
            .map_err(|e| {
                CarbideError::from(DatabaseError::new(
                    file!(),
                    line!(),
                    "commit get_route_servers",
                    e,
                ))
            })
            .map_err(CarbideError::from)?;

        Ok(tonic::Response::new(()))
    }

    async fn remove_route_servers(
        &self,
        request: tonic::Request<rpc::RouteServers>,
    ) -> Result<tonic::Response<()>, Status> {
        log_request_data(&request);

        let route_servers: Vec<IpAddr> = request
            .into_inner()
            .route_servers
            .iter()
            .map(|rs| IpAddr::from_str(rs))
            .collect::<Result<Vec<IpAddr>, _>>()
            .map_err(CarbideError::AddressParseError)?;

        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(|e| {
                CarbideError::from(DatabaseError::new(
                    file!(),
                    line!(),
                    "begin get_route_servers",
                    e,
                ))
            })
            .map_err(CarbideError::from)?;

        RouteServer::remove(&mut txn, &route_servers).await?;

        txn.commit()
            .await
            .map_err(|e| {
                CarbideError::from(DatabaseError::new(
                    file!(),
                    line!(),
                    "commit get_route_servers",
                    e,
                ))
            })
            .map_err(CarbideError::from)?;

        Ok(tonic::Response::new(()))
    }

    /// Overwrites all existing route server entries with the provided list
    async fn replace_route_servers(
        &self,
        request: tonic::Request<rpc::RouteServers>,
    ) -> Result<tonic::Response<()>, Status> {
        log_request_data(&request);

        let route_servers: Vec<IpAddr> = request
            .into_inner()
            .route_servers
            .iter()
            .map(|rs| IpAddr::from_str(rs))
            .collect::<Result<Vec<IpAddr>, _>>()
            .map_err(CarbideError::AddressParseError)?;

        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(|e| {
                CarbideError::from(DatabaseError::new(
                    file!(),
                    line!(),
                    "begin get_route_servers",
                    e,
                ))
            })
            .map_err(CarbideError::from)?;

        RouteServer::replace(&mut txn, &route_servers).await?;

        txn.commit()
            .await
            .map_err(|e| {
                CarbideError::from(DatabaseError::new(
                    file!(),
                    line!(),
                    "commit get_route_servers",
                    e,
                ))
            })
            .map_err(CarbideError::from)?;

        Ok(tonic::Response::new(()))
    }

    // Override RUST_LOG or site-explorer create_machines
    async fn set_dynamic_config(
        &self,
        request: tonic::Request<rpc::SetDynamicConfigRequest>,
    ) -> Result<tonic::Response<()>, Status> {
        log_request_data(&request);

        let req = request.into_inner();
        if req.value.is_empty() {
            return Err(Status::invalid_argument("'value' cannot be empty"));
        }

        let exp_str = req.expiry.as_deref().unwrap_or("1h");
        let expiry = duration_str::parse(exp_str).map_err(|err| {
            Status::invalid_argument(format!("Invalid expiry string '{exp_str}'. {err}"))
        })?;
        const MAX_SET_INTERNAL_EXPIRY: Duration = Duration::from_secs(60 * 60 * 60); // 60 hours
        if MAX_SET_INTERNAL_EXPIRY < expiry {
            return Err(Status::invalid_argument(
                "Expiry exceeds max allowed of 60 hours",
            ));
        }
        let expire_at = chrono::Utc::now() + expiry;

        let Ok(requested_setting) = rpc::ConfigSetting::try_from(req.setting) else {
            return Err(Status::invalid_argument(format!(
                "Not a supported dynamic config setting: {}",
                req.setting
            )));
        };
        match requested_setting {
            rpc::ConfigSetting::LogFilter => {
                let current_level = self.dynamic_settings.log_filter.load();
                let next_level = current_level
                    .with_base(&req.value, Some(expire_at))
                    .map_err(|err| {
                        Status::invalid_argument(format!(
                            "Invalid log filter string '{}'. {err}",
                            req.value
                        ))
                    })?;
                self.dynamic_settings.log_filter.store(Arc::new(next_level));
                tracing::info!("Log filter updated to '{}'", req.value);
            }
            rpc::ConfigSetting::CreateMachines => {
                let is_enabled = req.value.parse::<bool>().map_err(|err| {
                    Status::invalid_argument(format!(
                        "Invalid create_machines string '{}'. {err}",
                        req.value
                    ))
                })?;
                self.dynamic_settings
                    .create_machines
                    .store(Arc::new(is_enabled));
                tracing::info!("site-explorer create_machines updated to '{}'", req.value);
            }
        }
        Ok(tonic::Response::new(()))
    }

    async fn set_host_uefi_password(
        &self,
        request: tonic::Request<rpc::SetHostUefiPasswordRequest>,
    ) -> Result<tonic::Response<rpc::SetHostUefiPasswordResponse>, tonic::Status> {
        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin set_host_uefi_password",
                e,
            ))
        })?;

        let request = request.into_inner();
        let machine_id = match &request.host_id {
            Some(id) => try_parse_machine_id(id).map_err(CarbideError::from)?,
            None => {
                return Err(Status::invalid_argument("A machine UUID is required"));
            }
        };
        log_machine_id(&machine_id);

        if !machine_id.machine_type().is_host() {
            return Err(Status::invalid_argument(
                "Carbide only supports setting the UEFI password on discovered hosts",
            ));
        }

        let loader = DbSnapshotLoader {};
        let snapshot = loader
            .load_machine_snapshot(&mut txn, &machine_id)
            .await
            .map_err(CarbideError::from)?;

        let job_id =
            set_host_uefi_password(&snapshot.host_snapshot, self.redfish_pool.clone()).await?;

        let mut start = Instant::now();
        let mut sleep_duration: Duration = tokio::time::Duration::from_secs(5);
        let mut timeout: Duration = tokio::time::Duration::from_secs(60);
        if let Some(jid) = job_id.clone() {
            loop {
                sleep(sleep_duration).await;
                if poll_redfish_job(
                    jid.clone(),
                    libredfish::JobState::Scheduled,
                    self.redfish_pool.clone(),
                    &snapshot.host_snapshot,
                )
                .await?
                {
                    break;
                }
            }

            if start.elapsed() > timeout {
                return Err(Status::invalid_argument(format!(
                    "timed out waiting for uefi password change job {jid} to be scheduled"
                )));
            }
        }

        host_power_control(
            &snapshot.host_snapshot,
            SystemPowerControl::ForceRestart,
            None,
            self.ipmi_tool.clone(),
            self.redfish_pool.clone(),
            &mut txn,
        )
        .await?;

        start = Instant::now();
        sleep_duration = tokio::time::Duration::from_secs(30);
        timeout = tokio::time::Duration::from_secs(600);
        if let Some(jid) = job_id.clone() {
            loop {
                sleep(sleep_duration).await;
                if poll_redfish_job(
                    jid.clone(),
                    libredfish::JobState::Completed,
                    self.redfish_pool.clone(),
                    &snapshot.host_snapshot,
                )
                .await?
                {
                    break;
                }

                if start.elapsed() > timeout {
                    return Err(Status::invalid_argument(
                    format!("timed out waiting (since {start:#?}) for uefi password change job {jid} to complete")
                    ));
                }
            }
        }

        Ok(Response::new(rpc::SetHostUefiPasswordResponse {}))
    }

    /// Identify BMC vendor for given IP address
    async fn identify_bmc(
        &self,
        request: tonic::Request<rpc::IdentifyBmcRequest>,
    ) -> Result<tonic::Response<rpc::IdentifyBmcResponse>, tonic::Status> {
        let request = request.into_inner();
        if request.address.is_empty() {
            return Err(Status::invalid_argument("BMC IP address is required"));
        }

        let (org, vendor) =
            // If discovery already happened we can use scout's hardware info
            if let Ok(Some(vendor)) = self.identify_bmc_from_db(&request.address).await {
                ("".to_string(), vendor)
            } else {
                // For pre-discovery machines we use the TLS cert
                site_explorer::identify_bmc(&request.address).await?
            };

        let resp = rpc::IdentifyBmcResponse {
            known_vendor: if !vendor.is_unknown() {
                vendor.to_string()
            } else {
                "".to_string()
            },
            raw_vendor: org.to_string(),
        };
        Ok(Response::new(resp))
    }

    async fn get_expected_machine(
        &self,
        request: tonic::Request<rpc::ExpectedMachineRequest>,
    ) -> Result<Response<rpc::ExpectedMachine>, tonic::Status> {
        log_request_data(&request);

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin get_expected_machine",
                e,
            ))
        })?;

        let request = request.into_inner();

        let parsed_mac: MacAddress = request
            .bmc_mac_address
            .parse::<MacAddress>()
            .map_err(CarbideError::from)?;

        match ExpectedMachine::find_by_bmc_mac_address(&mut txn, parsed_mac).await? {
            Some(expected_machine) => {
                if expected_machine.bmc_mac_address != parsed_mac {
                    return Err(Status::invalid_argument(format!(
                    "find_by_bmc_mac_address returned {expected_machine:#?} which differs from the queried mac address {parsed_mac}")));
                }

                let rpc_expected_machine = rpc::ExpectedMachine {
                    bmc_mac_address: expected_machine.bmc_mac_address.to_string(),
                    bmc_username: expected_machine.bmc_username,
                    bmc_password: expected_machine.bmc_password,
                    chassis_serial_number: expected_machine.serial_number,
                };

                Ok(Response::new(rpc_expected_machine))
            }
            None => Err(CarbideError::NotFoundError {
                kind: "expected_machine",
                id: parsed_mac.to_string(),
            }
            .into()),
        }
    }

    async fn add_expected_machine(
        &self,
        request: tonic::Request<rpc::ExpectedMachine>,
    ) -> Result<Response<()>, tonic::Status> {
        log_request_data(&request);

        let request = request.into_inner();

        let parsed_mac: MacAddress = request
            .bmc_mac_address
            .parse::<MacAddress>()
            .map_err(CarbideError::from)?;

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin add_expected_machines",
                e,
            ))
        })?;

        ExpectedMachine::create(
            &mut txn,
            parsed_mac,
            request.bmc_username,
            request.bmc_password,
            request.chassis_serial_number,
        )
        .await?;

        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "commit add_expected_machines",
                e,
            ))
        })?;

        Ok(Response::new(()))
    }

    async fn update_instance_operating_system(
        &self,
        request: tonic::Request<rpc::InstanceOperatingSystemUpdateRequest>,
    ) -> Result<tonic::Response<rpc::Instance>, Status> {
        crate::handlers::instance::update_operating_system(self, request).await
    }

    async fn delete_expected_machine(
        &self,
        request: tonic::Request<rpc::ExpectedMachineRequest>,
    ) -> Result<Response<()>, tonic::Status> {
        log_request_data(&request);

        let rpc_expected_machine = self.get_expected_machine(request).await?.into_inner();

        let parsed_mac: MacAddress = rpc_expected_machine
            .bmc_mac_address
            .parse::<MacAddress>()
            .map_err(CarbideError::from)?;

        let expected_machine = ExpectedMachine {
            bmc_mac_address: parsed_mac,
            bmc_username: rpc_expected_machine.bmc_username,
            serial_number: rpc_expected_machine.chassis_serial_number,
            bmc_password: rpc_expected_machine.bmc_password,
        };

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin delete_expected_machines",
                e,
            ))
        })?;

        expected_machine
            .delete(&mut txn)
            .await
            .map_err(CarbideError::from)?;

        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "commit delete_expected_machines",
                e,
            ))
        })?;

        Ok(Response::new(()))
    }

    async fn update_expected_machine(
        &self,
        request: tonic::Request<rpc::ExpectedMachine>,
    ) -> Result<Response<()>, tonic::Status> {
        log_request_data(&request);

        let request = request.into_inner();

        let parsed_mac: MacAddress = request
            .bmc_mac_address
            .parse::<MacAddress>()
            .map_err(CarbideError::from)?;

        let mut expected_machine = ExpectedMachine {
            bmc_mac_address: parsed_mac,
            bmc_username: request.bmc_username.clone(),
            serial_number: request.chassis_serial_number,
            bmc_password: request.bmc_password.clone(),
        };

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin update_bmc_credentials",
                e,
            ))
        })?;

        expected_machine
            .update_bmc_credentials(&mut txn, request.bmc_username, request.bmc_password)
            .await?;

        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "commit update_bmc_credentials",
                e,
            ))
        })?;

        Ok(Response::new(()))
    }

    async fn replace_all_expected_machines(
        &self,
        request: tonic::Request<rpc::ExpectedMachineList>,
    ) -> Result<Response<()>, tonic::Status> {
        log_request_data(&request);
        let request = request.into_inner();

        let mut txn: Transaction<'_, Postgres> =
            self.database_connection.begin().await.map_err(|e| {
                CarbideError::from(DatabaseError::new(
                    file!(),
                    line!(),
                    "begin replace_all_expected_machines",
                    e,
                ))
            })?;

        ExpectedMachine::clear(&mut txn)
            .await
            .map_err(CarbideError::from)?;

        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "commit replace_all_expected_machines",
                e,
            ))
        })?;

        for expected_machine in request.expected_machines {
            self.add_expected_machine(Request::new(expected_machine))
                .await?;
        }
        Ok(Response::new(()))
    }

    async fn get_all_expected_machines(
        &self,
        request: tonic::Request<()>,
    ) -> Result<Response<rpc::ExpectedMachineList>, tonic::Status> {
        log_request_data(&request);

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin get_all_expected_machines",
                e,
            ))
        })?;

        let expected_machine_list: Vec<ExpectedMachine> = ExpectedMachine::find_all(&mut txn)
            .await
            .map_err(CarbideError::from)?;

        Ok(tonic::Response::new(rpc::ExpectedMachineList {
            expected_machines: expected_machine_list
                .into_iter()
                .map(|machine| rpc::ExpectedMachine {
                    bmc_mac_address: machine.bmc_mac_address.to_string(),
                    bmc_username: machine.bmc_username,
                    bmc_password: machine.bmc_password,
                    chassis_serial_number: machine.serial_number,
                })
                .collect(),
        }))
    }

    async fn delete_all_expected_machines(
        &self,
        request: tonic::Request<()>,
    ) -> Result<Response<()>, tonic::Status> {
        log_request_data(&request);

        let mut txn: Transaction<'_, Postgres> =
            self.database_connection.begin().await.map_err(|e| {
                CarbideError::from(DatabaseError::new(
                    file!(),
                    line!(),
                    "begin replace_all_expected_machines",
                    e,
                ))
            })?;

        ExpectedMachine::clear(&mut txn)
            .await
            .map_err(CarbideError::from)?;

        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "commit replace_all_expected_machines",
                e,
            ))
        })?;

        Ok(Response::new(()))
    }

    async fn find_connected_devices_by_dpu_machine_ids(
        &self,
        request: Request<rpc::MachineIdList>,
    ) -> Result<tonic::Response<rpc::ConnectedDeviceList>, Status> {
        log_request_data(&request);
        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin find_connected_devices_by_dpu_machine_ids",
                e,
            ))
        })?;
        let dpu_ids: Vec<String> = request
            .into_inner()
            .machine_ids
            .into_iter()
            .map(|id| id.id)
            .collect();

        let connected_devices = DpuToNetworkDeviceMap::find_by_dpu_ids(&mut txn, &dpu_ids)
            .await
            .map_err(CarbideError::from)?;

        Ok(tonic::Response::new(rpc::ConnectedDeviceList {
            connected_devices: connected_devices.into_iter().map_into().collect(),
        }))
    }

    async fn find_network_devices_by_device_ids(
        &self,
        request: Request<rpc::NetworkDeviceIdList>,
    ) -> Result<tonic::Response<rpc::NetworkTopologyData>, Status> {
        log_request_data(&request);
        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin find_network_devices_by_device_ids",
                e,
            ))
        })?;
        let request = request.into_inner(); // keep lifetime for this scope
        let network_device_ids: Vec<&str> = request
            .network_device_ids
            .iter()
            .map(|d| d.as_str())
            .collect();
        let network_devices = NetworkDevice::find(
            &mut txn,
            ObjectFilter::List(&network_device_ids),
            &NetworkDeviceSearchConfig::new(false),
        )
        .await
        .map_err(CarbideError::from)?;

        Ok(tonic::Response::new(rpc::NetworkTopologyData {
            network_devices: network_devices.into_iter().map_into().collect(),
        }))
    }

    async fn bind_attest_key(
        &self,
        request: tonic::Request<rpc::BindRequest>,
    ) -> std::result::Result<tonic::Response<rpc::BindResponse>, tonic::Status> {
        log_request_data(&request);

        if let Some(machine_id) = &request.get_ref().machine_id {
            if let Ok(id) = try_parse_machine_id(machine_id) {
                log_machine_id(&id)
            }
        }

        // TODO: fetch ek cert from the db - something like CREATE TABLE public.machines (

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin insert secret -> AK Pub",
                e,
            ))
        })?;

        // generate a secret/credential
        let secret_bytes: [u8; 32] = rand::random();

        tracing::debug!("Generated session key {:?}", secret_bytes);

        let (cli_cred_blob, cli_secret) = attest::cli_make_cred(
            &request.get_ref().ek_pub,
            &request.get_ref().ak_name,
            &secret_bytes,
        )?;

        SecretAkPub::insert(
            &mut txn,
            &Vec::from(secret_bytes),
            &request.get_ref().ak_pub,
        )
        .await?;

        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "commit insert secret -> AK Pub",
                e,
            ))
        })?;

        Ok(tonic::Response::new(rpc::BindResponse {
            cred_blob: cli_cred_blob,
            encrypted_secret: cli_secret,
        }))
    }

    async fn verify_quote(
        &self,
        request: tonic::Request<rpc::VerifyQuoteRequest>,
    ) -> std::result::Result<tonic::Response<rpc::VerifyQuoteResponse>, tonic::Status> {
        log_request_data(&request);

        if let Some(machine_id) = &request.get_ref().machine_id {
            if let Ok(id) = try_parse_machine_id(machine_id) {
                log_machine_id(&id)
            }
        }

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin find secret -> AK Pub",
                e,
            ))
        })?;

        let ak_pub_bytes =
            match SecretAkPub::get_by_secret(&mut txn, &request.get_ref().credential).await? {
                Some(entry) => entry.ak_pub,
                None => {
                    return Err(Status::from(CarbideError::AttestationVerifyQuoteError(
                        "Could not form SQL query to fetch AK Pub".into(),
                    )));
                }
            };

        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "commit find secret -> AK Pub",
                e,
            ))
        })?;

        let ak_pub = TssPublic::unmarshall(ak_pub_bytes.as_slice()).map_err(|e| {
            CarbideError::AttestationVerifyQuoteError(format!("Could not unmarshal AK Pub: {0}", e))
        })?;

        let attest = Attest::unmarshall(&(request.get_ref()).attestation).map_err(|e| {
            CarbideError::AttestationVerifyQuoteError(format!(
                "Could not unmarshall Attest struct: {0}",
                e
            ))
        })?;
        let signature = Signature::unmarshall(&(request.get_ref()).signature).map_err(|e| {
            CarbideError::AttestationVerifyQuoteError(format!(
                "Could not unmarshall Signature struct: {0}",
                e
            ))
        })?;

        let signature_valid =
            attest::verify_signature(&ak_pub, &request.get_ref().attestation, &signature)?;

        let pcr_hash_matches = attest::verify_pcr_hash(&attest, &request.get_ref().pcr_values)?;

        // TODO: change to debug? once the full implementation is in place?
        tracing::info!(
            "Signature valid: {0}, pcr hash matches: {1}",
            signature_valid,
            pcr_hash_matches
        );

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin delete secret -> AK Pub",
                e,
            ))
        })?;
        SecretAkPub::delete(&mut txn, &request.get_ref().credential).await?;

        txn.commit().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "commit delete secret -> AK Pub",
                e,
            ))
        })?;

        let _eventlog_opt = &request.get_ref().event_log;

        // TODO: Chet -> this is where verification logic goes

        Ok(tonic::Response::new(rpc::VerifyQuoteResponse {
            success: false,
        }))
    }

    async fn create_measurement_system_profile(
        &self,
        request: Request<measured_boot_pb::CreateMeasurementSystemProfileRequest>,
    ) -> Result<Response<measured_boot_pb::CreateMeasurementSystemProfileResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::profile::handle_create_system_measurement_profile(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn delete_measurement_system_profile(
        &self,
        request: Request<measured_boot_pb::DeleteMeasurementSystemProfileRequest>,
    ) -> Result<Response<measured_boot_pb::DeleteMeasurementSystemProfileResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::profile::handle_delete_measurement_system_profile(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn rename_measurement_system_profile(
        &self,
        request: Request<measured_boot_pb::RenameMeasurementSystemProfileRequest>,
    ) -> Result<Response<measured_boot_pb::RenameMeasurementSystemProfileResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::profile::handle_rename_measurement_system_profile(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn show_measurement_system_profile(
        &self,
        request: Request<measured_boot_pb::ShowMeasurementSystemProfileRequest>,
    ) -> Result<Response<measured_boot_pb::ShowMeasurementSystemProfileResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::profile::handle_show_measurement_system_profile(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn show_measurement_system_profiles(
        &self,
        request: Request<measured_boot_pb::ShowMeasurementSystemProfilesRequest>,
    ) -> Result<Response<measured_boot_pb::ShowMeasurementSystemProfilesResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::profile::handle_show_measurement_system_profiles(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn list_measurement_system_profiles(
        &self,
        request: Request<measured_boot_pb::ListMeasurementSystemProfilesRequest>,
    ) -> Result<Response<measured_boot_pb::ListMeasurementSystemProfilesResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::profile::handle_list_measurement_system_profiles(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn list_measurement_system_profile_bundles(
        &self,
        request: Request<measured_boot_pb::ListMeasurementSystemProfileBundlesRequest>,
    ) -> Result<Response<measured_boot_pb::ListMeasurementSystemProfileBundlesResponse>, Status>
    {
        Ok(Response::new(
            measured_boot::rpc::profile::handle_list_measurement_system_profile_bundles(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn list_measurement_system_profile_machines(
        &self,
        request: Request<measured_boot_pb::ListMeasurementSystemProfileMachinesRequest>,
    ) -> Result<Response<measured_boot_pb::ListMeasurementSystemProfileMachinesResponse>, Status>
    {
        Ok(Response::new(
            measured_boot::rpc::profile::handle_list_measurement_system_profile_machines(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn create_measurement_report(
        &self,
        request: Request<measured_boot_pb::CreateMeasurementReportRequest>,
    ) -> Result<Response<measured_boot_pb::CreateMeasurementReportResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::report::handle_create_measurement_report(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn delete_measurement_report(
        &self,
        request: Request<measured_boot_pb::DeleteMeasurementReportRequest>,
    ) -> Result<Response<measured_boot_pb::DeleteMeasurementReportResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::report::handle_delete_measurement_report(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn promote_measurement_report(
        &self,
        request: Request<measured_boot_pb::PromoteMeasurementReportRequest>,
    ) -> Result<Response<measured_boot_pb::PromoteMeasurementReportResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::report::handle_promote_measurement_report(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn revoke_measurement_report(
        &self,
        request: Request<measured_boot_pb::RevokeMeasurementReportRequest>,
    ) -> Result<Response<measured_boot_pb::RevokeMeasurementReportResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::report::handle_revoke_measurement_report(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn show_measurement_report_for_id(
        &self,
        request: Request<measured_boot_pb::ShowMeasurementReportForIdRequest>,
    ) -> Result<Response<measured_boot_pb::ShowMeasurementReportForIdResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::report::handle_show_measurement_report_for_id(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn show_measurement_reports_for_machine(
        &self,
        request: Request<measured_boot_pb::ShowMeasurementReportsForMachineRequest>,
    ) -> Result<Response<measured_boot_pb::ShowMeasurementReportsForMachineResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::report::handle_show_measurement_reports_for_machine(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn show_measurement_reports(
        &self,
        request: Request<measured_boot_pb::ShowMeasurementReportsRequest>,
    ) -> Result<Response<measured_boot_pb::ShowMeasurementReportsResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::report::handle_show_measurement_reports(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn list_measurement_report(
        &self,
        request: Request<measured_boot_pb::ListMeasurementReportRequest>,
    ) -> Result<Response<measured_boot_pb::ListMeasurementReportResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::report::handle_list_measurement_report(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn match_measurement_report(
        &self,
        request: Request<measured_boot_pb::MatchMeasurementReportRequest>,
    ) -> Result<Response<measured_boot_pb::MatchMeasurementReportResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::report::handle_match_measurement_report(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn create_measurement_bundle(
        &self,
        request: Request<measured_boot_pb::CreateMeasurementBundleRequest>,
    ) -> Result<Response<measured_boot_pb::CreateMeasurementBundleResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::bundle::handle_create_measurement_bundle(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn delete_measurement_bundle(
        &self,
        request: Request<measured_boot_pb::DeleteMeasurementBundleRequest>,
    ) -> Result<Response<measured_boot_pb::DeleteMeasurementBundleResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::bundle::handle_delete_measurement_bundle(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn rename_measurement_bundle(
        &self,
        request: Request<measured_boot_pb::RenameMeasurementBundleRequest>,
    ) -> Result<Response<measured_boot_pb::RenameMeasurementBundleResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::bundle::handle_rename_measurement_bundle(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn update_measurement_bundle(
        &self,
        request: Request<measured_boot_pb::UpdateMeasurementBundleRequest>,
    ) -> Result<Response<measured_boot_pb::UpdateMeasurementBundleResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::bundle::handle_update_measurement_bundle(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn show_measurement_bundle(
        &self,
        request: Request<measured_boot_pb::ShowMeasurementBundleRequest>,
    ) -> Result<Response<measured_boot_pb::ShowMeasurementBundleResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::bundle::handle_show_measurement_bundle(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn show_measurement_bundles(
        &self,
        request: Request<measured_boot_pb::ShowMeasurementBundlesRequest>,
    ) -> Result<Response<measured_boot_pb::ShowMeasurementBundlesResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::bundle::handle_show_measurement_bundles(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn list_measurement_bundles(
        &self,
        request: Request<measured_boot_pb::ListMeasurementBundlesRequest>,
    ) -> Result<Response<measured_boot_pb::ListMeasurementBundlesResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::bundle::handle_list_measurement_bundles(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn list_measurement_bundle_machines(
        &self,
        request: Request<measured_boot_pb::ListMeasurementBundleMachinesRequest>,
    ) -> Result<Response<measured_boot_pb::ListMeasurementBundleMachinesResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::bundle::handle_list_measurement_bundle_machines(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn delete_measurement_journal(
        &self,
        request: Request<measured_boot_pb::DeleteMeasurementJournalRequest>,
    ) -> Result<Response<measured_boot_pb::DeleteMeasurementJournalResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::journal::handle_delete_measurement_journal(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn show_measurement_journal(
        &self,
        request: Request<measured_boot_pb::ShowMeasurementJournalRequest>,
    ) -> Result<Response<measured_boot_pb::ShowMeasurementJournalResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::journal::handle_show_measurement_journal(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn show_measurement_journals(
        &self,
        request: Request<measured_boot_pb::ShowMeasurementJournalsRequest>,
    ) -> Result<Response<measured_boot_pb::ShowMeasurementJournalsResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::journal::handle_show_measurement_journals(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn list_measurement_journal(
        &self,
        request: Request<measured_boot_pb::ListMeasurementJournalRequest>,
    ) -> Result<Response<measured_boot_pb::ListMeasurementJournalResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::journal::handle_list_measurement_journal(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn attest_candidate_machine(
        &self,
        request: Request<measured_boot_pb::AttestCandidateMachineRequest>,
    ) -> Result<Response<measured_boot_pb::AttestCandidateMachineResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::machine::handle_attest_candidate_machine(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn show_candidate_machine(
        &self,
        request: Request<measured_boot_pb::ShowCandidateMachineRequest>,
    ) -> Result<Response<measured_boot_pb::ShowCandidateMachineResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::machine::handle_show_candidate_machine(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn show_candidate_machines(
        &self,
        request: Request<measured_boot_pb::ShowCandidateMachinesRequest>,
    ) -> Result<Response<measured_boot_pb::ShowCandidateMachinesResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::machine::handle_show_candidate_machines(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn list_candidate_machines(
        &self,
        request: Request<measured_boot_pb::ListCandidateMachinesRequest>,
    ) -> Result<Response<measured_boot_pb::ListCandidateMachinesResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::machine::handle_list_candidate_machines(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn import_site_measurements(
        &self,
        request: Request<measured_boot_pb::ImportSiteMeasurementsRequest>,
    ) -> Result<Response<measured_boot_pb::ImportSiteMeasurementsResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::site::handle_import_site_measurements(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn export_site_measurements(
        &self,
        request: Request<measured_boot_pb::ExportSiteMeasurementsRequest>,
    ) -> Result<Response<measured_boot_pb::ExportSiteMeasurementsResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::site::handle_export_site_measurements(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn add_measurement_trusted_machine(
        &self,
        request: Request<measured_boot_pb::AddMeasurementTrustedMachineRequest>,
    ) -> Result<Response<measured_boot_pb::AddMeasurementTrustedMachineResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::site::handle_add_measurement_trusted_machine(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn remove_measurement_trusted_machine(
        &self,
        request: Request<measured_boot_pb::RemoveMeasurementTrustedMachineRequest>,
    ) -> Result<Response<measured_boot_pb::RemoveMeasurementTrustedMachineResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::site::handle_remove_measurement_trusted_machine(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn list_measurement_trusted_machines(
        &self,
        request: Request<measured_boot_pb::ListMeasurementTrustedMachinesRequest>,
    ) -> Result<Response<measured_boot_pb::ListMeasurementTrustedMachinesResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::site::handle_list_measurement_trusted_machines(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn add_measurement_trusted_profile(
        &self,
        request: Request<measured_boot_pb::AddMeasurementTrustedProfileRequest>,
    ) -> Result<Response<measured_boot_pb::AddMeasurementTrustedProfileResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::site::handle_add_measurement_trusted_profile(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn remove_measurement_trusted_profile(
        &self,
        request: Request<measured_boot_pb::RemoveMeasurementTrustedProfileRequest>,
    ) -> Result<Response<measured_boot_pb::RemoveMeasurementTrustedProfileResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::site::handle_remove_measurement_trusted_profile(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }

    async fn list_measurement_trusted_profiles(
        &self,
        request: Request<measured_boot_pb::ListMeasurementTrustedProfilesRequest>,
    ) -> Result<Response<measured_boot_pb::ListMeasurementTrustedProfilesResponse>, Status> {
        Ok(Response::new(
            measured_boot::rpc::site::handle_list_measurement_trusted_profiles(
                &self.database_connection,
                request.get_ref(),
            )
            .await?,
        ))
    }
}

pub(crate) fn log_request_data<T: std::fmt::Debug>(request: &Request<T>) {
    tracing::Span::current().record(
        "request",
        truncate(
            format!("{:?}", request.get_ref()),
            ::rpc::MAX_ERR_MSG_SIZE as usize,
        ),
    );
}

/// Logs the Machine ID in the current tracing span
pub(crate) fn log_machine_id(machine_id: &MachineId) {
    tracing::Span::current().record("forge.machine_id", machine_id.to_string());
}

fn truncate(mut s: String, len: usize) -> String {
    if s.len() < len || len < 3 {
        return s;
    }
    s.truncate(len);
    if s.is_char_boundary(len - 2) {
        s.replace_range(len - 2..len, "..");
    }
    s
}

impl Api {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: Arc<CarbideConfig>,
        credential_provider: Arc<dyn CredentialProvider>,
        certificate_provider: Arc<dyn CertificateProvider>,
        database_connection: sqlx::PgPool,
        redfish_pool: Arc<dyn RedfishClientPool>,
        eth_data: ethernet_virtualization::EthVirtData,
        common_pools: Arc<CommonPools>,
        ib_fabric_manager: Arc<dyn IBFabricManager>,
        dynamic_settings: dynamic_settings::DynamicSettings,
        ipmi_tool: Arc<dyn IPMITool>,
    ) -> Self {
        Self {
            database_connection,
            credential_provider,
            certificate_provider,
            redfish_pool,
            eth_data,
            common_pools,
            ib_fabric_manager,
            runtime_config: config,
            dpu_health_log_limiter: LogLimiter::new(
                std::time::Duration::from_secs(5 * 60),
                std::time::Duration::from_secs(60 * 60),
            ),
            dynamic_settings,
            ipmi_tool,
        }
    }

    async fn load_machine(
        &self,
        machine_id: &MachineId,
        search_config: MachineSearchConfig,
    ) -> CarbideResult<(Machine, sqlx::Transaction<'_, sqlx::Postgres>)> {
        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin load_machine",
                e,
            ))
        })?;
        let machine = match Machine::find_one(&mut txn, machine_id, search_config).await {
            Err(err) => {
                tracing::warn!(%machine_id, error = %err, "failed loading machine");
                return Err(CarbideError::InvalidArgument(
                    "err loading machine".to_string(),
                ));
            }
            Ok(None) => {
                tracing::info!(%machine_id, "machine not found");
                return Err(CarbideError::NotFoundError {
                    kind: "machine",
                    id: machine_id.to_string(),
                });
            }
            Ok(Some(m)) => m,
        };
        Ok((machine, txn))
    }

    /// Allocate a value from the loopback IP resource pool.
    ///
    /// If the pool exists but is empty or has en error, return that.
    async fn allocate_loopback_ip(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        owner_id: &str,
    ) -> Result<Ipv4Addr, CarbideError> {
        match self
            .common_pools
            .ethernet
            .pool_loopback_ip
            .allocate(txn, resource_pool::OwnerType::Machine, owner_id)
            .await
        {
            Ok(val) => Ok(val),
            Err(resource_pool::ResourcePoolError::Empty) => {
                tracing::error!(owner_id, pool = "lo-ip", "Pool exhausted, cannot allocate");
                Err(CarbideError::ResourceExhausted("pool lo-ip".to_string()))
            }
            Err(err) => {
                tracing::error!(owner_id, error = %err, pool = "lo-ip", "Error allocating from resource pool");
                Err(err.into())
            }
        }
    }

    /// Allocate a value from the vpc vni resource pool.
    ///
    /// If the pool exists but is empty or has en error, return that.
    pub(crate) async fn allocate_vpc_vni(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        owner_id: &str,
    ) -> Result<i32, CarbideError> {
        match self
            .common_pools
            .ethernet
            .pool_vpc_vni
            .allocate(txn, resource_pool::OwnerType::Vpc, owner_id)
            .await
        {
            Ok(val) => Ok(val),
            Err(resource_pool::ResourcePoolError::Empty) => {
                tracing::error!(
                    owner_id,
                    pool = "vpc_vni",
                    "Pool exhausted, cannot allocate"
                );
                Err(CarbideError::ResourceExhausted("pool vpc_vni".to_string()))
            }
            Err(err) => {
                tracing::error!(owner_id, error = %err, pool = "vpc_vni", "Error allocating from resource pool");
                Err(err.into())
            }
        }
    }

    /// Allocate a value from the pkey resource pool.
    ///
    /// If the pool doesn't exist return error.
    /// If the pool exists but is empty or has en error, return that.
    pub(crate) async fn allocate_pkey(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        owner_id: &str,
    ) -> Result<Option<i16>, CarbideError> {
        match self
            .common_pools
            .infiniband
            .pool_pkey
            .as_ref()
            .allocate(txn, resource_pool::OwnerType::IBPartition, owner_id)
            .await
        {
            Ok(val) => Ok(Some(val)),
            Err(resource_pool::ResourcePoolError::Empty) => {
                tracing::error!(owner_id, pool = "pkey", "Pool exhausted, cannot allocate");
                Err(CarbideError::ResourceExhausted("pool pkey".to_string()))
            }
            Err(err) => {
                tracing::error!(owner_id, error = %err, pool = "pkey", "Error allocating from resource pool");
                Err(err.into())
            }
        }
    }

    pub fn log_filter_string(&self) -> String {
        self.dynamic_settings.log_filter.load().to_string()
    }

    async fn identify_bmc_from_db(
        &self,
        address: &str,
    ) -> Result<Option<bmc_vendor::BMCVendor>, CarbideError> {
        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin identify_bmc_from_db ",
                e,
            ))
        })?;

        if let Some(machine_id) =
            MachineTopology::find_machine_id_by_bmc_ip(&mut txn, address).await?
        {
            if let Some(machine) =
                Machine::find_one(&mut txn, &machine_id, MachineSearchConfig::default()).await?
            {
                return Ok(Some(machine.bmc_vendor()));
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::truncate;

    #[test]
    fn test_truncate() {
        let s = "hello world".to_string();
        let len = 10;
        assert_eq!(truncate(s, len), "hello wo..");
    }
}
