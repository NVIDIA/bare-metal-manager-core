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
use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use bmc_mock::MachineInfo;
use futures::{Stream, stream};
use rpc::protos::nmx_c as nmxc;
use rpc::protos::nmx_c::nmx_controller_server::{NmxController, NmxControllerServer};
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::device_simulator::SimulatorLifecycle;
use crate::simulator_registry::SimulatorRegistry;

const DEFAULT_PARTITION_ID: u32 = 32766;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NmxcGpuHealth {
    Unknown,
    Healthy,
    Degraded,
    NoNvlink,
    #[serde(rename = "degraded_bw")]
    DegradedBandwidth,
}

impl NmxcGpuHealth {
    fn as_proto(self) -> i32 {
        (match self {
            Self::Unknown => nmxc::GpuHealth::NmxGpuHealthUnknown,
            Self::Healthy => nmxc::GpuHealth::NmxGpuHealthHealthy,
            Self::Degraded => nmxc::GpuHealth::NmxGpuHealthDegraded,
            Self::NoNvlink => nmxc::GpuHealth::NmxGpuHealthNoNvlink,
            Self::DegradedBandwidth => nmxc::GpuHealth::NmxGpuHealthDegradedBw,
        }) as i32
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NmxcComputeNodeHealth {
    Unknown,
    Healthy,
    Degraded,
    Unhealthy,
}

impl NmxcComputeNodeHealth {
    fn as_proto(self) -> i32 {
        (match self {
            Self::Unknown => nmxc::ComputeNodeHealth::NmxComputeNodeHealthUnknown,
            Self::Healthy => nmxc::ComputeNodeHealth::NmxComputeNodeHealthHealthy,
            Self::Degraded => nmxc::ComputeNodeHealth::NmxComputeNodeHealthDegraded,
            Self::Unhealthy => nmxc::ComputeNodeHealth::NmxComputeNodeHealthUnhealthy,
        }) as i32
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NmxcPartitionHealth {
    Unknown,
    Healthy,
    DegradedBandwidth,
    Degraded,
    Unhealthy,
}

impl NmxcPartitionHealth {
    fn as_proto(self) -> i32 {
        (match self {
            Self::Unknown => nmxc::PartitionHealth::NmxPartitionHealthUnknown,
            Self::Healthy => nmxc::PartitionHealth::NmxPartitionHealthHealthy,
            Self::DegradedBandwidth => nmxc::PartitionHealth::NmxPartitionHealthDegradedBandwidth,
            Self::Degraded => nmxc::PartitionHealth::NmxPartitionHealthDegraded,
            Self::Unhealthy => nmxc::PartitionHealth::NmxPartitionHealthUnhealthy,
        }) as i32
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct NmxcHealthState {
    pub gpu: NmxcGpuHealth,
    pub compute_node: NmxcComputeNodeHealth,
    pub partition: NmxcPartitionHealth,
}

impl Default for NmxcHealthState {
    fn default() -> Self {
        Self {
            gpu: NmxcGpuHealth::Healthy,
            compute_node: NmxcComputeNodeHealth::Healthy,
            partition: NmxcPartitionHealth::Healthy,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NmxcHealthUpdate {
    pub gpu: Option<NmxcGpuHealth>,
    pub compute_node: Option<NmxcComputeNodeHealth>,
    pub partition: Option<NmxcPartitionHealth>,
}

#[derive(Clone, Debug)]
struct ComputeNode {
    location: nmxc::LocationInfo,
    gpu_uids: Vec<u64>,
}

#[derive(Clone, Debug)]
struct SimPartition {
    id: u32,
    name: String,
    gpu_uids: Vec<u64>,
}

#[derive(Debug)]
struct NmxcState {
    compute_nodes: Vec<ComputeNode>,
    partitions: BTreeMap<u32, SimPartition>,
    health: NmxcHealthState,
}

#[derive(Clone, Debug)]
pub struct NmxcSimulator {
    domain_uuid: Uuid,
    state: Arc<Mutex<NmxcState>>,
}

impl NmxcSimulator {
    pub fn from_registry(
        domain_uuid: Uuid,
        simulators: &SimulatorRegistry,
    ) -> eyre::Result<(Self, Vec<String>)> {
        let mut chassis_serials = BTreeSet::new();
        let mut compute_nodes = Vec::new();

        for (host_index, simulator) in simulators
            .devices()
            .iter()
            .filter_map(|device| device.machine())
            .enumerate()
        {
            let discovery = crate::discovery_info::for_machine(&MachineInfo::Host(
                simulator.handle().host_info().clone(),
            ));
            let platform_gpus = discovery
                .gpus
                .iter()
                .filter_map(|gpu| gpu.platform_info.as_ref())
                .collect::<Vec<_>>();
            let Some(first_gpu) = platform_gpus.first() else {
                continue;
            };

            chassis_serials.insert(first_gpu.chassis_serial.clone());
            compute_nodes.push(ComputeNode {
                location: nmxc::LocationInfo {
                    chassis_serial_number: first_gpu.chassis_serial.clone(),
                    tray_index: first_gpu.tray_index.into(),
                    location: Some(nmxc::Location {
                        chassis_id: 0,
                        slot_id: first_gpu.slot_number.into(),
                        host_id: (host_index + 1) as u64,
                    }),
                },
                gpu_uids: platform_gpus
                    .iter()
                    .map(|gpu| parse_gpu_uid(&gpu.fabric_guid))
                    .collect(),
            });
        }

        eyre::ensure!(
            !compute_nodes.is_empty(),
            "NMX-C simulation requires at least one machine with NVLink platform GPUs"
        );
        let simulator = Self::new(domain_uuid, compute_nodes)?;
        Ok((simulator, chassis_serials.into_iter().collect()))
    }

    fn new(domain_uuid: Uuid, compute_nodes: Vec<ComputeNode>) -> eyre::Result<Self> {
        let mut locations = BTreeSet::new();
        let mut gpu_uids = BTreeSet::new();
        for compute_node in &compute_nodes {
            let location = compute_node
                .location
                .location
                .as_ref()
                .ok_or_else(|| eyre::eyre!("NMX-C compute node is missing its location"))?;
            eyre::ensure!(
                locations.insert((location.chassis_id, location.slot_id, location.host_id)),
                "duplicate NMX-C compute-node location ({}, {}, {})",
                location.chassis_id,
                location.slot_id,
                location.host_id
            );
            for gpu_uid in &compute_node.gpu_uids {
                eyre::ensure!(*gpu_uid != 0, "NMX-C GPU UID must be nonzero");
                eyre::ensure!(
                    gpu_uids.insert(*gpu_uid),
                    "duplicate NMX-C GPU UID {gpu_uid}"
                );
            }
        }

        let default_partition = SimPartition {
            id: DEFAULT_PARTITION_ID,
            name: "default-partition".to_string(),
            gpu_uids: compute_nodes
                .iter()
                .flat_map(|node| node.gpu_uids.iter().copied())
                .collect(),
        };
        Ok(Self {
            domain_uuid,
            state: Arc::new(Mutex::new(NmxcState {
                compute_nodes,
                partitions: BTreeMap::from([(DEFAULT_PARTITION_ID, default_partition)]),
                health: NmxcHealthState::default(),
            })),
        })
    }

    pub fn health(&self) -> NmxcHealthState {
        self.state.lock().expect("NMX-C state lock poisoned").health
    }

    pub fn update_health(&self, update: NmxcHealthUpdate) -> NmxcHealthState {
        let mut state = self.state.lock().expect("NMX-C state lock poisoned");
        if let Some(gpu) = update.gpu {
            state.health.gpu = gpu;
        }
        if let Some(compute_node) = update.compute_node {
            state.health.compute_node = compute_node;
        }
        if let Some(partition) = update.partition {
            state.health.partition = partition;
        }
        state.health
    }

    fn server_header(&self, return_code: nmxc::StReturnCode) -> nmxc::ServerHeader {
        nmxc::ServerHeader {
            domain_uuid: self.domain_uuid.to_string(),
            app_uuid: String::new(),
            app_ver: env!("CARGO_PKG_VERSION").to_string(),
            return_code: return_code as i32,
        }
    }

    fn success_header(&self) -> nmxc::ServerHeader {
        self.server_header(nmxc::StReturnCode::NmxStSuccess)
    }

    fn partition_info(
        &self,
        partition: &SimPartition,
        health: NmxcPartitionHealth,
    ) -> nmxc::PartitionInfo {
        nmxc::PartitionInfo {
            partition_id: Some(nmxc::PartitionId {
                partition_id: partition.id,
            }),
            name: partition.name.clone(),
            num_gpus: partition.gpu_uids.len() as u32,
            gpu_location_list: Vec::new(),
            gpu_uid_list: partition.gpu_uids.clone(),
            health: health.as_proto(),
            partition_type: nmxc::PartitionType::NmxPartitionTypeGpuuidBased as i32,
            num_allocated_multicast_groups: 0,
            attr: Some(nmxc::PartitionAttr::default()),
        }
    }

    fn update_partition(
        &self,
        request: nmxc::UpdatePartitionRequest,
        add: bool,
    ) -> Result<nmxc::UpdatePartitionResponse, Status> {
        let mut state = self.state.lock().expect("NMX-C state lock poisoned");
        let partition_id = find_partition_id(
            &state.partitions,
            request.partition_id.as_ref(),
            &request.name,
        )?;
        let requested_uids = request.gpu_uid.into_iter().collect::<BTreeSet<_>>();
        if add
            && state.partitions.values().any(|partition| {
                partition.id != partition_id
                    && partition
                        .gpu_uids
                        .iter()
                        .any(|gpu_uid| requested_uids.contains(gpu_uid))
            })
        {
            return Ok(nmxc::UpdatePartitionResponse {
                server_header: Some(self.server_header(nmxc::StReturnCode::NmxStResourceInUse)),
                context: request.context,
                partition_id: Some(nmxc::PartitionId { partition_id }),
            });
        }

        let partition = state
            .partitions
            .get_mut(&partition_id)
            .expect("partition ID was resolved from the same map");
        if add {
            for gpu_uid in requested_uids {
                if !partition.gpu_uids.contains(&gpu_uid) {
                    partition.gpu_uids.push(gpu_uid);
                }
            }
        } else {
            partition
                .gpu_uids
                .retain(|gpu_uid| !requested_uids.contains(gpu_uid));
        }
        Ok(nmxc::UpdatePartitionResponse {
            server_header: Some(self.success_header()),
            context: request.context,
            partition_id: Some(nmxc::PartitionId { partition_id }),
        })
    }

    #[cfg(test)]
    pub(crate) fn for_test(domain_uuid: Uuid) -> Self {
        Self::new(
            domain_uuid,
            vec![ComputeNode {
                location: nmxc::LocationInfo {
                    chassis_serial_number: "test-chassis".to_string(),
                    tray_index: 1,
                    location: Some(nmxc::Location {
                        chassis_id: 1,
                        slot_id: 2,
                        host_id: 3,
                    }),
                },
                gpu_uids: vec![101, 102],
            }],
        )
        .expect("valid test NMX-C inventory")
    }
}

fn parse_gpu_uid(fabric_guid: &str) -> u64 {
    let value = fabric_guid.trim();
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).unwrap_or_default()
    } else {
        value.parse().unwrap_or_default()
    }
}

fn find_partition_id(
    partitions: &BTreeMap<u32, SimPartition>,
    partition_id: Option<&nmxc::PartitionId>,
    name: &str,
) -> Result<u32, Status> {
    if let Some(partition_id) = partition_id.filter(|id| id.partition_id != 0) {
        return partitions
            .contains_key(&partition_id.partition_id)
            .then_some(partition_id.partition_id)
            .ok_or_else(|| Status::not_found("partition ID not found"));
    }
    partitions
        .values()
        .find(|partition| partition.name == name)
        .map(|partition| partition.id)
        .ok_or_else(|| Status::not_found("partition name not found"))
}

#[tonic::async_trait]
impl NmxController for NmxcSimulator {
    async fn hello(
        &self,
        _request: Request<nmxc::ClientHello>,
    ) -> Result<Response<nmxc::ServerHello>, Status> {
        Ok(Response::new(nmxc::ServerHello {
            server_header: Some(self.success_header()),
            components_ver: Vec::new(),
            capabilities: Vec::new(),
            host_os_details: String::new(),
            major_version: nmxc::ProtoMsgMajorVersion::ProtoMsgMajorVersion as i32,
            minor_version: nmxc::ProtoMsgMinorVersion::ProtoMsgMinorVersion as i32,
        }))
    }

    type SubscribeStream =
        Pin<Box<dyn Stream<Item = Result<nmxc::ServerNotification, Status>> + Send>>;

    async fn subscribe(
        &self,
        _request: Request<nmxc::SubscribeRequest>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        Err(Status::unimplemented("subscribe is not simulated"))
    }

    async fn get_compute_node_count(
        &self,
        request: Request<nmxc::GetComputeNodeCountRequest>,
    ) -> Result<Response<nmxc::GetComputeNodeCountResponse>, Status> {
        let request = request.into_inner();
        let state = self.state.lock().expect("NMX-C state lock poisoned");
        Ok(Response::new(nmxc::GetComputeNodeCountResponse {
            server_header: Some(self.success_header()),
            context: request.context,
            num_nodes: state.compute_nodes.len() as u32,
        }))
    }

    async fn get_compute_node_location_list(
        &self,
        request: Request<nmxc::GetComputeNodeLocationListRequest>,
    ) -> Result<Response<nmxc::GetComputeNodeLocationListResponse>, Status> {
        let request = request.into_inner();
        let state = self.state.lock().expect("NMX-C state lock poisoned");
        Ok(Response::new(nmxc::GetComputeNodeLocationListResponse {
            server_header: Some(self.success_header()),
            context: request.context,
            loc_list: state
                .compute_nodes
                .iter()
                .filter_map(|node| node.location.location)
                .collect(),
        }))
    }

    async fn get_compute_node_info_list(
        &self,
        request: Request<nmxc::GetComputeNodeInfoListRequest>,
    ) -> Result<Response<nmxc::GetComputeNodeInfoListResponse>, Status> {
        let request = request.into_inner();
        let state = self.state.lock().expect("NMX-C state lock poisoned");
        let node_health = state.health.compute_node.as_proto();
        Ok(Response::new(nmxc::GetComputeNodeInfoListResponse {
            server_header: Some(self.success_header()),
            context: request.context,
            node_info_list: state
                .compute_nodes
                .iter()
                .map(|node| nmxc::ComputeNodeInfo {
                    loc: Some(node.location.clone()),
                    num_gpus: node.gpu_uids.len() as u32,
                    node_health,
                    partition_id_list: state
                        .partitions
                        .values()
                        .filter(|partition| {
                            partition
                                .gpu_uids
                                .iter()
                                .any(|gpu_uid| node.gpu_uids.contains(gpu_uid))
                        })
                        .map(|partition| nmxc::PartitionId {
                            partition_id: partition.id,
                        })
                        .collect(),
                })
                .collect(),
        }))
    }

    async fn get_gpu_info_list(
        &self,
        request: Request<nmxc::GetGpuInfoListRequest>,
    ) -> Result<Response<nmxc::GetGpuInfoListResponse>, Status> {
        let request = request.into_inner();
        let state = self.state.lock().expect("NMX-C state lock poisoned");
        let gpu_health = state.health.gpu.as_proto();
        let gpu_info_list = state
            .compute_nodes
            .iter()
            .flat_map(|node| {
                node.gpu_uids
                    .iter()
                    .enumerate()
                    .map(|(gpu_id, gpu_uid)| nmxc::GpuInfo {
                        loc: Some(node.location.clone()),
                        gpu_id: gpu_id as u32,
                        gpu_uid: *gpu_uid,
                        gpu_health,
                        partition_id: state
                            .partitions
                            .values()
                            .find(|partition| partition.gpu_uids.contains(gpu_uid))
                            .map(|partition| nmxc::PartitionId {
                                partition_id: partition.id,
                            }),
                    })
            })
            .collect();
        Ok(Response::new(nmxc::GetGpuInfoListResponse {
            server_header: Some(self.success_header()),
            context: request.context,
            gpu_info_list,
        }))
    }

    async fn get_partition_count(
        &self,
        request: Request<nmxc::GetPartitionCountRequest>,
    ) -> Result<Response<nmxc::GetPartitionCountResponse>, Status> {
        let request = request.into_inner();
        let state = self.state.lock().expect("NMX-C state lock poisoned");
        Ok(Response::new(nmxc::GetPartitionCountResponse {
            server_header: Some(self.success_header()),
            context: request.context,
            num_partitions: state.partitions.len() as u32,
        }))
    }

    async fn get_partition_id_list(
        &self,
        request: Request<nmxc::GetPartitionIdListRequest>,
    ) -> Result<Response<nmxc::GetPartitionIdListResponse>, Status> {
        let request = request.into_inner();
        let state = self.state.lock().expect("NMX-C state lock poisoned");
        Ok(Response::new(nmxc::GetPartitionIdListResponse {
            server_header: Some(self.success_header()),
            context: request.context,
            partition_list: state
                .partitions
                .values()
                .map(|partition| nmxc::Partition {
                    partition_id: Some(nmxc::PartitionId {
                        partition_id: partition.id,
                    }),
                    num_gpus: partition.gpu_uids.len() as u32,
                })
                .collect(),
        }))
    }

    async fn get_partition_info_list(
        &self,
        request: Request<nmxc::GetPartitionInfoListRequest>,
    ) -> Result<Response<nmxc::GetPartitionInfoListResponse>, Status> {
        let request = request.into_inner();
        let state = self.state.lock().expect("NMX-C state lock poisoned");
        let requested_ids = request
            .partition_id_list
            .iter()
            .map(|id| id.partition_id)
            .collect::<BTreeSet<_>>();
        let partition_info_list = state
            .partitions
            .values()
            .filter(|partition| {
                (requested_ids.is_empty() && request.partition_name_list.is_empty())
                    || requested_ids.contains(&partition.id)
                    || request.partition_name_list.contains(&partition.name)
            })
            .map(|partition| self.partition_info(partition, state.health.partition))
            .collect();
        Ok(Response::new(nmxc::GetPartitionInfoListResponse {
            server_header: Some(self.success_header()),
            context: request.context,
            partition_info_list,
        }))
    }

    async fn create_partition(
        &self,
        request: Request<nmxc::CreatePartitionRequest>,
    ) -> Result<Response<nmxc::CreatePartitionResponse>, Status> {
        let request = request.into_inner();
        let mut state = self.state.lock().expect("NMX-C state lock poisoned");
        let requested_id = request
            .partition_id
            .as_ref()
            .map(|id| id.partition_id)
            .filter(|id| *id != 0);
        let partition_id = match requested_id {
            Some(id) => id,
            None => (1..DEFAULT_PARTITION_ID)
                .find(|id| !state.partitions.contains_key(id))
                .ok_or_else(|| Status::resource_exhausted("no partition IDs available"))?,
        };
        if state.partitions.contains_key(&partition_id) {
            return Err(Status::already_exists("partition ID already exists"));
        }
        if !request.name.is_empty()
            && state
                .partitions
                .values()
                .any(|partition| partition.name == request.name)
        {
            return Err(Status::already_exists("partition name already exists"));
        }
        let gpu_uids = request
            .gpu_resource_id
            .iter()
            .filter_map(|resource| match resource.resource_id {
                Some(nmxc::gpu_resource_id::ResourceId::GpuUid(gpu_uid)) => Some(gpu_uid),
                _ => None,
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if state.partitions.values().any(|partition| {
            partition
                .gpu_uids
                .iter()
                .any(|gpu_uid| gpu_uids.contains(gpu_uid))
        }) {
            return Ok(Response::new(nmxc::CreatePartitionResponse {
                server_header: Some(self.server_header(nmxc::StReturnCode::NmxStResourceInUse)),
                context: request.context,
                partition_id: Some(nmxc::PartitionId { partition_id }),
            }));
        }
        state.partitions.insert(
            partition_id,
            SimPartition {
                id: partition_id,
                name: request.name,
                gpu_uids,
            },
        );
        Ok(Response::new(nmxc::CreatePartitionResponse {
            server_header: Some(self.success_header()),
            context: request.context,
            partition_id: Some(nmxc::PartitionId { partition_id }),
        }))
    }

    async fn delete_partition(
        &self,
        request: Request<nmxc::DeletePartitionRequest>,
    ) -> Result<Response<nmxc::DeletePartitionResponse>, Status> {
        let request = request.into_inner();
        let mut state = self.state.lock().expect("NMX-C state lock poisoned");
        let partition_id = if let Some(id) = request
            .partition_id
            .as_ref()
            .map(|id| id.partition_id)
            .filter(|id| *id != 0)
        {
            id
        } else {
            state
                .partitions
                .values()
                .find(|partition| partition.name == request.name)
                .map(|partition| partition.id)
                .ok_or_else(|| Status::not_found("partition name not found"))?
        };
        state
            .partitions
            .remove(&partition_id)
            .ok_or_else(|| Status::not_found("partition ID not found"))?;
        Ok(Response::new(nmxc::DeletePartitionResponse {
            server_header: Some(self.success_header()),
            context: request.context,
            partition_id: Some(nmxc::PartitionId { partition_id }),
        }))
    }

    async fn add_gpus_to_partition(
        &self,
        request: Request<nmxc::UpdatePartitionRequest>,
    ) -> Result<Response<nmxc::UpdatePartitionResponse>, Status> {
        self.update_partition(request.into_inner(), true)
            .map(Response::new)
    }

    async fn remove_gpus_from_partition(
        &self,
        request: Request<nmxc::UpdatePartitionRequest>,
    ) -> Result<Response<nmxc::UpdatePartitionResponse>, Status> {
        self.update_partition(request.into_inner(), false)
            .map(Response::new)
    }

    async fn factory_reset(
        &self,
        _request: Request<nmxc::FactoryResetRequest>,
    ) -> Result<Response<nmxc::ReturnCode>, Status> {
        Err(Status::unimplemented("factory_reset is not simulated"))
    }

    async fn get_static_config(
        &self,
        _request: Request<nmxc::GetStaticConfigRequest>,
    ) -> Result<Response<nmxc::StaticConfigResponse>, Status> {
        Err(Status::unimplemented("get_static_config is not simulated"))
    }

    async fn set_static_config(
        &self,
        _request: Request<nmxc::SetStaticConfigRequest>,
    ) -> Result<Response<nmxc::ReturnCode>, Status> {
        Err(Status::unimplemented("set_static_config is not simulated"))
    }

    async fn get_admin_state(
        &self,
        _request: Request<nmxc::GetAdminStateRequest>,
    ) -> Result<Response<nmxc::GetAdminStateResponse>, Status> {
        Err(Status::unimplemented("get_admin_state is not simulated"))
    }

    async fn set_admin_state(
        &self,
        _request: Request<nmxc::SetAdminStateRequest>,
    ) -> Result<Response<nmxc::SetAdminStateResponse>, Status> {
        Err(Status::unimplemented("set_admin_state is not simulated"))
    }

    async fn get_domain_properties(
        &self,
        _request: Request<nmxc::GetDomainPropertiesRequest>,
    ) -> Result<Response<nmxc::DomainProperties>, Status> {
        Err(Status::unimplemented(
            "get_domain_properties is not simulated",
        ))
    }

    async fn get_domain_state_info(
        &self,
        _request: Request<nmxc::GetDomainStateInfoRequest>,
    ) -> Result<Response<nmxc::DomainStateInfo>, Status> {
        Err(Status::unimplemented(
            "get_domain_state_info is not simulated",
        ))
    }

    async fn get_topology_info(
        &self,
        _request: Request<nmxc::GetTopologyInfoRequest>,
    ) -> Result<Response<nmxc::FmTopologyInfo>, Status> {
        Err(Status::unimplemented("get_topology_info is not simulated"))
    }

    async fn get_switch_node_count(
        &self,
        _request: Request<nmxc::GetSwitchNodeCountRequest>,
    ) -> Result<Response<nmxc::GetSwitchNodeCountResponse>, Status> {
        Err(Status::unimplemented(
            "get_switch_node_count is not simulated",
        ))
    }

    async fn get_switch_node_location_list(
        &self,
        _request: Request<nmxc::GetSwitchNodeLocationListRequest>,
    ) -> Result<Response<nmxc::GetSwitchNodeLocationListResponse>, Status> {
        Err(Status::unimplemented(
            "get_switch_node_location_list is not simulated",
        ))
    }

    async fn get_switch_node_info_list(
        &self,
        _request: Request<nmxc::GetSwitchNodeInfoListRequest>,
    ) -> Result<Response<nmxc::GetSwitchNodeInfoListResponse>, Status> {
        Err(Status::unimplemented(
            "get_switch_node_info_list is not simulated",
        ))
    }

    async fn get_switch_info_list(
        &self,
        _request: Request<nmxc::GetSwitchInfoListRequest>,
    ) -> Result<Response<nmxc::GetSwitchInfoListResponse>, Status> {
        Err(Status::unimplemented(
            "get_switch_info_list is not simulated",
        ))
    }

    async fn get_conn_count(
        &self,
        _request: Request<nmxc::GetConnCountRequest>,
    ) -> Result<Response<nmxc::GetConnCountResponse>, Status> {
        Err(Status::unimplemented("get_conn_count is not simulated"))
    }

    async fn get_conn_info_list(
        &self,
        _request: Request<nmxc::GetConnInfoListRequest>,
    ) -> Result<Response<nmxc::GetConnInfoListResponse>, Status> {
        Err(Status::unimplemented("get_conn_info_list is not simulated"))
    }

    async fn get_conn_info_combined(
        &self,
        _request: Request<nmxc::GetConnInfoCombinedRequest>,
    ) -> Result<Response<nmxc::ConnInfoCombined>, Status> {
        Err(Status::unimplemented(
            "get_conn_info_combined is not simulated",
        ))
    }

    async fn get_state_report(
        &self,
        _request: Request<nmxc::GetStateReportRequest>,
    ) -> Result<Response<nmxc::GetStateReportResponse>, Status> {
        Err(Status::unimplemented("get_state_report is not simulated"))
    }
}

pub struct NmxcServer {
    address: SocketAddr,
    cancellation: CancellationToken,
    task: Option<JoinHandle<Result<(), tonic::transport::Error>>>,
}

impl NmxcServer {
    pub async fn start(address: SocketAddr, simulator: NmxcSimulator) -> eyre::Result<Self> {
        let listener = tokio::net::TcpListener::bind(address).await?;
        let address = listener.local_addr()?;
        let incoming = stream::unfold(listener, |listener| async move {
            let connection = listener.accept().await.map(|(stream, _address)| stream);
            Some((connection, listener))
        });
        let cancellation = CancellationToken::new();
        let shutdown = cancellation.clone().cancelled_owned();
        let task = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(NmxControllerServer::new(simulator))
                .serve_with_incoming_shutdown(incoming, shutdown)
                .await
        });
        Ok(Self {
            address,
            cancellation,
            task: Some(task),
        })
    }

    pub fn address(&self) -> SocketAddr {
        self.address
    }

    pub async fn shutdown(mut self) -> eyre::Result<()> {
        self.cancellation.cancel();
        if let Some(task) = self.task.take() {
            task.await??;
        }
        Ok(())
    }
}

impl Drop for NmxcServer {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

#[cfg(test)]
mod tests {
    use bmc_mock::mac_address_pool::{MacAddressPool, PoolConfig};
    use bmc_mock::{DpuMachineInfo, DpuSettings, HardwareType, HostMachineInfo};
    use libnmxc::nmxc_model::{
        Context, CreatePartitionRequest, DeletePartitionRequest, GetComputeNodeInfoListRequest,
        GetGpuInfoListRequest, GetPartitionInfoListRequest, GpuAttr, GpuResourceId, PartitionId,
        UpdatePartitionRequest, gpu_resource_id,
    };
    use libnmxc::{Endpoint, NMX_C_GATEWAY_ID, NmxcClientPool};
    use mac_address::MacAddress;

    use super::*;
    use crate::DeviceHandle;
    use crate::host_machine::MachineHandle;

    fn two_host_wiwynn_registry() -> SimulatorRegistry {
        let pool_config = PoolConfig::new(MacAddress::new([2, 0, 0, 0, 0, 0]), 24).unwrap();
        let mut pool = MacAddressPool::new_pool(pool_config);
        let handles = (0..2)
            .map(|_| {
                let dpus = (0..2)
                    .map(|_| {
                        DpuMachineInfo::new(
                            HardwareType::WiwynnGB200Nvl,
                            &mut pool,
                            DpuSettings::default(),
                        )
                    })
                    .collect();
                let host = HostMachineInfo::new(
                    HardwareType::WiwynnGB200Nvl,
                    dpus,
                    &mut pool,
                    pool_config,
                );
                DeviceHandle::machine(MachineHandle::for_nmxc_test(host))
            })
            .collect();
        SimulatorRegistry::try_from_handles(handles).unwrap()
    }

    fn compute_node(host_id: u64, gpu_uids: Vec<u64>) -> ComputeNode {
        ComputeNode {
            location: nmxc::LocationInfo {
                chassis_serial_number: "test-chassis".to_string(),
                tray_index: 14,
                location: Some(nmxc::Location {
                    chassis_id: 0,
                    slot_id: 24,
                    host_id,
                }),
            },
            gpu_uids,
        }
    }

    fn create_partition_request(name: &str, gpu_uids: &[u64]) -> CreatePartitionRequest {
        CreatePartitionRequest {
            context: Some(Context::default()),
            name: name.to_string(),
            gpu_resource_id: gpu_uids
                .iter()
                .map(|gpu_uid| GpuResourceId {
                    resource_id: Some(gpu_resource_id::ResourceId::GpuUid(*gpu_uid)),
                })
                .collect(),
            attr: None,
            partition_id: None,
            gateway_id: NMX_C_GATEWAY_ID.to_string(),
        }
    }

    fn update_partition_request(
        partition_id: &PartitionId,
        gpu_uids: &[u64],
    ) -> UpdatePartitionRequest {
        UpdatePartitionRequest {
            context: Some(Context::default()),
            partition_id: Some(*partition_id),
            location_list: Vec::new(),
            gpu_uid: gpu_uids.to_vec(),
            gateway_id: NMX_C_GATEWAY_ID.to_string(),
            name: String::new(),
            reroute: true,
        }
    }

    async fn all_partitions(
        client: &mut dyn libnmxc::Nmxc,
    ) -> Vec<libnmxc::nmxc_model::PartitionInfo> {
        client
            .get_partition_info_list(GetPartitionInfoListRequest {
                context: Some(Context::default()),
                partition_id_list: Vec::new(),
                partition_name_list: Vec::new(),
                gateway_id: NMX_C_GATEWAY_ID.to_string(),
            })
            .await
            .unwrap()
            .partition_info_list
    }

    #[test]
    fn two_host_wiwynn_inventory_has_unique_identities() {
        let registry = two_host_wiwynn_registry();
        let (simulator, chassis_serials) =
            NmxcSimulator::from_registry(Uuid::from_u128(1), &registry).unwrap();

        assert_eq!(chassis_serials, vec!["18210000000000"]);
        let state = simulator.state.lock().unwrap();
        assert_eq!(state.compute_nodes.len(), 2);

        let gpu_uids = state
            .compute_nodes
            .iter()
            .flat_map(|node| node.gpu_uids.iter().copied())
            .collect::<BTreeSet<_>>();
        assert_eq!(gpu_uids.len(), 8);
        assert!(!gpu_uids.contains(&0));

        let locations = state
            .compute_nodes
            .iter()
            .map(|node| {
                assert_eq!(node.location.chassis_serial_number, "18210000000000");
                let location = node.location.location.as_ref().unwrap();
                (location.chassis_id, location.slot_id, location.host_id)
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(locations, BTreeSet::from([(0, 24, 1), (0, 24, 2)]));
    }

    #[test]
    fn inventory_rejects_invalid_identities() {
        let error =
            NmxcSimulator::new(Uuid::from_u128(1), vec![compute_node(1, vec![0])]).unwrap_err();
        assert_eq!(error.to_string(), "NMX-C GPU UID must be nonzero");

        let error = NmxcSimulator::new(
            Uuid::from_u128(1),
            vec![compute_node(1, vec![101]), compute_node(2, vec![101])],
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "duplicate NMX-C GPU UID 101");

        let error = NmxcSimulator::new(
            Uuid::from_u128(1),
            vec![compute_node(1, vec![101]), compute_node(1, vec![102])],
        )
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "duplicate NMX-C compute-node location (0, 24, 1)"
        );
    }

    #[tokio::test]
    async fn gpu_partition_ownership_is_exclusive_and_updates_are_atomic() {
        let simulator = NmxcSimulator::for_test(Uuid::from_u128(1));
        let server = NmxcServer::start("127.0.0.1:0".parse().unwrap(), simulator)
            .await
            .unwrap();
        let endpoint = Endpoint::new(format!("http://{}", server.address())).unwrap();
        let pool = NmxcClientPool::builder().build().unwrap();
        let mut client = pool.create_client(endpoint).await.unwrap();

        let error = client
            .create_partition(create_partition_request("occupied", &[101]))
            .await
            .unwrap_err();
        assert_eq!(
            error.nmx_return_code(),
            Some(nmxc::StReturnCode::NmxStResourceInUse as i32)
        );
        let partitions = all_partitions(client.as_mut()).await;
        assert_eq!(partitions.len(), 1);
        assert_eq!(partitions[0].gpu_uid_list, vec![101, 102]);

        let default_partition = PartitionId {
            partition_id: DEFAULT_PARTITION_ID,
        };
        client
            .remove_gpus_from_partition(update_partition_request(&default_partition, &[101]))
            .await
            .unwrap();
        let first_partition = client
            .create_partition(create_partition_request("first", &[101]))
            .await
            .unwrap()
            .partition_id
            .unwrap();
        let second_partition = client
            .create_partition(create_partition_request("second", &[]))
            .await
            .unwrap()
            .partition_id
            .unwrap();

        client
            .add_gpus_to_partition(update_partition_request(&first_partition, &[101]))
            .await
            .unwrap();
        client
            .remove_gpus_from_partition(update_partition_request(&first_partition, &[102]))
            .await
            .unwrap();
        let error = client
            .add_gpus_to_partition(update_partition_request(&second_partition, &[101, 103]))
            .await
            .unwrap_err();
        assert_eq!(
            error.nmx_return_code(),
            Some(nmxc::StReturnCode::NmxStResourceInUse as i32)
        );

        let partitions = all_partitions(client.as_mut())
            .await
            .into_iter()
            .map(|partition| (partition.name, partition.gpu_uid_list))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(partitions["default-partition"], vec![102]);
        assert_eq!(partitions["first"], vec![101]);
        assert!(partitions["second"].is_empty());

        client
            .remove_gpus_from_partition(update_partition_request(&first_partition, &[101]))
            .await
            .unwrap();
        client
            .add_gpus_to_partition(update_partition_request(&second_partition, &[101]))
            .await
            .unwrap();

        let gpus = client
            .get_gpu_info_list(GetGpuInfoListRequest {
                context: Some(Context::default()),
                attr: GpuAttr::NmxGpuAttrAll as i32,
                num_gpus: 0,
                loc: None,
                partition_id: None,
                gateway_id: NMX_C_GATEWAY_ID.to_string(),
                gpu_health: 0,
            })
            .await
            .unwrap();
        assert_eq!(
            gpus.gpu_info_list
                .iter()
                .find(|gpu| gpu.gpu_uid == 101)
                .unwrap()
                .partition_id,
            Some(second_partition)
        );

        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn production_client_observes_inventory_and_health_changes() {
        let domain_uuid = Uuid::from_u128(1);
        let simulator = NmxcSimulator::for_test(domain_uuid);
        let server = NmxcServer::start("127.0.0.1:0".parse().unwrap(), simulator.clone())
            .await
            .unwrap();
        let endpoint = Endpoint::new(format!("http://{}", server.address())).unwrap();
        let pool = NmxcClientPool::builder().build().unwrap();
        let mut client = pool.create_client(endpoint).await.unwrap();

        let hello = client.hello(NMX_C_GATEWAY_ID).await.unwrap();
        assert_eq!(
            hello.server_header.unwrap().domain_uuid,
            domain_uuid.to_string()
        );
        let partitions = client
            .get_partition_info_list(GetPartitionInfoListRequest {
                context: Some(Context::default()),
                partition_id_list: Vec::new(),
                partition_name_list: Vec::new(),
                gateway_id: NMX_C_GATEWAY_ID.to_string(),
            })
            .await
            .unwrap();
        assert_eq!(partitions.partition_info_list.len(), 1);
        let gpus = client
            .get_gpu_info_list(GetGpuInfoListRequest {
                context: Some(Context::default()),
                attr: GpuAttr::NmxGpuAttrAll as i32,
                num_gpus: 0,
                loc: None,
                partition_id: None,
                gateway_id: NMX_C_GATEWAY_ID.to_string(),
                gpu_health: 0,
            })
            .await
            .unwrap();
        assert_eq!(gpus.gpu_info_list.len(), 2);
        let nodes = client
            .get_compute_node_info_list(GetComputeNodeInfoListRequest {
                context: Some(Context::default()),
                loc_list: Vec::new(),
                gateway_id: NMX_C_GATEWAY_ID.to_string(),
            })
            .await
            .unwrap();
        assert_eq!(nodes.node_info_list.len(), 1);

        client
            .delete_partition(DeletePartitionRequest {
                context: Some(Context::default()),
                partition_id: Some(PartitionId {
                    partition_id: DEFAULT_PARTITION_ID,
                }),
                gateway_id: NMX_C_GATEWAY_ID.to_string(),
                name: String::new(),
            })
            .await
            .unwrap();
        let created = client
            .create_partition(CreatePartitionRequest {
                context: Some(Context::default()),
                name: "test-partition".to_string(),
                gpu_resource_id: vec![GpuResourceId {
                    resource_id: Some(gpu_resource_id::ResourceId::GpuUid(101)),
                }],
                attr: None,
                partition_id: None,
                gateway_id: NMX_C_GATEWAY_ID.to_string(),
            })
            .await
            .unwrap();
        let partition_id = created.partition_id.unwrap();
        client
            .add_gpus_to_partition(UpdatePartitionRequest {
                context: Some(Context::default()),
                partition_id: Some(partition_id),
                location_list: Vec::new(),
                gpu_uid: vec![102],
                gateway_id: NMX_C_GATEWAY_ID.to_string(),
                name: String::new(),
                reroute: true,
            })
            .await
            .unwrap();
        client
            .remove_gpus_from_partition(UpdatePartitionRequest {
                context: Some(Context::default()),
                partition_id: Some(partition_id),
                location_list: Vec::new(),
                gpu_uid: vec![101],
                gateway_id: NMX_C_GATEWAY_ID.to_string(),
                name: String::new(),
                reroute: true,
            })
            .await
            .unwrap();
        let partitions = client
            .get_partition_info_list(GetPartitionInfoListRequest {
                context: Some(Context::default()),
                partition_id_list: vec![partition_id],
                partition_name_list: Vec::new(),
                gateway_id: NMX_C_GATEWAY_ID.to_string(),
            })
            .await
            .unwrap();
        assert_eq!(partitions.partition_info_list[0].gpu_uid_list, vec![102]);

        simulator.update_health(NmxcHealthUpdate {
            gpu: Some(NmxcGpuHealth::Degraded),
            compute_node: Some(NmxcComputeNodeHealth::Unhealthy),
            partition: Some(NmxcPartitionHealth::DegradedBandwidth),
        });
        let gpus = client
            .get_gpu_info_list(GetGpuInfoListRequest {
                context: Some(Context::default()),
                attr: GpuAttr::NmxGpuAttrAll as i32,
                num_gpus: 0,
                loc: None,
                partition_id: None,
                gateway_id: NMX_C_GATEWAY_ID.to_string(),
                gpu_health: 0,
            })
            .await
            .unwrap();
        assert!(gpus.gpu_info_list.iter().all(|gpu| {
            gpu.gpu_health == libnmxc::nmxc_model::GpuHealth::NmxGpuHealthDegraded as i32
        }));

        server.shutdown().await.unwrap();
    }
}
