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

use std::collections::{BTreeMap, HashSet};
use std::str::FromStr as _;

use carbide_uuid::machine::MachineId;
use kube::Api;
use kube::api::{DeleteParams, ObjectMeta, Patch, PatchParams};
use serde_json::json;

use crate::crds::dpu_device_generated::{DPUDevice, DpuDeviceSpec};
use crate::crds::dpu_generated::{DPU, DpuStatusPhase};
use crate::crds::dpu_node_generated::{
    DPUNode, DpuNodeDpus, DpuNodeNodeRebootMethod, DpuNodeNodeRebootMethodExternal, DpuNodeSpec,
};
use crate::crds::dpu_node_maintenance_generated::DPUNodeMaintenance;
use crate::{DpfError, KubeImpl, NAMESPACE};

const RESTART_ANNOTATION: &str = "provisioning.dpu.nvidia.com/dpunode-external-reboot-required";
const HOST_BMC_IP_LABEL: &str = "carbide.nvidia.com/host-bmc-ip";
const CARBIDE_CONTROLLED_DEVICE_LABEL: &str = "carbide.nvidia.com/controlled.device";
const CARBIDE_CONTROLLED_NODE_LABEL: &str = "carbide.nvidia.com/controlled.node";
const CARBIDE_DPU_MACHINE_ID_LABEL: &str = "carbide.nvidia.com/dpu-machine-id";
const HOLD_ANNOTATION: &str = "provisioning.dpu.nvidia.com/wait-for-external-nodeeffect";

/// Construct a DPUDevice CR for a DPU with given parameters.
pub fn dpu_device(
    machine_id: &MachineId,
    dpu_bmc_ip: &str,
    host_bmc_ip: &str,
    serial_number: &str,
) -> DPUDevice {
    DPUDevice {
        metadata: ObjectMeta {
            name: Some(machine_id.to_string()),
            namespace: Some(NAMESPACE.to_string()),
            labels: Some(BTreeMap::from([
                (
                    CARBIDE_CONTROLLED_DEVICE_LABEL.to_string(),
                    "true".to_string(),
                ),
                (HOST_BMC_IP_LABEL.to_string(), host_bmc_ip.to_string()),
                (
                    CARBIDE_DPU_MACHINE_ID_LABEL.to_string(),
                    machine_id.to_string(),
                ),
            ])),
            ..Default::default()
        },
        spec: DpuDeviceSpec {
            bmc_ip: Some(dpu_bmc_ip.to_string()),
            bmc_port: Some(443),
            number_of_p_fs: Some(1),
            opn: None,
            pf0_name: None,
            psid: None,
            serial_number: serial_number.to_string(),
        },
        status: None,
    }
}

pub async fn create_dpu_device(
    machine_id: &MachineId,
    dpu_bmc_ip: &str,
    host_bmc_ip: &str,
    serial_number: &str,
    kube_impl: &dyn KubeImpl,
) -> Result<(), DpfError> {
    let dpu_device = dpu_device(machine_id, dpu_bmc_ip, host_bmc_ip, serial_number);
    let client = kube_impl.get_kube_client().await?;
    let dpu_devices = Api::<DPUDevice>::namespaced(client, NAMESPACE);
    if dpu_devices
        .get_opt(&machine_id.to_string())
        .await?
        .is_some()
    {
        return Err(DpfError::AlreadyExists(
            "DPUDevice",
            dpu_device.metadata.name.unwrap_or_default(),
        ));
    }
    dpu_devices.create(&Default::default(), &dpu_device).await?;
    Ok(())
}

pub async fn check_if_dpu_device_is_ready(
    machine_id: &MachineId,
    kube_impl: &dyn KubeImpl,
) -> Result<bool, DpfError> {
    let client = kube_impl.get_kube_client().await?;
    let dpu_devices = Api::<DPUDevice>::namespaced(client, NAMESPACE);
    let dpu_device = dpu_devices.get_opt(&machine_id.to_string()).await?;
    let Some(dpu_device) = dpu_device else {
        return Err(DpfError::NotFound("DPUDevice", machine_id.to_string()));
    };

    let Some(conditions) = dpu_device.status.and_then(|status| status.conditions) else {
        return Err(DpfError::NotFound(
            "DPUDeviceConditions",
            dpu_device.metadata.name.unwrap_or_default(),
        ));
    };
    let condition = conditions
        .iter()
        .find(|condition| condition.type_ == "Ready");

    Ok(condition.is_some())
}

/// Returns the name of the DPU node for the given host BMC IP.
pub fn dpu_node_name(host_bmc_ip: &str) -> String {
    format!("{host_bmc_ip}-node")
}

/// Construct a DPUNode CR with a list of DPU machine IDs.
pub fn dpu_node(host_bmc_ip: &str, dpu_machine_ids: &[&MachineId]) -> DPUNode {
    DPUNode {
        metadata: ObjectMeta {
            name: Some(dpu_node_name(host_bmc_ip)),
            namespace: Some(NAMESPACE.to_string()),
            labels: Some(BTreeMap::from([(
                CARBIDE_CONTROLLED_NODE_LABEL.to_string(),
                "true".to_string(),
            )])),
            ..Default::default()
        },
        spec: DpuNodeSpec {
            dpus: Some(
                dpu_machine_ids
                    .iter()
                    .map(|machine_id| DpuNodeDpus {
                        name: machine_id.to_string(),
                    })
                    .collect(),
            ),
            node_dms_address: None,
            node_reboot_method: Some(DpuNodeNodeRebootMethod {
                external: Some(DpuNodeNodeRebootMethodExternal {}),
                g_noi: None,
                host_agent: None,
                script: None,
            }),
        },
        status: None,
    }
}

pub async fn create_dpu_node(
    host_bmc_ip: &str,
    dpu_machine_ids: &[&MachineId],
    kube_impl: &dyn KubeImpl,
) -> Result<(), DpfError> {
    let dpu_node = dpu_node(host_bmc_ip, dpu_machine_ids);
    let client = kube_impl.get_kube_client().await?;
    let dpu_nodes = Api::<DPUNode>::namespaced(client, NAMESPACE);
    if dpu_nodes
        .get_opt(&dpu_node_name(host_bmc_ip))
        .await?
        .is_some()
    {
        return Err(DpfError::AlreadyExists(
            "DPUNode",
            dpu_node_name(host_bmc_ip),
        ));
    }
    dpu_nodes.create(&Default::default(), &dpu_node).await?;
    Ok(())
}

/// Remove the restart annotation from the DPU node.
pub async fn remove_restart_annotation_from_node(
    host_bmc_ip: &str,
    kube_impl: &dyn KubeImpl,
) -> Result<(), DpfError> {
    // Acquire the Api handle for DPUNode CRs
    let client = kube_impl.get_kube_client().await?;
    let dpu_nodes = Api::<DPUNode>::namespaced(client, NAMESPACE);

    if !check_if_restart_annotation_exists(&dpu_nodes, host_bmc_ip).await? {
        // Restart annotation does not exist, nothing to do.
        return Ok(());
    }

    // Build the patch that deletes the restart annotation by setting it to null
    let patch = json!({
        "metadata": {
            "annotations": {
                RESTART_ANNOTATION: null
            }
        }
    });

    // Attempt to patch the DPUNode resource in Kubernetes
    dpu_nodes
        .patch(
            &dpu_node_name(host_bmc_ip),
            &PatchParams::default(),
            &Patch::Merge(&patch),
        )
        .await?;
    Ok(())
}

/// Check if the restart annotation exists and is set to "true" on the DPU node.
pub async fn check_if_restart_annotation_exists(
    api: &Api<DPUNode>,
    host_bmc_ip: &str,
) -> Result<bool, DpfError> {
    // Step 1: Fetch the DPUNode CR from the cluster, or return error if missing
    let dpu_node = get_dpu_node_with_api(api, host_bmc_ip).await?;

    // Step 2: Retrieve annotations map from metadata (may not be present)
    let Some(annotations) = dpu_node.metadata.annotations else {
        return Ok(false);
    };
    // Step 3: Check for specific annotation key
    Ok(annotations.contains_key(RESTART_ANNOTATION))
}

/// Get the DPU node resource, or return NotFound error.
pub async fn get_dpu_node(
    host_bmc_ip: &str,
    kube_impl: &dyn KubeImpl,
) -> Result<DPUNode, DpfError> {
    // Attempt to get the DPUNode for the given BMC IP (if it exists)
    let client = kube_impl.get_kube_client().await?;
    let dpu_nodes = Api::<DPUNode>::namespaced(client, NAMESPACE);
    get_dpu_node_with_api(&dpu_nodes, host_bmc_ip).await
}

async fn get_dpu_node_with_api(api: &Api<DPUNode>, host_bmc_ip: &str) -> Result<DPUNode, DpfError> {
    let dpu_node = api.get_opt(&dpu_node_name(host_bmc_ip)).await?;
    // If not found, return a DpfError::NotFound
    dpu_node.ok_or_else(|| DpfError::NotFound("DPUNode", dpu_node_name(host_bmc_ip)))
}

/// Get the status phase of the DPU instance.
pub async fn get_dpu_status_phase(
    host_bmc_ip: &str,
    dpu_id: &MachineId,
    kube_impl: &dyn KubeImpl,
) -> Result<DpuStatusPhase, DpfError> {
    // Step 1: Fetch the DPU CRs Api handle
    let client = kube_impl.get_kube_client().await?;
    let dpu_nodes = Api::<DPU>::namespaced(client, NAMESPACE);
    // Step 2: Try to get the specific DPU CR instance for (dpu_id, host_bmc_ip)
    // This can return None if resource doesn't exist
    let dpu_node = dpu_nodes.get_opt(&dpu_name(dpu_id, host_bmc_ip)).await?;
    let Some(dpu_node) = dpu_node else {
        // If the resource is missing, return NotFound error
        return Err(DpfError::NotFound("DPU", dpu_name(dpu_id, host_bmc_ip)));
    };

    // Step 3: Return the status phase (if present in status struct)
    dpu_node
        .status
        .map(|status| status.phase)
        .ok_or_else(|| DpfError::NotFound("DPUStatusPhase", dpu_name(dpu_id, host_bmc_ip)))
}

/// Returns the name of the DPU node maintenance resource.
fn dpu_node_maintenance_name(host_bmc_ip: &str) -> String {
    format!("{}-hold", dpu_node_name(host_bmc_ip))
}

/// Set the hold annotation to "false" on the DPU node maintenance CR.
pub async fn update_dpu_node_maintenance_annotation(
    host_bmc_ip: &str,
    kube_impl: &dyn KubeImpl,
) -> Result<(), DpfError> {
    // Step 1: Get the Api handle for DPUNodeMaintenance resources
    let client = kube_impl.get_kube_client().await?;
    let dpu_node_maintenance = Api::<DPUNodeMaintenance>::namespaced(client, NAMESPACE);

    // Step 2: Try to fetch the maintenance CR by name; if missing, error out
    let Some(node) = dpu_node_maintenance
        .get_opt(&dpu_node_maintenance_name(host_bmc_ip))
        .await?
    else {
        return Err(DpfError::NotFound(
            "DPUNodeMaintenance",
            dpu_node_maintenance_name(host_bmc_ip),
        ));
    };

    // Step 3: Retrieve the annotation map (or default to empty)
    // and check if the specific annotation exists and is "false"
    if let Some(annotation) = node
        .metadata
        .annotations
        .unwrap_or_default()
        .get(HOLD_ANNOTATION)
    {
        // Already set to false, nothing to do
        if annotation == "false" {
            return Ok(());
        }
    } else {
        // If the annotation is not present at all, return error
        return Err(DpfError::AnnotationNotFound(
            HOLD_ANNOTATION.to_string(),
            dpu_node_maintenance_name(host_bmc_ip),
        ));
    };

    // Step 4: Build patch to set the hold annotation to "false"
    let patch = json!({
        "metadata": {
            "annotations": {
                HOLD_ANNOTATION: "false"
            }
        }
    });
    // Step 5: Patch the DPUNodeMaintenance resource to set annotation
    dpu_node_maintenance
        .patch(
            &dpu_node_maintenance_name(host_bmc_ip),
            &PatchParams::default(),
            &Patch::Merge(&patch),
        )
        .await?;
    Ok(())
}

/// Generate the DPU Kubernetes resource name for this DPU.
fn dpu_name(dpu_id: &MachineId, host_bmc_ip: &str) -> String {
    format!("{}-{}", dpu_node_name(host_bmc_ip), dpu_id)
}

/// Delete the DPU resource from Kubernetes.
pub async fn delete_dpu(
    dpu_id: &MachineId,
    host_bmc_ip: &str,
    kube_impl: &dyn KubeImpl,
) -> Result<(), DpfError> {
    // Step 1: Compute DPU CR name from IDs
    let dpu_name = dpu_name(dpu_id, host_bmc_ip);
    // Step 2: Get Api handle for DPU CRs
    let client = kube_impl.get_kube_client().await?;
    let dpu_api = Api::<DPU>::namespaced(client, NAMESPACE);
    // Step 3: Request deletion in Kubernetes (may fail if not present)
    dpu_api.delete(&dpu_name, &DeleteParams::default()).await?;
    Ok(())
}

async fn try_delete_dpu_device(
    dpu_id: &MachineId,
    kube_impl: &dyn KubeImpl,
) -> Result<(), DpfError> {
    let client = kube_impl.get_kube_client().await?;
    let dpu_devices = Api::<DPUDevice>::namespaced(client, NAMESPACE);
    if dpu_devices.get_opt(&dpu_id.to_string()).await?.is_none() {
        return Ok(());
    }
    dpu_devices
        .delete(&dpu_id.to_string(), &DeleteParams::default())
        .await?;
    Ok(())
}

/// Set the DPU status phase to "Error".
pub async fn force_dpu_status_failed(
    dpu_id: &MachineId,
    host_bmc_ip: &str,
    kube_impl: &dyn KubeImpl,
) -> Result<(), DpfError> {
    // Step 1: Compute name and get API handle
    let dpu_name = dpu_name(dpu_id, host_bmc_ip);
    let client = kube_impl.get_kube_client().await?;
    let dpu_api = Api::<DPU>::namespaced(client, NAMESPACE);
    // Step 2: Ensure DPU CR exists -- error if missing
    let Some(_dpu) = dpu_api.get_opt(&dpu_name).await? else {
        return Err(DpfError::NotFound("DPU", dpu_name));
    };

    // Step 3: Patch the status field to set phase to "Error"
    let patch = json!({
        "status": {
            "phase": "Error"
        }
    });
    // Step 4: Apply the status patch (can fail if the object changes concurrently)
    dpu_api
        .patch_status(&dpu_name, &PatchParams::default(), &Patch::Merge(&patch))
        .await?;
    Ok(())
}

/// This function tries its best to delete the managed host from dpf, even if feature is enabled or not.
/// This is needed because if the feature is disabled after the managed-host was created, the entry still needs to be deleted.
pub async fn force_delete_managed_host(
    api: &dyn KubeImpl,
    ip: &str,
    dpu_ids: &[String],
) -> Result<(), DpfError> {
    let client = api.get_kube_client().await?;
    let dpu_nodes = Api::<DPUNode>::namespaced(client, NAMESPACE);
    let dpu_node_name = dpu_node_name(ip);
    let Ok(Some(dpu_node)) = dpu_nodes.get_opt(&dpu_node_name).await else {
        tracing::info!("Failed to get DPU node {dpu_node_name} for host {ip}");
        tracing::info!("Trying to delete DPU devices for host {ip}");
        try_delete_dpu_devices(dpu_ids, api).await?;
        return Ok(());
    };

    for dpu in dpu_node.spec.dpus.clone().unwrap_or_default() {
        let Ok(dpu_id) = MachineId::from_str(&dpu.name) else {
            tracing::error!("Invalid DPU ID: {}", dpu.name);
            continue;
        };
        force_dpu_status_failed(&dpu_id, ip, api).await?;
    }

    // Remove the label to remove these DPUs from DPF supervision.
    let patch = json!({
        "metadata": {
            "labels": {
                CARBIDE_CONTROLLED_NODE_LABEL: null
            }
        }
    });
    dpu_nodes
        .patch(
            &dpu_node_name,
            &PatchParams::default(),
            &Patch::Merge(&patch),
        )
        .await?;

    // Delete DPU nodes
    dpu_nodes
        .delete(&dpu_node_name, &DeleteParams::default())
        .await?;

    let dpu_ids_to_delete = dpu_node
        .spec
        .dpus
        .unwrap_or_default()
        .iter()
        .map(|dpu| dpu.name.clone())
        .collect::<HashSet<String>>();

    // Concate the dpu_ids to delete as received in the request.
    let dpu_ids_to_delete = dpu_ids_to_delete
        .into_iter()
        .chain(dpu_ids.iter().cloned())
        .collect::<HashSet<String>>();

    // Delete the DPU nodes
    try_delete_dpu_devices(&dpu_ids_to_delete.into_iter().collect::<Vec<String>>(), api).await?;
    Ok(())
}

/// Try to delete the DPU devices for the given DPU IDs.
async fn try_delete_dpu_devices(dpu_ids: &[String], api: &dyn KubeImpl) -> Result<(), DpfError> {
    tracing::info!("Trying to delete DPU devices for DPU IDs: {:?}", dpu_ids);
    for dpu_id in dpu_ids {
        let Ok(dpu_id) = MachineId::from_str(dpu_id) else {
            tracing::error!("Invalid DPU ID: {dpu_id}");
            continue;
        };

        if let Err(err) = try_delete_dpu_device(&dpu_id, api).await {
            tracing::error!("Failed to delete DPU device {dpu_id}: {err}");
        }
    }
    Ok(())
}
