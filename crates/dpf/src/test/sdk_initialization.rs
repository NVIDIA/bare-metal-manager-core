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

//! Tests for DPF SDK initialization resources and lookup behavior.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use dashmap::DashMap;
use kube::Resource;
use kube::core::ObjectMeta;

use crate::crds::bfbs_generated::BFB;
use crate::crds::bluefieldsoftwares_generated::BlueFieldSoftware;
use crate::crds::dpudeployments_generated::{
    DPUDeployment, DpuDeploymentDpusDpuSets, DpuDeploymentDpusDpuSetsDpuNodeSelector,
};
use crate::crds::dpuflavors_generated::DPUFlavor;
use crate::crds::dpunodes_generated::{DPUNode, DpuNodeSpec};
use crate::crds::dpus_generated::{DPU, DpuStatusPhase};
use crate::crds::dpuserviceconfigurations_generated::DPUServiceConfiguration;
use crate::crds::dpuserviceinterfaces_generated::DPUServiceInterface;
use crate::crds::dpuservicenads_generated::DPUServiceNAD;
use crate::crds::dpuservicetemplates_generated::DPUServiceTemplate;
use crate::error::DpfError;
use crate::repository::{
    BfbRepository, BlueFieldSoftwareRepository, DpfOperatorConfigRepository,
    DpuDeploymentRepository, DpuFlavorRepository, DpuNodeRepository, DpuRepository,
    DpuServiceConfigurationRepository, DpuServiceInterfaceRepository, DpuServiceNADRepository,
    DpuServiceTemplateRepository, K8sConfigRepository,
};
use crate::sdk::{DpfSdkBuilder, ResourceLabeler};
use crate::types::*;

const TEST_NS: &str = "sdk-init-ns";
const TEST_NODE_NAME: &str = "node-host-001";
const TEST_DPU_NAME: &str = "node-host-001-device-001";
const SOURCE_DEPLOYMENT: &str = "bf3-deployment";
const TARGET_DEPLOYMENT: &str = "gb200-deployment";
const TEST_FLAVOR: &str = "test-flavor";
const TEST_BFB: &str = "bf-bundle-abc";
const OWNED_BY_DEPLOYMENT_LABEL: &str = "svc.dpu.nvidia.com/owned-by-dpudeployment";

fn ns_key(ns: &str, name: &str) -> String {
    format!("{}/{}", ns, name)
}

fn resource_key<T: Resource>(r: &T) -> String {
    format!(
        "{}/{}",
        r.meta().namespace.as_deref().unwrap_or(""),
        r.meta().name.as_deref().unwrap_or("")
    )
}

#[derive(Clone, Default)]
struct InitializationMock {
    bfbs: Arc<DashMap<String, BFB>>,
    bluefield_softwares: Arc<DashMap<String, BlueFieldSoftware>>,
    flavors: Arc<DashMap<String, DPUFlavor>>,
    nodes: Arc<DashMap<String, DPUNode>>,
    dpus: Arc<DashMap<String, DPU>>,
    deployments: Arc<DashMap<String, DPUDeployment>>,
    service_templates: Arc<DashMap<String, DPUServiceTemplate>>,
    service_configs: Arc<DashMap<String, DPUServiceConfiguration>>,
    nads: Arc<DashMap<String, DPUServiceNAD>>,
    service_interfaces: Arc<DashMap<String, DPUServiceInterface>>,
    configs: Arc<DashMap<String, BTreeMap<String, String>>>,
    secrets: Arc<DashMap<String, BTreeMap<String, Vec<u8>>>>,
    node_patches: Arc<Mutex<Vec<serde_json::Value>>>,
    dpu_list_selectors: Arc<Mutex<Vec<Option<String>>>>,
    dpu_uid_deletes: Arc<Mutex<Vec<(String, String)>>>,
}

#[derive(Clone, Copy)]
struct InitializationLabeler;

impl ResourceLabeler for InitializationLabeler {
    fn node_labels_for_deployment_type(
        &self,
        deployment_type: DpuDeploymentType,
    ) -> Result<BTreeMap<String, String>, DpfError> {
        let deployment_type = match deployment_type {
            DpuDeploymentType::Bf3 => "bf3",
            DpuDeploymentType::Bf3Gb200 => "bf3gb200",
            DpuDeploymentType::Bf4Generic => "bf4generic",
            DpuDeploymentType::Bf4Astra => "bf4astra",
        };
        Ok(BTreeMap::from([(
            "test.nvidia.com/deployment-type".to_string(),
            deployment_type.to_string(),
        )]))
    }
}

/// Provides selectors with one shared label and one label unique to each BF3
/// deployment so migration tests can distinguish selector ownership.
#[derive(Clone, Copy)]
struct MigrationLabeler;

impl ResourceLabeler for MigrationLabeler {
    fn node_labels_for_deployment_type(
        &self,
        deployment_type: DpuDeploymentType,
    ) -> Result<BTreeMap<String, String>, DpfError> {
        let deployment_label = match deployment_type {
            DpuDeploymentType::Bf3 => "test.nvidia.com/bf3",
            DpuDeploymentType::Bf3Gb200 => "test.nvidia.com/bf3gb200",
            other => {
                return Err(DpfError::ConfigError(format!(
                    "no migration test selector for {other:?}"
                )));
            }
        };

        Ok(BTreeMap::from([
            (
                "test.nvidia.com/dpu-enabled".to_string(),
                "true".to_string(),
            ),
            (deployment_label.to_string(), "true".to_string()),
        ]))
    }
}

#[async_trait]
impl BfbRepository for InitializationMock {
    async fn get(&self, name: &str, ns: &str) -> Result<Option<BFB>, DpfError> {
        Ok(self.bfbs.get(&ns_key(ns, name)).map(|r| r.clone()))
    }
    async fn list(&self, ns: &str) -> Result<Vec<BFB>, DpfError> {
        let prefix = format!("{}/", ns);
        Ok(self
            .bfbs
            .iter()
            .filter(|entry| entry.key().starts_with(&prefix))
            .map(|entry| entry.value().clone())
            .collect())
    }
    async fn create(&self, bfb: &BFB) -> Result<BFB, DpfError> {
        use crate::crds::bfbs_generated::{BfbStatus, BfbStatusPhase};
        let mut bfb_with_status = bfb.clone();
        bfb_with_status.status = Some(BfbStatus {
            file_name: None,
            phase: BfbStatusPhase::Ready,
            versions: None,
            conditions: None,
            observed_generation: None,
        });
        self.bfbs
            .insert(resource_key(&bfb_with_status), bfb_with_status.clone());
        Ok(bfb_with_status)
    }
    async fn delete(&self, name: &str, ns: &str) -> Result<(), DpfError> {
        self.bfbs.remove(&ns_key(ns, name));
        Ok(())
    }
}

#[async_trait]
impl BlueFieldSoftwareRepository for InitializationMock {
    async fn get(&self, name: &str, ns: &str) -> Result<Option<BlueFieldSoftware>, DpfError> {
        Ok(self
            .bluefield_softwares
            .get(&ns_key(ns, name))
            .map(|r| r.clone()))
    }
    async fn list(&self, ns: &str) -> Result<Vec<BlueFieldSoftware>, DpfError> {
        let prefix = format!("{}/", ns);
        Ok(self
            .bluefield_softwares
            .iter()
            .filter(|entry| entry.key().starts_with(&prefix))
            .map(|entry| entry.value().clone())
            .collect())
    }
    async fn create(&self, bfs: &BlueFieldSoftware) -> Result<BlueFieldSoftware, DpfError> {
        self.bluefield_softwares
            .insert(resource_key(bfs), bfs.clone());
        Ok(bfs.clone())
    }
    async fn delete(&self, name: &str, ns: &str) -> Result<(), DpfError> {
        self.bluefield_softwares.remove(&ns_key(ns, name));
        Ok(())
    }
}

#[async_trait]
impl DpuFlavorRepository for InitializationMock {
    async fn get(&self, name: &str, ns: &str) -> Result<Option<DPUFlavor>, DpfError> {
        Ok(self.flavors.get(&ns_key(ns, name)).map(|r| r.clone()))
    }
    async fn create(&self, f: &DPUFlavor) -> Result<DPUFlavor, DpfError> {
        self.flavors.insert(resource_key(f), f.clone());
        Ok(f.clone())
    }
}

#[async_trait]
impl DpuRepository for InitializationMock {
    async fn get(&self, name: &str, ns: &str) -> Result<Option<DPU>, DpfError> {
        Ok(self.dpus.get(&ns_key(ns, name)).map(|dpu| dpu.clone()))
    }

    async fn list(&self, ns: &str, label_selector: Option<&str>) -> Result<Vec<DPU>, DpfError> {
        self.dpu_list_selectors
            .lock()
            .unwrap()
            .push(label_selector.map(str::to_string));
        let prefix = format!("{ns}/");
        Ok(self
            .dpus
            .iter()
            .filter(|entry| entry.key().starts_with(&prefix))
            .map(|entry| entry.value().clone())
            .collect())
    }

    async fn patch_status(
        &self,
        _name: &str,
        _ns: &str,
        _patch: serde_json::Value,
    ) -> Result<(), DpfError> {
        Ok(())
    }

    async fn delete(&self, name: &str, ns: &str) -> Result<(), DpfError> {
        self.dpus.remove(&ns_key(ns, name));
        Ok(())
    }

    async fn delete_if_uid(&self, name: &str, ns: &str, uid: &str) -> Result<(), DpfError> {
        self.dpu_uid_deletes
            .lock()
            .unwrap()
            .push((name.to_string(), uid.to_string()));
        let current_uid = self
            .dpus
            .get(&ns_key(ns, name))
            .map(|dpu| dpu.metadata.uid.clone())
            .ok_or_else(|| DpfError::not_found("DPU", name))?;
        if current_uid.as_deref() != Some(uid) {
            return Err(DpfError::InvalidState(format!(
                "DPU {name} no longer has UID {uid}"
            )));
        }
        DpuRepository::delete(self, name, ns).await
    }

    fn watch<F, Fut>(
        &self,
        _ns: &str,
        _label_selector: Option<&str>,
        _handler: F,
    ) -> impl Future<Output = ()> + Send + 'static
    where
        F: Fn(Arc<DPU>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), DpfError>> + Send + 'static,
    {
        futures::future::pending()
    }
}

#[async_trait]
impl DpuNodeRepository for InitializationMock {
    async fn get(&self, name: &str, ns: &str) -> Result<Option<DPUNode>, DpfError> {
        Ok(self.nodes.get(&ns_key(ns, name)).map(|node| node.clone()))
    }

    async fn list(&self, ns: &str) -> Result<Vec<DPUNode>, DpfError> {
        let prefix = format!("{ns}/");
        Ok(self
            .nodes
            .iter()
            .filter(|entry| entry.key().starts_with(&prefix))
            .map(|entry| entry.value().clone())
            .collect())
    }

    async fn create(&self, node: &DPUNode) -> Result<DPUNode, DpfError> {
        self.nodes.insert(resource_key(node), node.clone());
        Ok(node.clone())
    }

    async fn patch(&self, name: &str, ns: &str, patch: serde_json::Value) -> Result<(), DpfError> {
        self.node_patches.lock().unwrap().push(patch.clone());

        if let Some(mut node) = self.nodes.get_mut(&ns_key(ns, name))
            && let Some(labels) = patch
                .pointer("/metadata/labels")
                .and_then(serde_json::Value::as_object)
        {
            let node_labels = node.metadata.labels.get_or_insert_with(BTreeMap::new);
            for (key, value) in labels {
                if value.is_null() {
                    node_labels.remove(key);
                } else if let Some(value) = value.as_str() {
                    node_labels.insert(key.clone(), value.to_string());
                }
            }
        }

        Ok(())
    }

    async fn delete(&self, name: &str, ns: &str) -> Result<(), DpfError> {
        self.nodes.remove(&ns_key(ns, name));
        Ok(())
    }
}

#[async_trait]
impl DpuDeploymentRepository for InitializationMock {
    async fn get(&self, name: &str, ns: &str) -> Result<Option<DPUDeployment>, DpfError> {
        Ok(self.deployments.get(&ns_key(ns, name)).map(|r| r.clone()))
    }
    async fn list(&self, ns: &str) -> Result<Vec<DPUDeployment>, DpfError> {
        let prefix = format!("{}/", ns);
        Ok(self
            .deployments
            .iter()
            .filter(|entry| entry.key().starts_with(&prefix))
            .map(|entry| entry.value().clone())
            .collect())
    }
    async fn apply(&self, d: &DPUDeployment) -> Result<DPUDeployment, DpfError> {
        self.deployments.insert(resource_key(d), d.clone());
        Ok(d.clone())
    }
    async fn patch(&self, name: &str, ns: &str, patch: serde_json::Value) -> Result<(), DpfError> {
        if let Some(mut dep) = self.deployments.get_mut(&ns_key(ns, name))
            && let Some(bfb) = patch.pointer("/spec/dpus/bfb").and_then(|v| v.as_str())
        {
            dep.spec.dpus.bfb = Some(bfb.to_string());
        }
        Ok(())
    }
    async fn delete(&self, name: &str, ns: &str) -> Result<(), DpfError> {
        self.deployments.remove(&ns_key(ns, name));
        Ok(())
    }
}

#[async_trait]
impl DpuServiceTemplateRepository for InitializationMock {
    async fn get(&self, name: &str, ns: &str) -> Result<Option<DPUServiceTemplate>, DpfError> {
        Ok(self
            .service_templates
            .get(&ns_key(ns, name))
            .map(|r| r.clone()))
    }
    async fn list(&self, ns: &str) -> Result<Vec<DPUServiceTemplate>, DpfError> {
        let prefix = format!("{}/", ns);
        Ok(self
            .service_templates
            .iter()
            .filter(|entry| entry.key().starts_with(&prefix))
            .map(|entry| entry.value().clone())
            .collect())
    }
    async fn apply(&self, t: &DPUServiceTemplate) -> Result<DPUServiceTemplate, DpfError> {
        self.service_templates.insert(resource_key(t), t.clone());
        Ok(t.clone())
    }
}

#[async_trait]
impl DpuServiceConfigurationRepository for InitializationMock {
    async fn get(&self, name: &str, ns: &str) -> Result<Option<DPUServiceConfiguration>, DpfError> {
        Ok(self
            .service_configs
            .get(&ns_key(ns, name))
            .map(|r| r.clone()))
    }
    async fn list(&self, ns: &str) -> Result<Vec<DPUServiceConfiguration>, DpfError> {
        let prefix = format!("{}/", ns);
        Ok(self
            .service_configs
            .iter()
            .filter(|entry| entry.key().starts_with(&prefix))
            .map(|entry| entry.value().clone())
            .collect())
    }
    async fn apply(
        &self,
        c: &DPUServiceConfiguration,
    ) -> Result<DPUServiceConfiguration, DpfError> {
        self.service_configs.insert(resource_key(c), c.clone());
        Ok(c.clone())
    }
}

#[async_trait]
impl DpuServiceNADRepository for InitializationMock {
    async fn get(&self, name: &str, ns: &str) -> Result<Option<DPUServiceNAD>, DpfError> {
        Ok(self.nads.get(&ns_key(ns, name)).map(|r| r.clone()))
    }
    async fn list(&self, ns: &str) -> Result<Vec<DPUServiceNAD>, DpfError> {
        let prefix = format!("{}/", ns);
        Ok(self
            .nads
            .iter()
            .filter(|entry| entry.key().starts_with(&prefix))
            .map(|entry| entry.value().clone())
            .collect())
    }
    async fn apply(&self, nad: &DPUServiceNAD) -> Result<DPUServiceNAD, DpfError> {
        self.nads.insert(resource_key(nad), nad.clone());
        Ok(nad.clone())
    }
}

#[async_trait]
impl DpuServiceInterfaceRepository for InitializationMock {
    async fn get(&self, name: &str, ns: &str) -> Result<Option<DPUServiceInterface>, DpfError> {
        Ok(self
            .service_interfaces
            .get(&ns_key(ns, name))
            .map(|r| r.clone()))
    }
    async fn list(&self, ns: &str) -> Result<Vec<DPUServiceInterface>, DpfError> {
        let prefix = format!("{}/", ns);
        Ok(self
            .service_interfaces
            .iter()
            .filter(|entry| entry.key().starts_with(&prefix))
            .map(|entry| entry.value().clone())
            .collect())
    }
    async fn apply(&self, iface: &DPUServiceInterface) -> Result<DPUServiceInterface, DpfError> {
        self.service_interfaces
            .insert(resource_key(iface), iface.clone());
        Ok(iface.clone())
    }
}

#[async_trait]
impl K8sConfigRepository for InitializationMock {
    async fn get_configmap(
        &self,
        name: &str,
        ns: &str,
    ) -> Result<Option<BTreeMap<String, String>>, DpfError> {
        Ok(self.configs.get(&ns_key(ns, name)).map(|r| r.clone()))
    }
    async fn apply_configmap(
        &self,
        name: &str,
        ns: &str,
        data: BTreeMap<String, String>,
    ) -> Result<(), DpfError> {
        self.configs.insert(ns_key(ns, name), data);
        Ok(())
    }
    async fn get_secret(
        &self,
        name: &str,
        ns: &str,
    ) -> Result<Option<BTreeMap<String, Vec<u8>>>, DpfError> {
        Ok(self.secrets.get(&ns_key(ns, name)).map(|r| r.clone()))
    }
    async fn apply_secret(
        &self,
        name: &str,
        ns: &str,
        data: BTreeMap<String, Vec<u8>>,
    ) -> Result<(), DpfError> {
        self.secrets.insert(ns_key(ns, name), data);
        Ok(())
    }
}

#[async_trait]
impl DpfOperatorConfigRepository for InitializationMock {
    async fn patch(&self, _: &str, _: &str, _: serde_json::Value) -> Result<(), DpfError> {
        Ok(())
    }
}

/// Builds a DPUNode with source deployment labels and one unrelated label that
/// a migration must preserve.
fn migration_dpu_node() -> DPUNode {
    DPUNode {
        metadata: ObjectMeta {
            name: Some(TEST_NODE_NAME.to_string()),
            namespace: Some(TEST_NS.to_string()),
            resource_version: Some("7".to_string()),
            labels: Some(BTreeMap::from([
                (
                    "test.nvidia.com/dpu-enabled".to_string(),
                    "true".to_string(),
                ),
                ("test.nvidia.com/bf3".to_string(), "true".to_string()),
                (
                    "external.nvidia.com/label".to_string(),
                    "preserved".to_string(),
                ),
            ])),
            ..Default::default()
        },
        spec: DpuNodeSpec {
            dpus: Some(vec![]),
            node_dms_address: None,
            node_reboot_method: None,
        },
        status: None,
    }
}

/// Builds one ready or settling deployment with the selector for its requested
/// BF3 deployment type.
fn migration_deployment(
    name: &str,
    deployment_type: DpuDeploymentType,
    ready: bool,
) -> DPUDeployment {
    let spec = serde_json::json!({
        "dpus": {
            "bfb": TEST_BFB,
            "flavor": TEST_FLAVOR,
            "dpuSetStrategy": { "type": "OnDelete" },
            "nodeEffect": {},
        },
        "services": {},
        "serviceChains": {
            "switches": [],
            "upgradePolicy": { "applyNodeEffect": true },
        },
    });
    let status = serde_json::json!({
        "conditions": [{
            "type": "DPUSetsReconciled",
            "status": if ready { "True" } else { "False" },
            "observedGeneration": 1,
            "lastTransitionTime": "2026-01-01T00:00:00Z",
            "reason": "Test",
        }],
    });
    let selector_labels = MigrationLabeler
        .node_labels_for_deployment_type(deployment_type)
        .expect("migration test selector");
    let mut deployment = DPUDeployment {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(TEST_NS.to_string()),
            generation: Some(1),
            ..Default::default()
        },
        spec: serde_json::from_value(spec).expect("valid DPUDeployment spec"),
        status: Some(serde_json::from_value(status).expect("valid DPUDeployment status")),
    };
    deployment.spec.dpus.dpu_sets = Some(vec![DpuDeploymentDpusDpuSets {
        dpu_annotations: None,
        dpu_selector: None,
        name_suffix: "default".to_string(),
        dpu_node_selector: Some(DpuDeploymentDpusDpuSetsDpuNodeSelector {
            match_expressions: None,
            match_labels: Some(selector_labels),
        }),
        dpu_cluster_selector: None,
        dpu_device_selector: None,
        node_selector: None,
    }]);
    deployment
}

/// Builds one DPU owned by a selected deployment with the configuration fields
/// that are authoritative after it reaches Ready.
fn migration_dpu(
    owner: &str,
    phase: DpuStatusPhase,
    flavor: &str,
    installed_bfb_file: Option<&str>,
    uid: &str,
) -> DPU {
    let mut dpu = super::helpers::make_dpu(TEST_NS, TEST_DPU_NAME, "001", TEST_NODE_NAME, phase);
    dpu.metadata.labels = Some(BTreeMap::from([(
        OWNED_BY_DEPLOYMENT_LABEL.to_string(),
        format!("{TEST_NS}_{owner}"),
    )]));
    dpu.metadata.uid = Some(uid.to_string());
    dpu.spec.dpu_flavor = flavor.to_string();
    dpu.status.as_mut().expect("DPU status").bfb_file = installed_bfb_file.map(str::to_string);
    dpu
}

/// Builds the SDK with migration selectors and returns the target deployment's
/// phase for the single test DPU.
async fn target_dpu_phase(mock: InitializationMock) -> Result<Option<DpuPhase>, DpfError> {
    let phases = DpfSdkBuilder::new(mock, TEST_NS, String::new())
        .with_labeler(MigrationLabeler)
        .build_without_resources()
        .await
        .expect("migration SDK")
        .get_dpu_phases_for_deployment_type(
            &["001".to_string()],
            TEST_NODE_NAME,
            DpuDeploymentType::Bf3Gb200,
        )
        .await?;

    Ok(phases.and_then(|mut phases| phases.remove("001")))
}

/// A selector transfer removes and adds the deployment-specific labels in one
/// version-guarded patch, is idempotent, and repairs a node matching both.
#[tokio::test]
async fn deployment_label_transfer_is_atomic_idempotent_and_repairs_partial_state() {
    let mock = InitializationMock::default();
    let node = migration_dpu_node();
    mock.nodes.insert(resource_key(&node), node);
    let sdk = DpfSdkBuilder::new(mock.clone(), TEST_NS, String::new())
        .with_labeler(MigrationLabeler)
        .build_without_resources()
        .await
        .expect("migration SDK");

    sdk.transfer_dpu_node_deployment_labels(
        TEST_NODE_NAME,
        DpuDeploymentType::Bf3,
        DpuDeploymentType::Bf3Gb200,
    )
    .await
    .expect("source-to-target selector transfer");

    {
        let patches = mock.node_patches.lock().unwrap();
        assert_eq!(patches.len(), 1);
        assert_eq!(
            patches[0]
                .pointer("/metadata/resourceVersion")
                .and_then(serde_json::Value::as_str),
            Some("7")
        );
        assert!(patches[0]["metadata"]["labels"]["test.nvidia.com/bf3"].is_null());
        assert_eq!(
            patches[0]["metadata"]["labels"]["test.nvidia.com/bf3gb200"],
            "true"
        );
    }

    let node = DpuNodeRepository::get(&mock, TEST_NODE_NAME, TEST_NS)
        .await
        .unwrap()
        .expect("transferred DPUNode");
    assert_eq!(
        node.metadata.labels,
        Some(BTreeMap::from([
            (
                "test.nvidia.com/dpu-enabled".to_string(),
                "true".to_string()
            ),
            ("test.nvidia.com/bf3gb200".to_string(), "true".to_string()),
            (
                "external.nvidia.com/label".to_string(),
                "preserved".to_string()
            ),
        ]))
    );

    sdk.transfer_dpu_node_deployment_labels(
        TEST_NODE_NAME,
        DpuDeploymentType::Bf3,
        DpuDeploymentType::Bf3Gb200,
    )
    .await
    .expect("idempotent selector transfer");
    assert_eq!(mock.node_patches.lock().unwrap().len(), 1);

    mock.nodes
        .get_mut(&ns_key(TEST_NS, TEST_NODE_NAME))
        .expect("DPUNode to repair")
        .metadata
        .labels
        .as_mut()
        .expect("DPUNode labels")
        .insert("test.nvidia.com/bf3".to_string(), "true".to_string());
    sdk.transfer_dpu_node_deployment_labels(
        TEST_NODE_NAME,
        DpuDeploymentType::Bf3,
        DpuDeploymentType::Bf3Gb200,
    )
    .await
    .expect("repair selector overlap");

    let node = DpuNodeRepository::get(&mock, TEST_NODE_NAME, TEST_NS)
        .await
        .unwrap()
        .expect("repaired DPUNode");
    assert!(
        !node
            .metadata
            .labels
            .expect("DPUNode labels")
            .contains_key("test.nvidia.com/bf3")
    );
    assert_eq!(mock.node_patches.lock().unwrap().len(), 2);
}

/// A node outside both deployment selectors cannot be claimed by the target
/// deployment as a side effect of migration.
#[tokio::test]
async fn deployment_label_transfer_rejects_unrelated_node() {
    let mock = InitializationMock::default();
    let mut node = migration_dpu_node();
    node.metadata.labels = Some(BTreeMap::from([
        (
            "test.nvidia.com/dpu-enabled".to_string(),
            "true".to_string(),
        ),
        (
            "external.nvidia.com/label".to_string(),
            "preserved".to_string(),
        ),
    ]));
    mock.nodes.insert(resource_key(&node), node);
    let sdk = DpfSdkBuilder::new(mock.clone(), TEST_NS, String::new())
        .with_labeler(MigrationLabeler)
        .build_without_resources()
        .await
        .expect("migration SDK");

    let error = sdk
        .transfer_dpu_node_deployment_labels(
            TEST_NODE_NAME,
            DpuDeploymentType::Bf3,
            DpuDeploymentType::Bf3Gb200,
        )
        .await
        .expect_err("unrelated DPUNode must be rejected");

    assert!(matches!(error, DpfError::InvalidState(_)));
    assert!(mock.node_patches.lock().unwrap().is_empty());
}

/// Deployment-scoped reads require one unambiguous live deployment selector.
#[tokio::test]
async fn deployment_phase_requires_exactly_one_target_deployment() {
    for (name, deployment_count, expected_message) in [
        ("no matching deployment", 0, "no DPUDeployment selects"),
        (
            "multiple matching deployments",
            2,
            "multiple DPUDeployments select",
        ),
    ] {
        let mock = InitializationMock::default();
        for index in 0..deployment_count {
            let deployment = migration_deployment(
                &format!("target-deployment-{index}"),
                DpuDeploymentType::Bf3Gb200,
                true,
            );
            mock.deployments
                .insert(resource_key(&deployment), deployment);
        }

        let error = target_dpu_phase(mock).await.expect_err(name);
        assert!(
            matches!(&error, DpfError::InvalidState(message) if message.contains(expected_message)),
            "{name}: {error}"
        );
    }
}

/// Target phase reads are owner-scoped; work in progress can be reported by
/// ownership alone, while Ready requires matching flavor and installed BFB.
#[tokio::test]
async fn target_deployment_phase_checks_ownership_and_ready_configuration() {
    struct Case {
        name: &'static str,
        owner: &'static str,
        phase: DpuStatusPhase,
        flavor: &'static str,
        installed_bfb_file: Option<&'static str>,
        expected_phase: Option<DpuPhase>,
        expects_error: bool,
    }

    let cases = [
        Case {
            name: "source still owns the DPU",
            owner: SOURCE_DEPLOYMENT,
            phase: DpuStatusPhase::Ready,
            flavor: TEST_FLAVOR,
            installed_bfb_file: Some("/bfb/sdk-init-ns-bf-bundle-abc.bfb"),
            expected_phase: None,
            expects_error: false,
        },
        Case {
            name: "target owns a DPU still installing",
            owner: TARGET_DEPLOYMENT,
            phase: DpuStatusPhase::OsInstalling,
            flavor: "old-flavor",
            installed_bfb_file: None,
            expected_phase: Some(DpuPhase::Provisioning("OsInstalling".to_string())),
            expects_error: false,
        },
        Case {
            name: "target owns a matching Ready DPU",
            owner: TARGET_DEPLOYMENT,
            phase: DpuStatusPhase::Ready,
            flavor: TEST_FLAVOR,
            installed_bfb_file: Some("/bfb/sdk-init-ns-bf-bundle-abc.bfb"),
            expected_phase: Some(DpuPhase::Ready),
            expects_error: false,
        },
        Case {
            name: "Ready flavor drift",
            owner: TARGET_DEPLOYMENT,
            phase: DpuStatusPhase::Ready,
            flavor: "old-flavor",
            installed_bfb_file: Some("/bfb/sdk-init-ns-bf-bundle-abc.bfb"),
            expected_phase: None,
            expects_error: true,
        },
        Case {
            name: "Ready BFB drift",
            owner: TARGET_DEPLOYMENT,
            phase: DpuStatusPhase::Ready,
            flavor: TEST_FLAVOR,
            installed_bfb_file: Some("/bfb/sdk-init-ns-bf-bundle-old.bfb"),
            expected_phase: None,
            expects_error: true,
        },
    ];

    for case in cases {
        let mock = InitializationMock::default();
        let deployment = migration_deployment(TARGET_DEPLOYMENT, DpuDeploymentType::Bf3Gb200, true);
        mock.deployments
            .insert(resource_key(&deployment), deployment);
        let dpu = migration_dpu(
            case.owner,
            case.phase,
            case.flavor,
            case.installed_bfb_file,
            "dpu-uid",
        );
        mock.dpus.insert(resource_key(&dpu), dpu);

        let result = target_dpu_phase(mock.clone()).await;
        if case.expects_error {
            assert!(
                matches!(result, Err(DpfError::InvalidState(_))),
                "{}: {result:?}",
                case.name
            );
        } else {
            assert_eq!(result.unwrap(), case.expected_phase, "{}", case.name);
        }
        assert_eq!(
            *mock.dpu_list_selectors.lock().unwrap(),
            vec![Some(format!(
                "{OWNED_BY_DEPLOYMENT_LABEL}={TEST_NS}_{TARGET_DEPLOYMENT}"
            ))],
            "{}",
            case.name
        );
    }
}

/// Source deletion uses the observed UID and a retry preserves a replacement
/// already owned by the target deployment.
#[tokio::test]
async fn deployment_migration_deletion_is_uid_guarded_and_preserves_target_replacement() {
    let mock = InitializationMock::default();
    for (name, deployment_type) in [
        (SOURCE_DEPLOYMENT, DpuDeploymentType::Bf3),
        (TARGET_DEPLOYMENT, DpuDeploymentType::Bf3Gb200),
    ] {
        let deployment = migration_deployment(name, deployment_type, true);
        mock.deployments
            .insert(resource_key(&deployment), deployment);
    }
    let source_dpu = migration_dpu(
        SOURCE_DEPLOYMENT,
        DpuStatusPhase::Ready,
        TEST_FLAVOR,
        Some("/bfb/sdk-init-ns-bf-bundle-abc.bfb"),
        "source-uid",
    );
    mock.dpus.insert(resource_key(&source_dpu), source_dpu);
    let sdk = DpfSdkBuilder::new(mock.clone(), TEST_NS, String::new())
        .with_labeler(MigrationLabeler)
        .build_without_resources()
        .await
        .expect("migration SDK");

    sdk.delete_source_dpus_for_deployment_migration(
        &["001".to_string()],
        TEST_NODE_NAME,
        DpuDeploymentType::Bf3,
        DpuDeploymentType::Bf3Gb200,
    )
    .await
    .expect("source DPU deletion");
    assert!(
        DpuRepository::get(&mock, TEST_DPU_NAME, TEST_NS)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        *mock.dpu_uid_deletes.lock().unwrap(),
        vec![(TEST_DPU_NAME.to_string(), "source-uid".to_string())]
    );

    let target_replacement = migration_dpu(
        TARGET_DEPLOYMENT,
        DpuStatusPhase::OsInstalling,
        TEST_FLAVOR,
        None,
        "target-uid",
    );
    mock.dpus
        .insert(resource_key(&target_replacement), target_replacement);
    sdk.delete_source_dpus_for_deployment_migration(
        &["001".to_string()],
        TEST_NODE_NAME,
        DpuDeploymentType::Bf3,
        DpuDeploymentType::Bf3Gb200,
    )
    .await
    .expect("migration retry");

    let replacement = DpuRepository::get(&mock, TEST_DPU_NAME, TEST_NS)
        .await
        .unwrap()
        .expect("target replacement must remain");
    assert_eq!(replacement.metadata.uid.as_deref(), Some("target-uid"));
    assert_eq!(mock.dpu_uid_deletes.lock().unwrap().len(), 1);
}

/// A conditional delete must preserve a replacement DPU whose UID differs
/// from the stale object observed by the migration reconciler.
#[tokio::test]
async fn conditional_dpu_delete_rejects_uid_mismatch() {
    let mock = InitializationMock::default();
    let dpu_name = "node-host-device-dpu";
    let mut replacement = super::helpers::make_dpu(
        TEST_NS,
        dpu_name,
        "device-dpu",
        "node-host",
        DpuStatusPhase::Ready,
    );
    replacement.metadata.uid = Some("replacement-uid".to_string());
    mock.dpus.insert(resource_key(&replacement), replacement);

    let error = DpuRepository::delete_if_uid(&mock, dpu_name, TEST_NS, "stale-uid")
        .await
        .expect_err("a stale UID must not delete the replacement DPU");

    assert!(matches!(error, DpfError::InvalidState(_)));
    assert!(
        DpuRepository::get(&mock, dpu_name, TEST_NS)
            .await
            .unwrap()
            .is_some(),
        "the replacement DPU must remain after the rejected delete"
    );
}

#[tokio::test]
async fn test_create_initialization_objects() {
    let mock = InitializationMock::default();

    let config = InitDpfResourcesConfig {
        bfb_url: "http://example.com/test.bfb".to_string(),
        ..Default::default()
    };
    let deployment_name = config.deployment_name.clone();

    let sdk = crate::sdk::DpfSdkBuilder::new(mock.clone(), TEST_NS, "test-password".to_string())
        .initialize(&config)
        .await
        .unwrap();

    let bfbs = BfbRepository::list(&mock, TEST_NS).await.unwrap();
    assert_eq!(bfbs.len(), 1);

    let expected_flavor_name = crate::flavor::default_flavor(TEST_NS, &config.proxy)
        .unwrap()
        .unique_name(crate::flavor::DEFAULT_FLAVOR_NAME)
        .unwrap();
    let flavor = DpuFlavorRepository::get(&mock, &expected_flavor_name, TEST_NS)
        .await
        .unwrap();
    assert!(flavor.is_some());

    let deployment = DpuDeploymentRepository::get(&mock, &deployment_name, TEST_NS)
        .await
        .unwrap();
    assert!(deployment.is_some());

    let secret = K8sConfigRepository::get_secret(&mock, "bmc-shared-password", TEST_NS)
        .await
        .unwrap();
    assert!(secret.is_some());

    drop(sdk);
}

/// Verifies BF3 and GB200 initialization persist separate flavor, service,
/// and selector wiring in a shared namespace.
#[tokio::test]
async fn bf3_and_gb200_initialization_persists_distinct_resources() {
    let mock = InitializationMock::default();
    let sdk = crate::sdk::DpfSdkBuilder::new(mock.clone(), TEST_NS, "test-password".to_string())
        .with_labeler(InitializationLabeler)
        .build_without_resources()
        .await
        .unwrap();

    let service_name = "test-service";
    let services = vec![ServiceDefinition::new(
        service_name,
        "repo",
        "chart",
        "1.0.0",
    )];
    for (deployment_name, deployment_type) in [
        ("bf3-deployment", DpuDeploymentType::Bf3),
        ("gb200-deployment", DpuDeploymentType::Bf3Gb200),
    ] {
        sdk.create_initialization_objects(&InitDpfResourcesConfig {
            bfb_url: "http://example.com/bf3.bfb".to_string(),
            deployment_name: deployment_name.to_string(),
            flavor_name: "bf3-flavor".to_string(),
            services: services.clone(),
            deployment_type,
            ..Default::default()
        })
        .await
        .unwrap();
    }

    let bf3_deployment = DpuDeploymentRepository::get(&mock, "bf3-deployment", TEST_NS)
        .await
        .unwrap()
        .expect("BF3 deployment must be persisted");
    let gb200_deployment = DpuDeploymentRepository::get(&mock, "gb200-deployment", TEST_NS)
        .await
        .unwrap()
        .expect("GB200 deployment must be persisted");
    assert_eq!(mock.deployments.len(), 2);

    let bf3_flavor_name = bf3_deployment
        .spec
        .dpus
        .flavor
        .as_deref()
        .expect("BF3 deployment must reference a flavor");
    let gb200_flavor_name = gb200_deployment
        .spec
        .dpus
        .flavor
        .as_deref()
        .expect("GB200 deployment must reference a flavor");
    assert_ne!(bf3_flavor_name, gb200_flavor_name);
    assert_eq!(mock.flavors.len(), 2);

    let bf3_flavor = DpuFlavorRepository::get(&mock, bf3_flavor_name, TEST_NS)
        .await
        .unwrap()
        .expect("BF3 deployment flavor must be persisted");
    let gb200_flavor = DpuFlavorRepository::get(&mock, gb200_flavor_name, TEST_NS)
        .await
        .unwrap()
        .expect("GB200 deployment flavor must be persisted");
    let bf3_nvconfig = bf3_flavor.spec.nvconfig.as_ref().unwrap()[0]
        .parameters
        .as_ref()
        .unwrap();
    let gb200_nvconfig = gb200_flavor.spec.nvconfig.as_ref().unwrap()[0]
        .parameters
        .as_ref()
        .unwrap();
    assert!(
        !bf3_nvconfig
            .iter()
            .any(|parameter| parameter == "OFF_BOARD_SERIALIZER=1")
    );
    assert!(
        bf3_nvconfig
            .iter()
            .any(|parameter| parameter == "PF_TOTAL_SF=30")
    );
    assert!(
        gb200_nvconfig
            .iter()
            .any(|parameter| parameter == "OFF_BOARD_SERIALIZER=1")
    );
    assert!(
        gb200_nvconfig
            .iter()
            .any(|parameter| parameter == "PF_TOTAL_SF=128")
    );

    let bf3_service = bf3_deployment
        .spec
        .services
        .get(service_name)
        .expect("BF3 deployment must reference the test service");
    assert_eq!(bf3_service.service_template.as_deref(), Some(service_name));
    assert_eq!(
        bf3_service.service_configuration.as_deref(),
        Some(service_name)
    );
    let gb200_service = gb200_deployment
        .spec
        .services
        .get(service_name)
        .expect("GB200 deployment must reference the test service");
    assert_eq!(
        gb200_service.service_template.as_deref(),
        Some("test-service-bf3gb200")
    );
    assert_eq!(
        gb200_service.service_configuration.as_deref(),
        Some("test-service-bf3gb200")
    );

    let selector_label = "test.nvidia.com/deployment-type";
    let bf3_selector_labels = bf3_deployment.spec.dpus.dpu_sets.as_ref().unwrap()[0]
        .dpu_node_selector
        .as_ref()
        .and_then(|selector| selector.match_labels.as_ref())
        .expect("BF3 deployment must have DPUNode selector labels");
    let gb200_selector_labels = gb200_deployment.spec.dpus.dpu_sets.as_ref().unwrap()[0]
        .dpu_node_selector
        .as_ref()
        .and_then(|selector| selector.match_labels.as_ref())
        .expect("GB200 deployment must have DPUNode selector labels");
    assert_eq!(
        bf3_selector_labels.get(selector_label).map(String::as_str),
        Some("bf3")
    );
    assert_eq!(
        gb200_selector_labels
            .get(selector_label)
            .map(String::as_str),
        Some("bf3gb200")
    );
}

#[tokio::test]
async fn test_create_initialization_objects_bluefield_software() {
    let mock = InitializationMock::default();

    let config = InitDpfResourcesConfig {
        bluefield_software: Some(BlueFieldSoftwareParams {
            os_iso: "http://example.com/os.iso".to_string(),
            pldm_fw_bundle: Some("http://example.com/fw.pldm".to_string()),
        }),
        deployment_name: "bf4-dep".to_string(),
        deployment_type: DpuDeploymentType::Bf4Generic,
        ..Default::default()
    };

    let sdk = crate::sdk::DpfSdkBuilder::new(mock.clone(), TEST_NS, "test-password".to_string())
        .initialize(&config)
        .await
        .unwrap();

    // A BlueFieldSoftware CR is created; no BFB is.
    let bfbs = BfbRepository::list(&mock, TEST_NS).await.unwrap();
    assert!(
        bfbs.is_empty(),
        "no BFB should be created for a BF4 deployment"
    );
    let bfsw = BlueFieldSoftwareRepository::list(&mock, TEST_NS)
        .await
        .unwrap();
    assert_eq!(bfsw.len(), 1);
    assert_eq!(bfsw[0].spec.os_iso, "http://example.com/os.iso");
    assert_eq!(
        bfsw[0].spec.pldm_fw_bundle.as_deref(),
        Some("http://example.com/fw.pldm")
    );

    // The DPUDeployment references the BlueFieldSoftware CR, not a BFB.
    let deployment = DpuDeploymentRepository::get(&mock, "bf4-dep", TEST_NS)
        .await
        .unwrap()
        .expect("bf4 deployment created");
    assert_eq!(
        deployment.spec.dpus.blue_field_software.as_deref(),
        Some(bfsw[0].metadata.name.as_deref().unwrap())
    );
    assert!(deployment.spec.dpus.bfb.is_none());

    drop(sdk);
}

/// Verifies a missing referenced template fails the complete inventory lookup
/// so callers cannot mistake an incomplete operator view for current state.
#[tokio::test]
async fn service_versions_fail_when_referenced_template_is_missing() {
    let mock = InitializationMock::default();
    let dpu_name = "node-host-device-dpu";
    let mut dpu = super::helpers::make_dpu(
        TEST_NS,
        dpu_name,
        "device-dpu",
        "node-host",
        DpuStatusPhase::Ready,
    );
    dpu.metadata.labels = Some(BTreeMap::from([(
        "svc.dpu.nvidia.com/owned-by-dpudeployment".to_string(),
        format!("{TEST_NS}_deployment"),
    )]));
    mock.dpus.insert(resource_key(&dpu), dpu);

    // Resolve one service before encountering the absent template to exercise
    // the partial-result path that must now be rejected.
    let services = vec![
        ServiceDefinition::new("a-present", "repo", "chart", "1.0.0"),
        ServiceDefinition::new("z-missing", "repo", "chart", "2.0.0"),
    ];
    let deployment = crate::sdk::build_deployment(
        &services,
        "deployment",
        &crate::sdk::DpuProvisioningSource::Bfb("bfb".to_string()),
        "flavor",
        TEST_NS,
        &[],
        BTreeMap::new(),
        crate::types::DpuDeploymentType::Bf3,
    );
    DpuDeploymentRepository::apply(&mock, &deployment)
        .await
        .unwrap();
    DpuServiceTemplateRepository::apply(
        &mock,
        &crate::sdk::build_service_template(&services[0], TEST_NS, ""),
    )
    .await
    .unwrap();
    let sdk = crate::sdk::DpfSdkBuilder::new(mock, TEST_NS, String::new())
        .build_without_resources()
        .await
        .unwrap();

    // The missing reference invalidates the whole snapshot rather than
    // returning only the service whose template was available.
    let error = sdk
        .get_service_versions_for_dpu(dpu_name)
        .await
        .expect_err("missing referenced template must fail inventory lookup");
    let DpfError::InvalidState(message) = error else {
        panic!("expected invalid state, got {error}");
    };
    assert!(message.contains(
        "DPUServiceTemplate z-missing not found for service z-missing in DPUDeployment deployment"
    ));
}
