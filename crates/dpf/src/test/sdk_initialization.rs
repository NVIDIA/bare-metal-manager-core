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

//! Tests for DPF SDK initialization object creation.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use dashmap::DashMap;
use kube::Resource;

use crate::crds::bfbs_generated::BFB;
use crate::crds::dpudeployments_generated::DPUDeployment;
use crate::crds::dpuflavors_generated::DPUFlavor;
use crate::crds::dpuserviceconfigurations_generated::DPUServiceConfiguration;
use crate::crds::dpuserviceinterfaces_generated::DPUServiceInterface;
use crate::crds::dpuservicenads_generated::DPUServiceNAD;
use crate::crds::dpuservicetemplates_generated::DPUServiceTemplate;
use crate::error::DpfError;
use crate::repository::{
    BfbRepository, DpfOperatorConfigRepository, DpuDeploymentRepository, DpuFlavorRepository,
    DpuServiceConfigurationRepository, DpuServiceInterfaceRepository, DpuServiceNADRepository,
    DpuServiceTemplateRepository, K8sConfigRepository,
};
use crate::types::*;

const TEST_NS: &str = "sdk-init-ns";

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
    flavors: Arc<DashMap<String, DPUFlavor>>,
    deployments: Arc<DashMap<String, DPUDeployment>>,
    service_templates: Arc<DashMap<String, DPUServiceTemplate>>,
    service_configs: Arc<DashMap<String, DPUServiceConfiguration>>,
    nads: Arc<DashMap<String, DPUServiceNAD>>,
    service_interfaces: Arc<DashMap<String, DPUServiceInterface>>,
    configs: Arc<DashMap<String, BTreeMap<String, String>>>,
    secrets: Arc<DashMap<String, BTreeMap<String, Vec<u8>>>>,
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
            dep.spec.dpus.bfb = bfb.to_string();
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
    async fn create_secret(
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

    let flavor = DpuFlavorRepository::get(&mock, crate::flavor::DEFAULT_FLAVOR_NAME, TEST_NS)
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
