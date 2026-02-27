/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

//! Repository traits for DPF CRD operations.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Arc;

use async_trait::async_trait;

use crate::crds::bfbs_generated::BFB;
use crate::crds::dpuclusters_generated::DPUCluster;
use crate::crds::dpudeployments_generated::DPUDeployment;
use crate::crds::dpudevices_generated::DPUDevice;
use crate::crds::dpuflavors_generated::DPUFlavor;
use crate::crds::dpunodemaintenances_generated::DPUNodeMaintenance;
use crate::crds::dpunodes_generated::DPUNode;
use crate::crds::dpus_generated::DPU;
use crate::crds::dpuservicechains_generated::DPUServiceChain;
use crate::crds::dpuserviceconfigurations_generated::DPUServiceConfiguration;
use crate::crds::dpuserviceinterfaces_generated::DPUServiceInterface;
use crate::crds::dpuservices_generated::DPUService;
use crate::crds::dpuservicetemplates_generated::DPUServiceTemplate;
use crate::crds::dpusets_generated::DPUSet;
use crate::error::DpfError;

/// Repository for BFB (BlueField Bundle) resources.
#[async_trait]
pub trait BfbRepository: Send + Sync {
    async fn get(&self, name: &str, namespace: &str) -> Result<Option<BFB>, DpfError>;
    async fn list(&self, namespace: &str) -> Result<Vec<BFB>, DpfError>;
    async fn create(&self, bfb: &BFB) -> Result<BFB, DpfError>;
    async fn delete(&self, name: &str, namespace: &str) -> Result<(), DpfError>;
}

/// Repository for DPU resources.
#[async_trait]
pub trait DpuRepository: Send + Sync {
    async fn get(&self, name: &str, namespace: &str) -> Result<Option<DPU>, DpfError>;
    async fn list(&self, namespace: &str) -> Result<Vec<DPU>, DpfError>;
    async fn patch_status(
        &self,
        name: &str,
        namespace: &str,
        patch: serde_json::Value,
    ) -> Result<(), DpfError>;
    async fn delete(&self, name: &str, namespace: &str) -> Result<(), DpfError>;

    /// Watch for DPU changes and invoke the handler for each object.
    ///
    /// The returned future runs until the watch is cancelled. The handler's
    /// `Result` signals whether the event was processed; implementations may
    /// retry on `Err`.
    fn watch<F, Fut>(
        &self,
        namespace: &str,
        handler: F,
    ) -> impl Future<Output = ()> + Send + 'static
    where
        F: Fn(Arc<DPU>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), DpfError>> + Send + 'static;
}

/// Repository for DPUDevice resources.
#[async_trait]
pub trait DpuDeviceRepository: Send + Sync {
    async fn get(&self, name: &str, namespace: &str) -> Result<Option<DPUDevice>, DpfError>;
    async fn list(&self, namespace: &str) -> Result<Vec<DPUDevice>, DpfError>;
    async fn create(&self, device: &DPUDevice) -> Result<DPUDevice, DpfError>;
    async fn delete(&self, name: &str, namespace: &str) -> Result<(), DpfError>;
}

/// Repository for DPUNode resources.
#[async_trait]
pub trait DpuNodeRepository: Send + Sync {
    async fn get(&self, name: &str, namespace: &str) -> Result<Option<DPUNode>, DpfError>;
    async fn list(&self, namespace: &str) -> Result<Vec<DPUNode>, DpfError>;
    async fn create(&self, node: &DPUNode) -> Result<DPUNode, DpfError>;
    async fn patch(
        &self,
        name: &str,
        namespace: &str,
        patch: serde_json::Value,
    ) -> Result<(), DpfError>;
    async fn delete(&self, name: &str, namespace: &str) -> Result<(), DpfError>;
}

/// Repository for DPUNodeMaintenance resources.
#[async_trait]
pub trait DpuNodeMaintenanceRepository: Send + Sync {
    async fn get(
        &self,
        name: &str,
        namespace: &str,
    ) -> Result<Option<DPUNodeMaintenance>, DpfError>;
    async fn patch(
        &self,
        name: &str,
        namespace: &str,
        patch: serde_json::Value,
    ) -> Result<(), DpfError>;
}

/// Repository for DPUFlavor resources.
#[async_trait]
pub trait DpuFlavorRepository: Send + Sync {
    async fn get(&self, name: &str, namespace: &str) -> Result<Option<DPUFlavor>, DpfError>;
    async fn create(&self, flavor: &DPUFlavor) -> Result<DPUFlavor, DpfError>;
}

/// Repository for DPUSet resources.
#[async_trait]
pub trait DpuSetRepository: Send + Sync {
    async fn get(&self, name: &str, namespace: &str) -> Result<Option<DPUSet>, DpfError>;
    async fn apply(&self, set: &DPUSet) -> Result<DPUSet, DpfError>;
}

/// Repository for DPUCluster resources.
#[async_trait]
pub trait DpuClusterRepository: Send + Sync {
    async fn get(&self, name: &str, namespace: &str) -> Result<Option<DPUCluster>, DpfError>;
    async fn list(&self, namespace: &str) -> Result<Vec<DPUCluster>, DpfError>;
}

/// Repository for DPUDeployment resources.
#[async_trait]
pub trait DpuDeploymentRepository: Send + Sync {
    async fn get(&self, name: &str, namespace: &str) -> Result<Option<DPUDeployment>, DpfError>;
    async fn list(&self, namespace: &str) -> Result<Vec<DPUDeployment>, DpfError>;
    async fn apply(&self, deployment: &DPUDeployment) -> Result<DPUDeployment, DpfError>;
    async fn patch(
        &self,
        name: &str,
        namespace: &str,
        patch: serde_json::Value,
    ) -> Result<(), DpfError>;
    async fn delete(&self, name: &str, namespace: &str) -> Result<(), DpfError>;
}

/// Repository for DPUServiceTemplate resources.
#[async_trait]
pub trait DpuServiceTemplateRepository: Send + Sync {
    async fn get(
        &self,
        name: &str,
        namespace: &str,
    ) -> Result<Option<DPUServiceTemplate>, DpfError>;
    async fn list(&self, namespace: &str) -> Result<Vec<DPUServiceTemplate>, DpfError>;
    async fn apply(&self, template: &DPUServiceTemplate) -> Result<DPUServiceTemplate, DpfError>;
}

/// Repository for DPUServiceConfiguration resources.
#[async_trait]
pub trait DpuServiceConfigurationRepository: Send + Sync {
    async fn get(
        &self,
        name: &str,
        namespace: &str,
    ) -> Result<Option<DPUServiceConfiguration>, DpfError>;
    async fn list(&self, namespace: &str) -> Result<Vec<DPUServiceConfiguration>, DpfError>;
    async fn apply(
        &self,
        config: &DPUServiceConfiguration,
    ) -> Result<DPUServiceConfiguration, DpfError>;
}

/// Repository for DPUService resources.
#[async_trait]
pub trait DpuServiceRepository: Send + Sync {
    async fn get(&self, name: &str, namespace: &str) -> Result<Option<DPUService>, DpfError>;
    async fn list(&self, namespace: &str) -> Result<Vec<DPUService>, DpfError>;
}

/// Repository for DPUServiceChain resources.
#[async_trait]
pub trait DpuServiceChainRepository: Send + Sync {
    async fn get(&self, name: &str, namespace: &str) -> Result<Option<DPUServiceChain>, DpfError>;
    async fn list(&self, namespace: &str) -> Result<Vec<DPUServiceChain>, DpfError>;
}

/// Repository for DPUServiceInterface resources.
#[async_trait]
pub trait DpuServiceInterfaceRepository: Send + Sync {
    async fn get(
        &self,
        name: &str,
        namespace: &str,
    ) -> Result<Option<DPUServiceInterface>, DpfError>;
    async fn list(&self, namespace: &str) -> Result<Vec<DPUServiceInterface>, DpfError>;
}

/// Repository for Kubernetes ConfigMaps and Secrets.
#[async_trait]
pub trait K8sConfigRepository: Send + Sync {
    async fn get_configmap(
        &self,
        name: &str,
        namespace: &str,
    ) -> Result<Option<BTreeMap<String, String>>, DpfError>;
    async fn apply_configmap(
        &self,
        name: &str,
        namespace: &str,
        data: BTreeMap<String, String>,
    ) -> Result<(), DpfError>;
    async fn get_secret(
        &self,
        name: &str,
        namespace: &str,
    ) -> Result<Option<BTreeMap<String, Vec<u8>>>, DpfError>;
    async fn create_secret(
        &self,
        name: &str,
        namespace: &str,
        data: BTreeMap<String, Vec<u8>>,
    ) -> Result<(), DpfError>;
}

/// Combined trait for all DPF repository operations.
///
/// Implementors of this trait provide access to all DPF CRD operations,
/// enabling the SDK to work with any backend (real K8s, mock, etc.).
pub trait DpfRepository:
    BfbRepository
    + DpuRepository
    + DpuDeviceRepository
    + DpuNodeRepository
    + DpuNodeMaintenanceRepository
    + DpuFlavorRepository
    + DpuSetRepository
    + DpuClusterRepository
    + DpuDeploymentRepository
    + DpuServiceTemplateRepository
    + DpuServiceConfigurationRepository
    + DpuServiceRepository
    + DpuServiceChainRepository
    + DpuServiceInterfaceRepository
    + K8sConfigRepository
    + Send
    + Sync
{
}
