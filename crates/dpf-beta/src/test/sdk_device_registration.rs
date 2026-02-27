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

//! Tests for DPU device and node registration and force delete.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use kube::Resource;

use crate::crds::dpudevices_generated::DPUDevice;
use crate::crds::dpunodes_generated::*;
use crate::crds::dpus_generated::*;
use crate::error::DpfError;
use crate::repository::{DpuDeviceRepository, DpuNodeRepository, DpuRepository};
use crate::sdk::DpfSdk;
use crate::types::*;

const TEST_NS: &str = "sdk-device-reg-ns";

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
struct DeviceRegistrationMock {
    devices: Arc<RwLock<BTreeMap<String, DPUDevice>>>,
    nodes: Arc<RwLock<BTreeMap<String, DPUNode>>>,
}

#[async_trait]
impl DpuDeviceRepository for DeviceRegistrationMock {
    async fn get(&self, name: &str, ns: &str) -> Result<Option<DPUDevice>, DpfError> {
        Ok(self.devices.read().unwrap().get(&ns_key(ns, name)).cloned())
    }
    async fn list(&self, ns: &str) -> Result<Vec<DPUDevice>, DpfError> {
        Ok(self
            .devices
            .read()
            .unwrap()
            .iter()
            .filter(|(k, _)| k.starts_with(&format!("{}/", ns)))
            .map(|(_, v)| v.clone())
            .collect())
    }
    async fn create(&self, d: &DPUDevice) -> Result<DPUDevice, DpfError> {
        self.devices
            .write()
            .unwrap()
            .insert(resource_key(d), d.clone());
        Ok(d.clone())
    }
    async fn delete(&self, name: &str, ns: &str) -> Result<(), DpfError> {
        self.devices.write().unwrap().remove(&ns_key(ns, name));
        Ok(())
    }
}

#[async_trait]
impl DpuNodeRepository for DeviceRegistrationMock {
    async fn get(&self, name: &str, ns: &str) -> Result<Option<DPUNode>, DpfError> {
        Ok(self.nodes.read().unwrap().get(&ns_key(ns, name)).cloned())
    }
    async fn list(&self, ns: &str) -> Result<Vec<DPUNode>, DpfError> {
        Ok(self
            .nodes
            .read()
            .unwrap()
            .iter()
            .filter(|(k, _)| k.starts_with(&format!("{}/", ns)))
            .map(|(_, v)| v.clone())
            .collect())
    }
    async fn create(&self, n: &DPUNode) -> Result<DPUNode, DpfError> {
        self.nodes
            .write()
            .unwrap()
            .insert(resource_key(n), n.clone());
        Ok(n.clone())
    }
    async fn patch(&self, _: &str, _: &str, _: serde_json::Value) -> Result<(), DpfError> {
        Ok(())
    }
    async fn delete(&self, name: &str, ns: &str) -> Result<(), DpfError> {
        self.nodes.write().unwrap().remove(&ns_key(ns, name));
        Ok(())
    }
}

#[async_trait]
impl DpuRepository for DeviceRegistrationMock {
    async fn get(&self, _: &str, _: &str) -> Result<Option<DPU>, DpfError> {
        Ok(None)
    }
    async fn list(&self, _: &str) -> Result<Vec<DPU>, DpfError> {
        Ok(vec![])
    }
    async fn patch_status(&self, _: &str, _: &str, _: serde_json::Value) -> Result<(), DpfError> {
        Ok(())
    }
    async fn delete(&self, _: &str, _: &str) -> Result<(), DpfError> {
        Ok(())
    }
    fn watch<F, Fut>(&self, _: &str, _handler: F) -> impl Future<Output = ()> + Send + 'static
    where
        F: Fn(Arc<DPU>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), DpfError>> + Send + 'static,
    {
        futures::future::pending()
    }
}

#[tokio::test]
async fn test_register_devices_node_and_force_delete() {
    let mock = DeviceRegistrationMock::default();
    let sdk = DpfSdk::new(mock.clone(), TEST_NS);

    // Register devices
    for i in 1..=2 {
        let info = DpuDeviceInfo {
            device_name: format!("dpu-{}", i),
            dpu_bmc_ip: format!("192.168.1.{}", 100 + i),
            host_bmc_ip: "192.168.1.1".to_string(),
            serial_number: format!("SN-{}", i),
        };
        sdk.register_dpu_device(info).await.unwrap();
    }

    // Register node
    let node_info = DpuNodeInfo {
        node_id: "host-001".to_string(),
        host_bmc_ip: "192.168.1.1".to_string(),
        dpu_device_names: vec!["dpu-1".to_string(), "dpu-2".to_string()],
    };
    sdk.register_dpu_node(node_info).await.unwrap();

    assert_eq!(
        DpuDeviceRepository::list(&mock, TEST_NS)
            .await
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        DpuNodeRepository::list(&mock, TEST_NS).await.unwrap().len(),
        1
    );

    // Force delete
    let dpu_ids = vec!["dpu-1".to_string(), "dpu-2".to_string()];
    sdk.force_delete_host("dpu-node-host-001", &dpu_ids)
        .await
        .unwrap();

    assert_eq!(
        DpuDeviceRepository::list(&mock, TEST_NS)
            .await
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        DpuNodeRepository::list(&mock, TEST_NS).await.unwrap().len(),
        0
    );
}
