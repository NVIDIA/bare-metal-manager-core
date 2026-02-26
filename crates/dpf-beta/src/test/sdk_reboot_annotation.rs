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

//! Tests for reboot annotation set/check/clear via DPF SDK.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use kube::Resource;

use crate::crds::dpunodes_generated::*;
use crate::error::DpfError;
use crate::repository::DpuNodeRepository;
use crate::sdk::{DpfSdk, RESTART_ANNOTATION};
use crate::types::*;

const TEST_NS: &str = "sdk-reboot-ns";

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
struct RebootAnnotationMock {
    nodes: Arc<RwLock<BTreeMap<String, DPUNode>>>,
}

#[async_trait]
impl DpuNodeRepository for RebootAnnotationMock {
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
    async fn create(&self, node: &DPUNode) -> Result<DPUNode, DpfError> {
        self.nodes
            .write()
            .unwrap()
            .insert(resource_key(node), node.clone());
        Ok(node.clone())
    }
    async fn patch(&self, name: &str, ns: &str, patch: serde_json::Value) -> Result<(), DpfError> {
        if let Some(node) = self.nodes.write().unwrap().get_mut(&ns_key(ns, name))
            && let Some(annos) = patch
                .pointer("/metadata/annotations")
                .and_then(|v| v.as_object())
        {
            let node_annos = node.metadata.annotations.get_or_insert_with(BTreeMap::new);
            for (k, v) in annos {
                if v.is_null() {
                    node_annos.remove(k);
                } else if let Some(s) = v.as_str() {
                    node_annos.insert(k.clone(), s.to_string());
                }
            }
        }
        Ok(())
    }
    async fn delete(&self, name: &str, ns: &str) -> Result<(), DpfError> {
        self.nodes.write().unwrap().remove(&ns_key(ns, name));
        Ok(())
    }
}

#[tokio::test]
async fn test_reboot_annotation_set_check_clear() {
    let mock = RebootAnnotationMock::default();
    let sdk = DpfSdk::new(mock.clone(), TEST_NS);

    // Register a DPU node
    let node_info = DpuNodeInfo {
        node_id: "host-001".to_string(),
        host_bmc_ip: "192.168.1.1".to_string(),
        dpu_device_names: vec!["dpu-001".to_string()],
    };
    sdk.register_dpu_node(node_info).await.unwrap();

    let node_name = "dpu-node-host-001";

    // No annotation set yet
    assert!(!sdk.is_reboot_required(node_name).await.unwrap());

    // Simulate operator setting the reboot annotation
    DpuNodeRepository::patch(
        &mock,
        node_name,
        TEST_NS,
        serde_json::json!({
            "metadata": {
                "annotations": {
                    RESTART_ANNOTATION: "true"
                }
            }
        }),
    )
    .await
    .unwrap();

    // Now reboot should be required
    assert!(sdk.is_reboot_required(node_name).await.unwrap());

    // Clear the reboot annotation
    sdk.reboot_complete(node_name).await.unwrap();

    // Reboot should no longer be required
    assert!(!sdk.is_reboot_required(node_name).await.unwrap());
}
