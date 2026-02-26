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

//! Tests for releasing the DPF maintenance hold annotation.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use kube::core::ObjectMeta;

use crate::crds::dpunodemaintenances_generated::*;
use crate::error::DpfError;
use crate::repository::DpuNodeMaintenanceRepository;
use crate::sdk::{DpfSdk, HOLD_ANNOTATION};

const TEST_NS: &str = "sdk-maintenance-ns";

#[derive(Clone, Default)]
struct MaintenanceHoldMock {
    maintenances: Arc<RwLock<BTreeMap<String, DPUNodeMaintenance>>>,
}

impl MaintenanceHoldMock {
    fn insert(&self, m: &DPUNodeMaintenance) {
        let key = m.metadata.name.clone().unwrap_or_default();
        self.maintenances.write().unwrap().insert(key, m.clone());
    }

    fn get(&self, name: &str) -> Option<DPUNodeMaintenance> {
        self.maintenances.read().unwrap().get(name).cloned()
    }
}

#[async_trait]
impl DpuNodeMaintenanceRepository for MaintenanceHoldMock {
    async fn get(&self, name: &str, _: &str) -> Result<Option<DPUNodeMaintenance>, DpfError> {
        Ok(self.maintenances.read().unwrap().get(name).cloned())
    }
    async fn patch(&self, name: &str, _: &str, patch: serde_json::Value) -> Result<(), DpfError> {
        if let Some(m) = self.maintenances.write().unwrap().get_mut(name)
            && let Some(annos) = patch
                .pointer("/metadata/annotations")
                .and_then(|v| v.as_object())
        {
            let m_annos = m.metadata.annotations.get_or_insert_with(BTreeMap::new);
            for (k, v) in annos {
                if v.is_null() {
                    m_annos.remove(k);
                } else if let Some(s) = v.as_str() {
                    m_annos.insert(k.clone(), s.to_string());
                }
            }
        }
        Ok(())
    }
}

#[tokio::test]
async fn test_release_maintenance_hold_sets_annotation_false() {
    let mock = MaintenanceHoldMock::default();
    let sdk = DpfSdk::new(mock.clone(), TEST_NS);

    // Pre-populate a DPUNodeMaintenance with hold annotation set to "true"
    let maint = DPUNodeMaintenance {
        metadata: ObjectMeta {
            name: Some("dpu-node-host-001-hold".into()),
            namespace: Some(TEST_NS.into()),
            annotations: Some(BTreeMap::from([(HOLD_ANNOTATION.into(), "true".into())])),
            ..Default::default()
        },
        spec: DpuNodeMaintenanceSpec {
            dpu_node_name: "dpu-node-host-001".into(),
            node_effect: None,
            requestor: None,
        },
        status: None,
    };
    mock.insert(&maint);

    // Verify hold is true
    let m = mock.get("dpu-node-host-001-hold").unwrap();
    assert_eq!(
        m.metadata
            .annotations
            .as_ref()
            .unwrap()
            .get(HOLD_ANNOTATION),
        Some(&"true".to_string())
    );

    // Release the maintenance hold
    sdk.release_maintenance_hold("dpu-node-host-001")
        .await
        .unwrap();

    // Hold annotation should now be "false"
    let m = mock.get("dpu-node-host-001-hold").unwrap();
    assert_eq!(
        m.metadata
            .annotations
            .as_ref()
            .unwrap()
            .get(HOLD_ANNOTATION),
        Some(&"false".to_string())
    );
}
