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

//! `DpfSdk::is_dpu_outdated`, the single-DPU staleness check that gates work
//! which must not land on a DPU still awaiting reprovisioning.
//!
//! Every path that cannot produce a confident "this DPU is current" must report
//! `true`, because the caller's safe action is to do nothing.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Arc;

use async_trait::async_trait;
use dashmap::DashMap;
use kube::core::ObjectMeta;

use crate::crds::dpudeployments_generated::DPUDeployment;
use crate::crds::dpus_generated::DPU;
use crate::crds::dpuservicetemplates_generated::DPUServiceTemplate;
use crate::error::DpfError;
use crate::repository::{
    DpuDeploymentRepository, DpuRepository, DpuServiceTemplateRepository, K8sConfigRepository,
};
use crate::sdk::DpfSdkBuilder;

const TEST_NS: &str = "test-namespace";
const DEPLOYMENT: &str = "test-deployment";
const FLAVOR: &str = "test-flavor";
const DPU_NAME: &str = "node-host-001-device-001";
const OWNED_BY_LABEL: &str = "svc.dpu.nvidia.com/owned-by-dpudeployment";

#[derive(Default, Clone)]
struct OutdatedDpuMock {
    dpus: Arc<DashMap<String, DPU>>,
    deployments: Arc<DashMap<String, DPUDeployment>>,
}

impl OutdatedDpuMock {
    fn with(dpu: DPU, deployment: DPUDeployment) -> Self {
        let mock = Self::default();
        mock.dpus.insert(DPU_NAME.to_string(), dpu);
        mock.deployments.insert(DEPLOYMENT.to_string(), deployment);
        mock
    }
}

#[async_trait]
impl DpuRepository for OutdatedDpuMock {
    async fn get(&self, name: &str, _ns: &str) -> Result<Option<DPU>, DpfError> {
        Ok(self.dpus.get(name).map(|dpu| dpu.clone()))
    }
    async fn list(&self, _ns: &str, _selector: Option<&str>) -> Result<Vec<DPU>, DpfError> {
        Ok(self.dpus.iter().map(|e| e.value().clone()).collect())
    }
    async fn patch_status(
        &self,
        _name: &str,
        _ns: &str,
        _patch: serde_json::Value,
    ) -> Result<(), DpfError> {
        Ok(())
    }
    async fn delete(&self, _name: &str, _ns: &str) -> Result<(), DpfError> {
        Ok(())
    }
    fn watch<F, Fut>(
        &self,
        _ns: &str,
        _selector: Option<&str>,
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
impl DpuDeploymentRepository for OutdatedDpuMock {
    async fn get(&self, name: &str, _ns: &str) -> Result<Option<DPUDeployment>, DpfError> {
        Ok(self.deployments.get(name).map(|d| d.clone()))
    }
    async fn list(&self, _ns: &str) -> Result<Vec<DPUDeployment>, DpfError> {
        Ok(self.deployments.iter().map(|e| e.value().clone()).collect())
    }
    async fn apply(&self, d: &DPUDeployment) -> Result<DPUDeployment, DpfError> {
        Ok(d.clone())
    }
    async fn patch(
        &self,
        _name: &str,
        _ns: &str,
        _patch: serde_json::Value,
    ) -> Result<(), DpfError> {
        Ok(())
    }
    async fn delete(&self, _name: &str, _ns: &str) -> Result<(), DpfError> {
        Ok(())
    }
}

/// Required by `build_without_resources`; nothing here reads config or secrets.
#[async_trait]
impl K8sConfigRepository for OutdatedDpuMock {
    async fn get_configmap(
        &self,
        _: &str,
        _: &str,
    ) -> Result<Option<BTreeMap<String, String>>, DpfError> {
        Ok(None)
    }
    async fn apply_configmap(
        &self,
        _: &str,
        _: &str,
        _: BTreeMap<String, String>,
    ) -> Result<(), DpfError> {
        Ok(())
    }
    async fn get_secret(
        &self,
        _: &str,
        _: &str,
    ) -> Result<Option<BTreeMap<String, Vec<u8>>>, DpfError> {
        Ok(None)
    }
    async fn apply_secret(
        &self,
        _: &str,
        _: &str,
        _: BTreeMap<String, Vec<u8>>,
    ) -> Result<(), DpfError> {
        Ok(())
    }
}

#[async_trait]
impl DpuServiceTemplateRepository for OutdatedDpuMock {
    async fn get(&self, _name: &str, _ns: &str) -> Result<Option<DPUServiceTemplate>, DpfError> {
        Ok(None)
    }
    async fn list(&self, _ns: &str) -> Result<Vec<DPUServiceTemplate>, DpfError> {
        Ok(vec![])
    }
    async fn apply(&self, t: &DPUServiceTemplate) -> Result<DPUServiceTemplate, DpfError> {
        Ok(t.clone())
    }
}

/// A DPU owned by [`DEPLOYMENT`], built through serde so the literal names only
/// the fields these tests care about.
fn dpu(
    bfb: Option<&str>,
    blue_field_software: Option<&str>,
    installed_bfb_file: Option<&str>,
    flavor: &str,
) -> DPU {
    let spec = serde_json::json!({
        "bfb": bfb,
        "blueFieldSoftware": blue_field_software,
        "dpuDeviceName": "device-001",
        "dpuFlavor": flavor,
        "dpuNodeName": "node-host-001",
        "nodeEffect": {},
        "serialNumber": "SN123",
    });
    let status = serde_json::json!({
        "phase": "Ready",
        "bfbFile": installed_bfb_file,
    });

    DPU {
        metadata: ObjectMeta {
            name: Some(DPU_NAME.to_string()),
            namespace: Some(TEST_NS.to_string()),
            labels: Some(BTreeMap::from([(
                OWNED_BY_LABEL.to_string(),
                format!("{TEST_NS}_{DEPLOYMENT}"),
            )])),
            ..Default::default()
        },
        spec: serde_json::from_value(spec).expect("valid DpuSpec"),
        status: Some(serde_json::from_value(status).expect("valid DpuStatus")),
    }
}

/// `ready` controls whether `DPUSetsReconciled` is `True` at the current
/// generation, which is what [`dpu_deployment_is_ready`] requires.
fn deployment(bfb: Option<&str>, blue_field_software: Option<&str>, ready: bool) -> DPUDeployment {
    let spec = serde_json::json!({
        "dpus": {
            "bfb": bfb,
            "blueFieldSoftware": blue_field_software,
            "flavor": FLAVOR,
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

    DPUDeployment {
        metadata: ObjectMeta {
            name: Some(DEPLOYMENT.to_string()),
            namespace: Some(TEST_NS.to_string()),
            generation: Some(1),
            ..Default::default()
        },
        spec: serde_json::from_value(spec).expect("valid DpuDeploymentSpec"),
        status: Some(serde_json::from_value(status).expect("valid DpuDeploymentStatus")),
    }
}

async fn is_outdated(mock: OutdatedDpuMock) -> Result<bool, DpfError> {
    DpfSdkBuilder::new(mock, TEST_NS, String::new())
        .build_without_resources()
        .await
        .expect("sdk")
        .is_dpu_outdated(DPU_NAME)
        .await
}

/// Both provisioning sources, matching and drifted. A DPUDeployment declares
/// either a BFB or a BlueFieldSoftware CR, and the two are compared differently:
/// a BFB against the image actually installed, BlueFieldSoftware against the CR
/// name the DPU was created with.
#[tokio::test]
async fn a_dpu_is_current_only_while_it_matches_its_declared_provisioning_source() {
    let cases: [(&str, DPU, DPUDeployment, bool); 4] = [
        (
            "BFB matches the installed image",
            dpu(
                Some("bf-bundle-abc"),
                None,
                Some("/bfb/test-namespace-bf-bundle-abc.bfb"),
                FLAVOR,
            ),
            deployment(Some("bf-bundle-abc"), None, true),
            false,
        ),
        (
            "BFB moved on from the installed image",
            dpu(
                Some("bf-bundle-old"),
                None,
                Some("/bfb/test-namespace-bf-bundle-old.bfb"),
                FLAVOR,
            ),
            deployment(Some("bf-bundle-new"), None, true),
            true,
        ),
        (
            "BlueFieldSoftware matches the DPU's spec",
            dpu(None, Some("bf-software-abc"), None, FLAVOR),
            deployment(None, Some("bf-software-abc"), true),
            false,
        ),
        (
            "BlueFieldSoftware moved on from the DPU's spec",
            dpu(None, Some("bf-software-old"), None, FLAVOR),
            deployment(None, Some("bf-software-new"), true),
            true,
        ),
    ];

    for (name, dpu, deployment, expected_outdated) in cases {
        let outdated = is_outdated(OutdatedDpuMock::with(dpu, deployment))
            .await
            .unwrap_or_else(|error| panic!("{name}: evaluation failed: {error}"));
        assert_eq!(outdated, expected_outdated, "{name}");
    }
}

#[tokio::test]
async fn a_dpu_whose_flavor_drifted_is_outdated() {
    let mock = OutdatedDpuMock::with(
        dpu(
            Some("bf-bundle-abc"),
            None,
            Some("/bfb/test-namespace-bf-bundle-abc.bfb"),
            "some-other-flavor",
        ),
        deployment(Some("bf-bundle-abc"), None, true),
    );

    assert!(is_outdated(mock).await.expect("evaluated"));
}

#[tokio::test]
async fn an_unready_deployment_leaves_the_dpu_outdated() {
    // Matches on every field, so only the deployment's readiness decides. An
    // unready deployment is still settling and its declared state is not yet
    // authoritative.
    let mock = OutdatedDpuMock::with(
        dpu(
            Some("bf-bundle-abc"),
            None,
            Some("/bfb/test-namespace-bf-bundle-abc.bfb"),
            FLAVOR,
        ),
        deployment(Some("bf-bundle-abc"), None, false),
    );

    assert!(is_outdated(mock).await.expect("evaluated"));
}

#[tokio::test]
async fn a_deployment_declaring_no_provisioning_source_leaves_the_dpu_outdated() {
    // Neither bfb nor blueFieldSoftware violates the DPU CRD's
    // `has(self.bfb) != has(self.blueFieldSoftware)` rule, so the comparison is
    // inconclusive. `find_outdated_dpus_dpf` skips this case; here it must not
    // read as "up to date".
    let mock = OutdatedDpuMock::with(
        dpu(Some("bf-bundle-abc"), None, None, FLAVOR),
        deployment(None, None, true),
    );

    assert!(is_outdated(mock).await.expect("evaluated"));
}

#[tokio::test]
async fn a_deployment_declaring_both_provisioning_sources_leaves_the_dpu_outdated() {
    let mock = OutdatedDpuMock::with(
        dpu(Some("bf-bundle-abc"), None, None, FLAVOR),
        deployment(Some("bf-bundle-abc"), Some("bf-software-abc"), true),
    );

    assert!(is_outdated(mock).await.expect("evaluated"));
}

#[tokio::test]
async fn a_missing_dpu_is_an_error_rather_than_a_verdict() {
    // Nothing seeded. Reporting `false` here would release a hold for a DPU
    // that cannot be inspected; reporting `true` would silently stall. The
    // caller needs to tell this apart from a real answer.
    let mock = OutdatedDpuMock::default();

    assert!(is_outdated(mock).await.is_err());
}

#[tokio::test]
async fn a_dpu_without_an_owner_label_is_an_error() {
    let mut orphan = dpu(
        Some("bf-bundle-abc"),
        None,
        Some("/bfb/test-namespace-bf-bundle-abc.bfb"),
        FLAVOR,
    );
    orphan.metadata.labels = None;
    let mock = OutdatedDpuMock::with(orphan, deployment(Some("bf-bundle-abc"), None, true));

    assert!(is_outdated(mock).await.is_err());
}
