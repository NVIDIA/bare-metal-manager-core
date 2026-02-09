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

use std::collections::HashMap;
use std::sync::{Arc, LazyLock};

use carbide_dpf::KubeImpl;
use http::{Request, Response};
use kube::Client;
use kube::client::Body;
use model::machine::{DpfState, MachineState, ManagedHostState, ReprovisionState};
use rustls::crypto::{CryptoProvider, aws_lc_rs};
use serde_json::json;
use tokio::sync::Mutex;
use tower_test::mock::Handle;

use crate::tests::common::api_fixtures::{
    TestEnvOverrides, create_managed_host_with_dpf, create_test_env_with_overrides, get_config,
};

/********************************************************************************
 * Tower Server for DPF
 *********************************************************************************/

pub struct TestDpfTowerServer {
    client: LazyLock<Mutex<Option<Client>>>,
}

impl std::fmt::Debug for TestDpfTowerServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TestDpfTowerServer")
    }
}

#[async_trait::async_trait]
impl KubeImpl for TestDpfTowerServer {
    async fn get_kube_client(&self) -> Result<kube::Client, carbide_dpf::DpfError> {
        Ok(self.client.lock().await.clone().unwrap())
    }
}

fn dpu_device(path: &str) -> serde_json::Value {
    let name = path.split("/").last().unwrap();
    json!(
        {
            "apiVersion": "provisioning.dpu.nvidia.com/v1alpha1",
            "kind": "DPUDevice",
            "metadata": {
                "annotations": {
                    "kubectl.kubernetes.io/last-applied-configuration": "{\"apiVersion\":\"provisioning.dpu.nvidia.com/v1alpha1\",\"kind\":\"DPUDevice\",\"metadata\":{\"annotations\":{},\"labels\":{\"carbide.controlled.device\":\"true\"},\"name\":\"fm100dse6beua0hn56ujusoo1jbggg0rclfomaesdfadduu4i0mj5kg2g20\",\"namespace\":\"dpf-operator-system\"},\"spec\":{\"bmcIp\":\"10.217.170.50\",\"serialNumber\":\"MT2425601XKZ\"}}\n"
                },
                "creationTimestamp": "2026-01-20T09:32:27Z",
                "finalizers": [
                    "provisioning.dpu.nvidia.com/dpudevice-protection"
                ],
                "generation": 1,
                "labels": {
                    "carbide.controlled.device": "true",
                    "provisioning.dpu.nvidia.com/dpudevice-bmc-ip": "10.217.170.50",
                    "provisioning.dpu.nvidia.com/dpudevice-opn": "900-9D3B6-00CV-AA0",
                    "provisioning.dpu.nvidia.com/dpudevice-psid": "MT2425601XKZ",
                    "provisioning.dpu.nvidia.com/dpunode-name": "10.217.168.190-m1"
                },
                "name": name,
                "namespace": "dpf-operator-system",
                "resourceVersion": "763249",
                "uid": "b42c4c64-f169-4f15-8bee-6e0369d6903f"
            },
            "spec": {
                "bmcIp": "10.217.170.50",
                "bmcPort": 443,
                "numberOfPFs": 1,
                "serialNumber": "MT2425601XKZ"
            },
            "status": {
                "bmcIp": "10.217.170.50",
                "bmcPort": 443,
                "conditions": [
                    {
                        "lastTransitionTime": "2026-01-20T09:32:49Z",
                        "message": "",
                        "observedGeneration": 1,
                        "reason": "Success",
                        "status": "True",
                        "type": "Ready"
                    },
                    {
                        "lastTransitionTime": "2026-01-20T18:04:58Z",
                        "message": "",
                        "observedGeneration": 1,
                        "reason": "Success",
                        "status": "True",
                        "type": "Discovered"
                    },
                    {
                        "lastTransitionTime": "2026-01-20T09:32:49Z",
                        "message": "",
                        "observedGeneration": 1,
                        "reason": "Success",
                        "status": "True",
                        "type": "Initialized"
                    },
                    {
                        "lastTransitionTime": "2026-01-20T09:32:42Z",
                        "message": "",
                        "observedGeneration": 1,
                        "reason": "Success",
                        "status": "True",
                        "type": "NodeAttached"
                    }
                ],
                "dpuMode": "dpu",
                "opn": "900-9D3B6-00CV-AA0",
                "pf0Mac": "5c:25:73:6e:08:0c",
                "psid": "MT2425601XKZ",
                "serialNumber": "MT2425601XKZ"
            }
        }
    )
}

fn dpu_node(name: &str, annotations: bool) -> serde_json::Value {
    let annotations = if annotations {
        json!(
            {
                "provisioning.dpu.nvidia.com/dpunode-external-reboot-required": "true"
            }
        )
    } else {
        json!({})
    };

    json!(
        {
            "apiVersion": "provisioning.dpu.nvidia.com/v1alpha1",
            "kind": "DPUNode",
            "metadata": {
                "annotations": annotations,
                "creationTimestamp": "2026-01-20T09:32:40Z",
                "finalizers": [
                    "provisioning.dpu.nvidia.com/dpunode-protection"
                ],
                "generation": 1,
                "labels": {
                    "carbide.controlled.node": "true",
                    "feature.node.kubernetes.io/dpu-enabled": "true"
                },
                "name": name,
                "namespace": "dpf-operator-system",
                "resourceVersion": "763446",
                "uid": "853b511c-9aa1-4f24-bc05-ad29e69ea98d"
            },
            "spec": {
                "dpus": [
                    {
                        "name": "fm100dse6beua0hn56ujusoo1jbggg0rclfomaesdfadduu4i0mj5kg2g20"
                    },
                ],
                "nodeRebootMethod": {
                    "external": {}
                }
            },
            "status": {
                "conditions": [
                    {
                        "lastTransitionTime": "2026-01-21T15:21:37Z",
                        "message": "node effect is in progress",
                        "observedGeneration": 1,
                        "reason": "Ready",
                        "status": "False",
                        "type": "Ready"
                    },
                    {
                        "lastTransitionTime": "2026-01-21T15:20:14Z",
                        "message": "",
                        "observedGeneration": 1,
                        "reason": "DPUNodeRebootInProgress",
                        "status": "False",
                        "type": "DPUNodeRebootInProgress"
                    },
                    {
                        "lastTransitionTime": "2026-01-21T15:21:37Z",
                        "message": "",
                        "reason": "NodeEffectInProgress",
                        "status": "True",
                        "type": "DPUNodeNodeEffectInProgress"
                    }
                ],
                "dpuInstallInterface": "redfish"
            }
        }
    )
}

fn dpu_node_maintenance(path: &str, nodeeffect: &str) -> serde_json::Value {
    let name = path.split("/").last().unwrap();
    json!(
        {
            "apiVersion": "provisioning.dpu.nvidia.com/v1alpha1",
            "kind": "DPUNodeMaintenance",
            "metadata": {
                "annotations": {
                    "provisioning.dpu.nvidia.com/last-applied-additional-requestors-on-3e6b6ab444a068b2": "null",
                    "provisioning.dpu.nvidia.com/last-applied-additional-requestors-on-7fcf1787b2ced308": "[]",
                    "provisioning.dpu.nvidia.com/wait-for-external-nodeeffect": nodeeffect
                },
                "creationTimestamp": "2026-01-21T15:21:06Z",
                "finalizers": [
                    "provisioning.dpu.nvidia.com/dpunodemaintenance-protection"
                ],
                "generation": 2,
                "labels": {
                    "provisioning.dpu.nvidia.com/dpunode-name": "10.217.168.190-m1"
                },
                "name": name,
                "namespace": "dpf-operator-system",
                "resourceVersion": "763448",
                "uid": "4ff356d5-41e9-43d5-8539-d28b5154ffd8"
            },
            "spec": {
                "dpuNodeName": "10.217.168.190-m1",
                "nodeEffect": {
                    "applyOnLabelChange": false,
                    "force": false,
                    "hold": true
                },
                "requestor": [
                    "10.217.168.190-m1-fm100dse6beua0hn56ujusoo1jbggg0rclfomaesdfadduu4i0mj5kg2g20",
                ]
            },
            "status": {
                "conditions": [
                    {
                        "lastTransitionTime": "2026-01-21T15:21:37Z",
                        "message": "Node effect is being applied: DPUNodeMaintenance is in waiting for external node effect",
                        "observedGeneration": 2,
                        "reason": "NodeEffectIsProcessing",
                        "status": "False",
                        "type": "NodeEffectApplied"
                    }
                ],
                "maxUnavailableDPUNodes": 50,
                "multiDPUOperationsSyncWaitTime": "30s",
                "nodeEffectSyncStartTime": "2026-01-21T15:21:07Z"
            }
        }
    )
}

fn dpu_cr(dpu_name: &str, phase: &str) -> serde_json::Value {
    let toks = dpu_name.split("-").collect::<Vec<&str>>();
    let node = toks[0];
    let dpu_id = toks[2];
    let node_name = format!("{node}-node");

    json!(
        {
            "apiVersion": "provisioning.dpu.nvidia.com/v1alpha1",
            "kind": "DPU",
            "metadata": {
                "creationTimestamp": "2026-01-21T15:21:06Z",
                "finalizers": [
                    "provisioning.dpu.nvidia.com/dpu-protection"
                ],
                "generation": 2,
                "labels": {
                    "carbide.controlled.device": "true",
                    "provisioning.dpu.nvidia.com/dpudevice-bmc-ip": node,
                    "provisioning.dpu.nvidia.com/dpudevice-name": dpu_id,
                    "provisioning.dpu.nvidia.com/dpudevice-opn": "900-9D3B6-00CV-AA0",
                    "provisioning.dpu.nvidia.com/dpudevice-psid": "MT2425601XKZ",
                    "provisioning.dpu.nvidia.com/dpunode-name": node_name,
                    "provisioning.dpu.nvidia.com/dpuset-dpu-template-spec-hash": "c3b3a5edda",
                    "provisioning.dpu.nvidia.com/dpuset-name": "carbide-dpu-set",
                    "provisioning.dpu.nvidia.com/dpuset-namespace": "dpf-operator-system"
                },
                "name": dpu_name,
                "namespace": "dpf-operator-system",
                "ownerReferences": [
                    {
                        "apiVersion": "provisioning.dpu.nvidia.com/v1alpha1",
                        "blockOwnerDeletion": true,
                        "controller": true,
                        "kind": "DPUSet",
                        "name": "carbide-dpu-set",
                        "uid": "d0e5066f-9425-492c-8d05-cc669698eacb"
                    }
                ],
                "resourceVersion": "763278",
                "uid": "da5890a4-4547-401c-8b9d-932a0254db52"
            },
            "spec": {
                "bfb": "bf-bundle-1c4ec4d7-ee9f-4b57-9d66-efe428a44ca8",
                "cluster": {
                    "name": "carbide-dpf-cluster",
                    "namespace": "dpf-operator-system",
                    "nodeLabels": {
                        "operator.dpu.nvidia.com/dpf-version": "v25.10.1",
                        "provisioning.dpu.nvidia.com/host": node_name
                    }
                },
                "dpuDeviceName": dpu_id,
                "dpuFlavor": "carbide-dpu-flavor",
                "dpuNodeName": node_name,
                "nodeEffect": {
                    "applyOnLabelChange": false,
                    "force": false,
                    "hold": true
                },
                "serialNumber": "MT2425601XKZ"
            },
            "status": {
                "bfbFile": "/bfb/dpf-operator-system-bf-bundle-1c4ec4d7-ee9f-4b57-9d66-efe428a44ca8.bfb",
                "conditions": [
                    {
                        "lastTransitionTime": "2026-01-21T15:21:06Z",
                        "message": "",
                        "observedGeneration": 2,
                        "reason": "BFBReady",
                        "status": "True",
                        "type": "BFBReady"
                    },
                    {
                        "lastTransitionTime": "2026-01-21T15:21:06Z",
                        "message": "",
                        "observedGeneration": 2,
                        "reason": "Initialized",
                        "status": "True",
                        "type": "Initialized"
                    },
                    {
                        "lastTransitionTime": "2026-01-21T15:21:06Z",
                        "message": "node effect is in progress",
                        "observedGeneration": 2,
                        "reason": "NodeEffectInProgress",
                        "status": "False",
                        "type": "NodeEffectReady"
                    }
                ],
                "dpfVersion": "v25.10.1",
                "dpuInstallInterface": "redfish",
                "dpuMode": "dpu",
                "observedGeneration": 2,
                "phase": phase
            }
        }
    )
}

impl TestDpfTowerServer {
    pub fn new() -> Self {
        Self {
            client: LazyLock::new(|| Mutex::new(None)),
        }
    }

    pub async fn init(&mut self) -> Handle<Request<Body>, Response<Body>> {
        if CryptoProvider::get_default().is_none() {
            CryptoProvider::install_default(aws_lc_rs::default_provider()).unwrap();
        }
        let (service, handle) = tower_test::mock::pair::<Request<Body>, Response<Body>>();
        let client = Client::new(service, "default");
        *self.client.lock().await = Some(client);
        handle
    }

    pub fn start_server_mh_ready(
        &self,
        mut handle: Handle<Request<Body>, Response<Body>>,
    ) -> tokio::task::JoinHandle<()> {
        let server = tokio::spawn(async move {
            let (req, send) = handle.next_request().await.unwrap();
            let dpu_id = req.uri().path().split("/").last().unwrap();
            assert_eq!(
                req.uri().path(),
                format!(
                    "/apis/provisioning.dpu.nvidia.com/v1alpha1/namespaces/dpf-operator-system/dpudevices/{dpu_id}"
                )
            );
            send.send_response(Self::not_found_json());

            let (req, send) = handle.next_request().await.unwrap();
            assert_eq!(
                req.uri(),
                "/apis/provisioning.dpu.nvidia.com/v1alpha1/namespaces/dpf-operator-system/dpudevices?"
            );
            let bytes = req.into_body().collect_bytes().await.unwrap();
            let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            // TODO: Validate body
            send.send_response(Self::ok_json(body));
            let (req, send) = handle.next_request().await.unwrap();
            let node_name = req.uri().path().split("/").last().unwrap();
            assert_eq!(
                req.uri().path(),
                format!(
                    "/apis/provisioning.dpu.nvidia.com/v1alpha1/namespaces/dpf-operator-system/dpunodes/{node_name}"
                )
            );
            send.send_response(Self::not_found_json());
            let (req, send) = handle.next_request().await.unwrap();
            assert_eq!(
                req.uri(),
                "/apis/provisioning.dpu.nvidia.com/v1alpha1/namespaces/dpf-operator-system/dpunodes?"
            );
            let bytes = req.into_body().collect_bytes().await.unwrap();
            let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            let body_clone = body.clone();
            let node_name = body_clone
                .get("metadata")
                .unwrap()
                .get("name")
                .unwrap()
                .as_str()
                .unwrap();

            // TODO: Validate body
            send.send_response(Self::ok_json(body));

            let (req, send) = handle.next_request().await.unwrap();
            assert_eq!(
                req.uri().path(),
                format!(
                    "/apis/provisioning.dpu.nvidia.com/v1alpha1/namespaces/dpf-operator-system/dpudevices/{dpu_id}"
                )
            );
            send.send_response(Self::ok_json(dpu_device(req.uri().path())));

            let (req, send) = handle.next_request().await.unwrap();
            assert_eq!(
                req.uri().path(),
                format!(
                    "/apis/provisioning.dpu.nvidia.com/v1alpha1/namespaces/dpf-operator-system/dpunodemaintenances/{node_name}-hold"
                )
            );
            send.send_response(Self::ok_json(dpu_node_maintenance(
                req.uri().path(),
                "true",
            )));
            let (req, send) = handle.next_request().await.unwrap();
            assert_eq!(
                req.uri().path(),
                format!(
                    "/apis/provisioning.dpu.nvidia.com/v1alpha1/namespaces/dpf-operator-system/dpunodemaintenances/{node_name}-hold"
                )
            );
            assert_eq!(req.method(), http::Method::PATCH);
            send.send_response(Self::ok_json(dpu_node_maintenance(
                req.uri().path(),
                "false",
            )));

            // Exter-reboot annotation handling.
            let (req, send) = handle.next_request().await.unwrap();
            assert_eq!(
                req.uri().path(),
                format!(
                    "/apis/provisioning.dpu.nvidia.com/v1alpha1/namespaces/dpf-operator-system/dpunodes/{node_name}"
                )
            );
            send.send_response(Self::ok_json(dpu_node(node_name, true)));

            let (req, send) = handle.next_request().await.unwrap();
            assert_eq!(
                req.uri().path(),
                format!(
                    "/apis/provisioning.dpu.nvidia.com/v1alpha1/namespaces/dpf-operator-system/dpunodes/{node_name}"
                )
            );
            assert_eq!(req.method(), http::Method::PATCH);
            send.send_response(Self::ok_json(dpu_node(node_name, false)));
        });
        tracing::info!("Server started");
        server
    }

    pub fn start_server_mh_reprovisioning(
        &self,
        mut handle: Handle<Request<Body>, Response<Body>>,
    ) -> tokio::task::JoinHandle<()> {
        let server = tokio::spawn(async move {
            let (req, send) = handle.next_request().await.unwrap();
            let dpu_name = req.uri().path().split("/").last().unwrap();
            assert_eq!(
                req.uri().path(),
                format!(
                    "/apis/provisioning.dpu.nvidia.com/v1alpha1/namespaces/dpf-operator-system/dpus/{dpu_name}"
                )
            );
            send.send_response(Self::ok_json(dpu_cr(dpu_name, "OS Installing")));

            let (req, send) = handle.next_request().await.unwrap();
            assert_eq!(
                req.uri().path(),
                format!(
                    "/apis/provisioning.dpu.nvidia.com/v1alpha1/namespaces/dpf-operator-system/dpus/{dpu_name}/status"
                )
            );
            assert_eq!(req.method(), http::Method::PATCH);
            send.send_response(Self::ok_json(dpu_cr(dpu_name, "Error")));

            let (req, send) = handle.next_request().await.unwrap();
            assert_eq!(
                req.uri().path(),
                format!(
                    "/apis/provisioning.dpu.nvidia.com/v1alpha1/namespaces/dpf-operator-system/dpus/{dpu_name}"
                )
            );
            assert_eq!(req.method(), http::Method::DELETE);
            send.send_response(Self::deleted_json());

            // Fetch and update node effect annotation.
            let (req, send) = handle.next_request().await.unwrap();
            let maintenancenode_name = req.uri().path().split("/").last().unwrap();
            assert_eq!(
                req.uri().path(),
                format!(
                    "/apis/provisioning.dpu.nvidia.com/v1alpha1/namespaces/dpf-operator-system/dpunodemaintenances/{maintenancenode_name}"
                )
            );
            send.send_response(Self::ok_json(dpu_node_maintenance(
                req.uri().path(),
                "true",
            )));
            let (req, send) = handle.next_request().await.unwrap();
            assert_eq!(
                req.uri().path(),
                format!(
                    "/apis/provisioning.dpu.nvidia.com/v1alpha1/namespaces/dpf-operator-system/dpunodemaintenances/{maintenancenode_name}"
                )
            );
            assert_eq!(req.method(), http::Method::PATCH);
            send.send_response(Self::ok_json(dpu_node_maintenance(
                req.uri().path(),
                "false",
            )));

            // Exter-reboot annotation handling.
            let (req, send) = handle.next_request().await.unwrap();
            let node_name = req.uri().path().split("/").last().unwrap();
            assert_eq!(
                req.uri().path(),
                format!(
                    "/apis/provisioning.dpu.nvidia.com/v1alpha1/namespaces/dpf-operator-system/dpunodes/{node_name}"
                )
            );
            send.send_response(Self::ok_json(dpu_node(node_name, true)));

            let (req, send) = handle.next_request().await.unwrap();
            assert_eq!(
                req.uri().path(),
                format!(
                    "/apis/provisioning.dpu.nvidia.com/v1alpha1/namespaces/dpf-operator-system/dpunodes/{node_name}"
                )
            );
            assert_eq!(req.method(), http::Method::PATCH);
            send.send_response(Self::ok_json(dpu_node(node_name, false)));
        });
        tracing::info!("Server started");
        server
    }

    pub fn start_server_mh_force_delete(
        &self,
        mut handle: Handle<Request<Body>, Response<Body>>,
    ) -> tokio::task::JoinHandle<()> {
        let server = tokio::spawn(async move {
            let (req, send) = handle.next_request().await.unwrap();
            let node_name = req.uri().path().split("/").last().unwrap();
            assert_eq!(
                req.uri().path(),
                format!(
                    "/apis/provisioning.dpu.nvidia.com/v1alpha1/namespaces/dpf-operator-system/dpunodes/{node_name}"
                )
            );
            send.send_response(Self::ok_json(dpu_node(node_name, false)));

            let (req, send) = handle.next_request().await.unwrap();
            let dpu_name = req.uri().path().split("/").last().unwrap();
            assert_eq!(
                req.uri().path(),
                format!(
                    "/apis/provisioning.dpu.nvidia.com/v1alpha1/namespaces/dpf-operator-system/dpus/{dpu_name}"
                )
            );
            assert_eq!(req.method(), http::Method::GET);
            send.send_response(Self::ok_json(dpu_cr(dpu_name, "OS Installing")));

            let (req, send) = handle.next_request().await.unwrap();
            println!("path: {:?}", req.uri().path());
            println!("method: {:?}", req.method());
            assert_eq!(
                req.uri().path(),
                format!(
                    "/apis/provisioning.dpu.nvidia.com/v1alpha1/namespaces/dpf-operator-system/dpus/{dpu_name}/status"
                )
            );
            assert_eq!(req.method(), http::Method::PATCH);
            send.send_response(Self::ok_json(dpu_cr(dpu_name, "Error")));

            let (req, send) = handle.next_request().await.unwrap();
            let dpu_node_name = req.uri().path().split("/").last().unwrap();
            assert_eq!(
                req.uri().path(),
                format!(
                    "/apis/provisioning.dpu.nvidia.com/v1alpha1/namespaces/dpf-operator-system/dpunodes/{dpu_node_name}"
                )
            );
            send.send_response(Self::ok_json(dpu_node(dpu_node_name, false)));

            let (req, send) = handle.next_request().await.unwrap();
            assert_eq!(
                req.uri().path(),
                format!(
                    "/apis/provisioning.dpu.nvidia.com/v1alpha1/namespaces/dpf-operator-system/dpunodes/{dpu_node_name}"
                )
            );
            assert_eq!(req.method(), http::Method::DELETE);
            send.send_response(Self::deleted_json());

            let (req, send) = handle.next_request().await.unwrap();
            let dpu_device_name = req.uri().path().split("/").last().unwrap();
            assert_eq!(
                req.uri().path(),
                format!(
                    "/apis/provisioning.dpu.nvidia.com/v1alpha1/namespaces/dpf-operator-system/dpudevices/{dpu_device_name}"
                )
            );
            assert_eq!(req.method(), http::Method::GET);
            send.send_response(Self::ok_json(dpu_device(dpu_device_name)));

            let (req, send) = handle.next_request().await.unwrap();
            let dpu_device_name = req.uri().path().split("/").last().unwrap();
            assert_eq!(
                req.uri().path(),
                format!(
                    "/apis/provisioning.dpu.nvidia.com/v1alpha1/namespaces/dpf-operator-system/dpudevices/{dpu_device_name}"
                )
            );
            assert_eq!(req.method(), http::Method::DELETE);
            send.send_response(Self::deleted_json());

            let (req, send) = handle.next_request().await.unwrap();
            let dpu_device_name = req.uri().path().split("/").last().unwrap();
            assert_eq!(
                req.uri().path(),
                format!(
                    "/apis/provisioning.dpu.nvidia.com/v1alpha1/namespaces/dpf-operator-system/dpudevices/{dpu_device_name}"
                )
            );
            assert_eq!(req.method(), http::Method::GET);
            send.send_response(Self::ok_json(dpu_device(dpu_device_name)));

            let (req, send) = handle.next_request().await.unwrap();
            let dpu_device_name = req.uri().path().split("/").last().unwrap();
            assert_eq!(
                req.uri().path(),
                format!(
                    "/apis/provisioning.dpu.nvidia.com/v1alpha1/namespaces/dpf-operator-system/dpudevices/{dpu_device_name}"
                )
            );
            assert_eq!(req.method(), http::Method::DELETE);
            send.send_response(Self::deleted_json());
        });
        tracing::info!("Server started");
        server
    }

    /////////////////// Helper Functions ///////////////////
    fn ok_json(value: serde_json::Value) -> http::Response<Body> {
        Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .body(Body::from(value.to_string().into_bytes()))
            .unwrap()
    }

    fn deleted_json() -> http::Response<Body> {
        let value = serde_json::json!({
          "kind": "Status",
        "apiVersion": "v1",
        "status": "Success",
        "code": 200
        });

        Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .body(Body::from(value.to_string().into_bytes()))
            .unwrap()
    }

    fn not_found_json() -> http::Response<Body> {
        let value = serde_json::json!({
          "kind": "Status",
          "apiVersion": "v1",
          "metadata": {},
          "status": "Failure",
          "message": "mycrds.example.com \"example\" not found",
          "reason": "NotFound",
          "details": {
            "name": "example",
            "group": "example.com",
            "kind": "mycrds"
          },
          "code": 404
        });

        Response::builder()
            .status(404)
            .header("content-type", "application/json")
            .body(Body::from(value.to_string().into_bytes()))
            .unwrap()
    }
}

/********************************************************************************/
#[crate::sqlx_test]
async fn test_dpu_and_host_till_ready(pool: sqlx::PgPool) {
    let mut kube_impl = TestDpfTowerServer::new();
    let handle = kube_impl.init().await;
    let server = kube_impl.start_server_mh_ready(handle);

    let mut config = get_config();
    config.dpf = crate::cfg::file::DpfConfig { enabled: true };
    let dpf_config = crate::state_controller::machine::handler::DpfConfig::from(
        config.dpf.clone(),
        Arc::new(kube_impl),
    );
    let env = create_test_env_with_overrides(
        pool,
        TestEnvOverrides::with_config(config).with_dpf_config(dpf_config),
    )
    .await;
    let mh = create_managed_host_with_dpf(&env).await;

    // Server has done handling.
    if !server.is_finished() {
        server.abort();
    }

    let mut txn = env.db_txn().await;

    assert!(mh.host().db_machine(&mut txn).await.dpf.used_for_ingestion);
    for i in 0..mh.dpu_ids.len() {
        let dpu = mh.dpu_n(i).db_machine(&mut txn).await;
        assert!(dpu.dpf.used_for_ingestion);
        assert!(matches!(dpu.current_state(), ManagedHostState::Ready));
    }

    let carbide_machines_per_state = env.test_meter.parsed_metrics("carbide_machines_per_state");

    assert!(carbide_machines_per_state.contains(&(
        "{fresh=\"true\",state=\"ready\",substate=\"\"}".to_string(),
        "2".to_string()
    )));

    let expected_states_entered = &[
        (
            r#"{state="dpunotready",substate="waitingfornetworkconfig"}"#,
            1,
        ),
        (
            r#"{state="dpunotready",substate="waitingforplatformconfiguration"}"#,
            1,
        ),
        (r#"{state="hostnotready",substate="discovered"}"#, 1),
        (
            r#"{state="hostnotready",substate="waitingfordiscovery"}"#,
            1,
        ),
        (r#"{state="hostnotready",substate="pollingbiossetup"}"#, 1),
        (
            r#"{state="hostnotready",substate="waitingforplatformconfiguration"}"#,
            1,
        ),
        (r#"{state="hostnotready",substate="waitingforlockdown"}"#, 4),
        (r#"{state="ready",substate=""}"#, 3),
    ];

    let states_entered = env
        .test_meter
        .parsed_metrics("carbide_machines_state_entered_total");

    for expected in expected_states_entered.iter() {
        let actual = states_entered
            .iter()
            .find(|s| s.0 == expected.0)
            .unwrap_or_else(|| panic!("Did not enter state {}", expected.0));
        assert_eq!(
            actual.1.parse::<i64>().unwrap(),
            expected.1,
            "Did not enter state {} {} times",
            expected.0,
            expected.1
        );
    }

    let expected_states_exited = &[
        ("{state=\"dpunotready\",substate=\"dpfstates\"}", 8),
        (
            "{state=\"dpunotready\",substate=\"waitingfornetworkconfig\"}",
            1,
        ),
        (
            "{state=\"dpunotready\",substate=\"waitingforplatformconfiguration\"}",
            1,
        ),
        ("{state=\"hostnotready\",substate=\"discovered\"}", 1),
        (
            "{state=\"hostnotready\",substate=\"waitingfordiscovery\"}",
            1,
        ),
        ("{state=\"hostnotready\",substate=\"pollingbiossetup\"}", 1),
        (
            "{state=\"hostnotready\",substate=\"waitingforplatformconfiguration\"}",
            1,
        ),
        (
            "{state=\"hostnotready\",substate=\"waitingforlockdown\"}",
            4,
        ),
    ];

    let states_exited = env
        .test_meter
        .parsed_metrics("carbide_machines_state_exited_total");

    for expected in expected_states_exited.iter() {
        let actual = states_exited
            .iter()
            .find(|s| s.0 == expected.0)
            .unwrap_or_else(|| panic!("Did not exit state {}", expected.0));
        assert_eq!(
            actual.1.parse::<i64>().unwrap(),
            expected.1,
            "Did not exit state {} {} times",
            expected.0,
            expected.1
        );
    }
}

#[crate::sqlx_test]
async fn test_dpu_and_host_till_ready_with_reprovisioning(pool: sqlx::PgPool) {
    let mut kube_impl = TestDpfTowerServer::new();
    let handle = kube_impl.init().await;
    let server = kube_impl.start_server_mh_ready(handle);

    let mut config = get_config();
    config.dpf = crate::cfg::file::DpfConfig { enabled: true };
    let dpf_config = crate::state_controller::machine::handler::DpfConfig::from(
        config.dpf.clone(),
        Arc::new(kube_impl),
    );
    let env = create_test_env_with_overrides(
        pool,
        TestEnvOverrides::with_config(config).with_dpf_config(dpf_config),
    )
    .await;
    let mh = create_managed_host_with_dpf(&env).await;

    // Server has done handling.
    if !server.is_finished() {
        server.abort();
    }

    let mut reprovisioning_api = TestDpfTowerServer::new();
    let reprovisioning_handle = reprovisioning_api.init().await;
    let reprovisioning_server =
        reprovisioning_api.start_server_mh_reprovisioning(reprovisioning_handle);

    env.machine_state_handler
        .inner
        .lock()
        .await
        .dpu_handler
        .dpf_config
        .kube_client_provider = Arc::new(reprovisioning_api);

    mh.mark_machine_for_updates().await;
    mh.host()
        .trigger_dpu_reprovisioning(rpc::forge::dpu_reprovisioning_request::Mode::Set, true)
        .await;

    env.run_machine_state_controller_iteration_until_state_matches(
        &mh.id,
        9,
        ManagedHostState::DPUReprovision {
            dpu_states: model::machine::DpuReprovisionStates {
                states: HashMap::from([(
                    mh.dpu().id,
                    ReprovisionState::DpfStates {
                        substate: DpfState::WaitingForOsInstallToComplete,
                    },
                )]),
            },
        },
    )
    .await;
    mh.dpu().discovery_completed().await;
    env.run_machine_state_controller_iteration_until_state_matches(
        &mh.id,
        9,
        ManagedHostState::DPUReprovision {
            dpu_states: model::machine::DpuReprovisionStates {
                states: HashMap::from([(
                    mh.dpu().id,
                    ReprovisionState::DpfStates {
                        substate: DpfState::WaitForNetworkConfigAndRemoveAnnotation,
                    },
                )]),
            },
        },
    )
    .await;
    mh.network_configured(&env).await;
    env.run_machine_state_controller_iteration_until_state_matches(
        &mh.id,
        4,
        ManagedHostState::DPUReprovision {
            dpu_states: model::machine::DpuReprovisionStates {
                states: HashMap::from([(mh.dpu().id, ReprovisionState::WaitingForNetworkConfig)]),
            },
        },
    )
    .await;
    mh.network_configured(&env).await;
    env.run_machine_state_controller_iteration_until_state_matches(
        &mh.id,
        4,
        ManagedHostState::HostInit {
            machine_state: MachineState::Discovered {
                skip_reboot_wait: false,
            },
        },
    )
    .await;
    let _response = mh.host().forge_agent_control().await;
    env.run_machine_state_controller_iteration().await;

    if !reprovisioning_server.is_finished() {
        reprovisioning_server.abort();
    }

    let mut txn = env.db_txn().await;
    let dpu = mh.dpu().db_machine(&mut txn).await;

    assert!(matches!(dpu.current_state(), ManagedHostState::Ready));
    txn.rollback().await.unwrap();
}

#[crate::sqlx_test]
async fn test_dpu_and_host_force_delete(pool: sqlx::PgPool) {
    let mut kube_impl = TestDpfTowerServer::new();
    let handle = kube_impl.init().await;
    let server = kube_impl.start_server_mh_ready(handle);

    let mut config = get_config();
    config.dpf = crate::cfg::file::DpfConfig { enabled: true };
    let dpf_config = crate::state_controller::machine::handler::DpfConfig::from(
        config.dpf.clone(),
        Arc::new(kube_impl),
    );
    let env = create_test_env_with_overrides(
        pool,
        TestEnvOverrides::with_config(config).with_dpf_config(dpf_config),
    )
    .await;
    let mh = create_managed_host_with_dpf(&env).await;

    // Server has done handling.
    if !server.is_finished() {
        server.abort();
    }

    let mut force_delete_api = TestDpfTowerServer::new();
    let force_delete_handle = force_delete_api.init().await;
    let force_delete_server = force_delete_api.start_server_mh_force_delete(force_delete_handle);

    let mut txn = env.db_txn().await;
    let bmc_ip = mh.host().bmc_ip(&mut txn).await;
    txn.rollback().await.unwrap();

    carbide_dpf::utils::force_delete_managed_host(
        &force_delete_api,
        &bmc_ip,
        &mh.dpu_ids
            .clone()
            .iter()
            .map(|id| id.to_string())
            .collect::<Vec<String>>(),
    )
    .await
    .unwrap();

    if !force_delete_server.is_finished() {
        force_delete_server.abort();
    }
}
