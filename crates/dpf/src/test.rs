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
#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::LazyLock;

    use http::{Request, Response};
    use kube::Client;
    use kube::client::Body;
    use tokio::sync::Mutex;
    use tower_test::mock::Handle;

    use crate::{DpfError, KubeImpl, create_crds_and_secret_with_client, get_fw_update_data};

    static CLIENT: LazyLock<Mutex<Option<Client>>> = LazyLock::new(|| Mutex::new(None));
    #[allow(clippy::type_complexity)]
    static HANDLE: LazyLock<Mutex<Option<Handle<Request<Body>, Response<Body>>>>> =
        LazyLock::new(|| Mutex::new(None));

    #[derive(Clone, Debug)]
    pub struct TestKubeImpl {}

    #[async_trait::async_trait]
    impl KubeImpl for TestKubeImpl {
        async fn get_kube_client(&self) -> Result<kube::Client, DpfError> {
            let client = CLIENT.lock().await;
            Ok(client.clone().unwrap())
        }
    }

    #[tokio::test]
    async fn test_create_crds_and_secret() {
        let kube_impl = TestKubeImpl {};

        let (service, handle) = tower_test::mock::pair::<Request<Body>, Response<Body>>();
        let client = Client::new(service, "default");
        *CLIENT.lock().await = Some(client);
        *HANDLE.lock().await = Some(handle);

        let kube_clone = kube_impl.clone();
        let fut = tokio::spawn(async move {
            let mut bfcfg_context = HashMap::new();
            bfcfg_context.insert("api_url".to_string(), "carbide-api.forge".to_string());
            bfcfg_context.insert("pxe_url".to_string(), "carbide-pxe.forge".to_string());
            bfcfg_context.insert("bmc_fw_update".to_string(), get_fw_update_data());
            bfcfg_context.insert(
                "seconds_since_epoch".to_string(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("Time went backwards")
                    .as_secs()
                    .to_string(),
            );
            let bmc_password = "password".to_string();
            let result =
                create_crds_and_secret_with_client(bfcfg_context, bmc_password, &kube_clone).await;
            assert!(result.is_ok());
        });

        let server = tokio::spawn(async move {
            let mut handle = HANDLE.lock().await;
            let mut handle = handle.take().unwrap();
            let (req, send) = handle.next_request().await.unwrap();
            assert_eq!(
                req.uri(),
                "/api/v1/namespaces/dpf-operator-system/secrets/bmc-shared-password"
            );
            send.send_response(ok_json(get_secret_response()));

            let (req, send) = handle.next_request().await.unwrap();
            assert_eq!(
                req.uri(),
                "/apis/provisioning.dpu.nvidia.com/v1alpha1/namespaces/dpf-operator-system/dpuflavors/carbide-dpu-flavor"
            );
            send.send_response(not_found_json());

            let (req, send) = handle.next_request().await.unwrap();
            assert_eq!(req.method(), http::Method::POST);
            assert_eq!(
                req.uri(),
                "/apis/provisioning.dpu.nvidia.com/v1alpha1/namespaces/dpf-operator-system/dpuflavors?"
            );
            let bytes = req.into_body().collect_bytes().await.unwrap();
            let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            // TODO: Validate body
            send.send_response(ok_json(body));

            let (req, send) = handle.next_request().await.unwrap();
            assert_eq!(
                req.uri().path(),
                "/api/v1/namespaces/forge-system/services/carbide-pxe-external"
            );
            send.send_response(ok_json(get_svc()));

            let (req, send) = handle.next_request().await.unwrap();
            assert_eq!(
                req.uri(),
                "/apis/provisioning.dpu.nvidia.com/v1alpha1/namespaces/dpf-operator-system/bfbs?"
            );
            let bytes = req.into_body().collect_bytes().await.unwrap();
            let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            // TODO: Validate body
            send.send_response(ok_json(body));

            let (req, send) = handle.next_request().await.unwrap();
            let uri = req.uri();
            let name = uri.path().split("/").last().unwrap();
            send.send_response(ok_json(get_bfb_response(name.to_string())));

            let (req, send) = handle.next_request().await.unwrap();
            assert_eq!(
                req.uri().path(),
                "/apis/provisioning.dpu.nvidia.com/v1alpha1/namespaces/dpf-operator-system/dpusets/carbide-dpu-set"
            );
            assert_eq!(req.method(), http::Method::PATCH);
            let bytes = req.into_body().collect_bytes().await.unwrap();
            let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            // TODO: Validate body
            send.send_response(created_json(body));

            let (req, send) = handle.next_request().await.unwrap();
            assert_eq!(
                req.uri().path(),
                "/apis/provisioning.dpu.nvidia.com/v1alpha1/namespaces/dpf-operator-system/bfbs"
            );
            assert_eq!(req.method(), http::Method::GET);
            send.send_response(ok_json(get_bfb_response_list(name.to_string())));

            let (req, send) = handle.next_request().await.unwrap();
            assert_eq!(
                req.uri().path(),
                "/apis/provisioning.dpu.nvidia.com/v1alpha1/namespaces/dpf-operator-system/bfbs/bf-bundle"
            );
            assert_eq!(req.method(), http::Method::DELETE);
            send.send_response(deleted_json());

            let (req, send) = handle.next_request().await.unwrap();
            assert_eq!(
                req.uri().path(),
                "/api/v1/namespaces/dpf-operator-system/configmaps/carbide-dpf-bf-cfg-template"
            );
            assert_eq!(req.method(), http::Method::PATCH);
            let bytes = req.into_body().collect_bytes().await.unwrap();
            let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            // TODO: Validate body
            send.send_response(created_json(body));
        });

        fut.await.unwrap();
        server.abort();
    }

    fn get_bfb_response_list(name: String) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "v1",
            "items": [
                {
                    "apiVersion": "provisioning.dpu.nvidia.com/v1alpha1",
                    "kind": "BFB",
                    "metadata": {
                        "annotations": {
                            "kubectl.kubernetes.io/last-applied-configuration": "{\"apiVersion\":\"provisioning.dpu.nvidia.com/v1alpha1\",\"kind\":\"BFB\",\"metadata\":{\"annotations\":{},\"name\":\"bf-bundle\",\"namespace\":\"dpf-operator-system\"},\"spec\":{\"url\":\"http://carbide-pxe.forge/public/blobs/internal/aarch64/forge.bfb\"}}\n"
                        },
                        "creationTimestamp": "2026-01-14T11:42:02Z",
                        "finalizers": [
                            "provisioning.dpu.nvidia.com/bfb-protection"
                        ],
                        "generation": 1,
                        "name": "bf-bundle",
                        "namespace": "dpf-operator-system",
                        "resourceVersion": "21519",
                        "uid": "d37ade08-d98e-45ed-81f2-de88f1938714"
                    },
                    "spec": {
                        "url": "http://carbide-pxe.forge/public/blobs/internal/aarch64/forge.bfb"
                    },
                    "status": {
                        "conditions": [
                            {
                                "lastTransitionTime": "2026-01-14T11:42:02Z",
                                "message": "",
                                "observedGeneration": 1,
                                "reason": "Success",
                                "status": "True",
                                "type": "Ready"
                            },
                            {
                                "lastTransitionTime": "2026-01-14T11:42:02Z",
                                "message": "",
                                "observedGeneration": 1,
                                "reason": "Success",
                                "status": "True",
                                "type": "Downloaded"
                            },
                            {
                                "lastTransitionTime": "2026-01-14T11:42:02Z",
                                "message": "",
                                "observedGeneration": 1,
                                "reason": "Success",
                                "status": "True",
                                "type": "Initialized"
                            }
                        ],
                        "fileName": "dpf-operator-system-bf-bundle.bfb",
                        "observedGeneration": 1,
                        "phase": "Ready",
                        "versions": {
                            "atf": "4.13.0-19-g5fcb148df",
                            "bsp": "4.13.0.13799",
                            "doca": "3.2.0",
                            "uefi": "4.13.0-26-g337fea6bfd"
                        }
                    }
                },
                {
                    "apiVersion": "provisioning.dpu.nvidia.com/v1alpha1",
                    "kind": "BFB",
                    "metadata": {
                        "annotations": {
                            "kubectl.kubernetes.io/last-applied-configuration": "{\"apiVersion\":\"provisioning.dpu.nvidia.com/v1alpha1\",\"kind\":\"BFB\",\"metadata\":{\"annotations\":{},\"name\":\"bf-bundle\",\"namespace\":\"dpf-operator-system\"},\"spec\":{\"url\":\"http://carbide-pxe.forge/public/blobs/internal/aarch64/forge.bfb\"}}\n"
                        },
                        "creationTimestamp": "2026-01-14T11:42:02Z",
                        "finalizers": [
                            "provisioning.dpu.nvidia.com/bfb-protection"
                        ],
                        "generation": 1,
                        "name": name,
                        "namespace": "dpf-operator-system",
                        "resourceVersion": "21519",
                        "uid": "d37ade08-d98e-45ed-81f2-de88f1938714"
                    },
                    "spec": {
                        "url": "http://carbide-pxe.forge/public/blobs/internal/aarch64/forge.bfb"
                    },
                    "status": {
                        "conditions": [
                            {
                                "lastTransitionTime": "2026-01-14T11:42:02Z",
                                "message": "",
                                "observedGeneration": 1,
                                "reason": "Success",
                                "status": "True",
                                "type": "Ready"
                            },
                            {
                                "lastTransitionTime": "2026-01-14T11:42:02Z",
                                "message": "",
                                "observedGeneration": 1,
                                "reason": "Success",
                                "status": "True",
                                "type": "Downloaded"
                            },
                            {
                                "lastTransitionTime": "2026-01-14T11:42:02Z",
                                "message": "",
                                "observedGeneration": 1,
                                "reason": "Success",
                                "status": "True",
                                "type": "Initialized"
                            }
                        ],
                        "fileName": "dpf-operator-system-bf-bundle.bfb",
                        "observedGeneration": 1,
                        "phase": "Ready",
                        "versions": {
                            "atf": "4.13.0-19-g5fcb148df",
                            "bsp": "4.13.0.13799",
                            "doca": "3.2.0",
                            "uefi": "4.13.0-26-g337fea6bfd"
                        }
                    }
                }

            ],
            "kind": "List",
            "metadata": {
                "resourceVersion": ""
            }
        }
        )
    }

    fn get_svc() -> serde_json::Value {
        serde_json::json!(
                    {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "annotations": {
                    "argocd.argoproj.io/tracking-id": "site-controller:/Service:forge-system/carbide-pxe-external",
                    "config.kubernetes.io/origin": "path: ../../../../overlays/forge-system/external-services.yaml\n",
                    "kubectl.kubernetes.io/last-applied-configuration": "{\"apiVersion\":\"v1\",\"kind\":\"Service\",\"metadata\":{\"annotations\":{\"argocd.argoproj.io/tracking-id\":\"site-controller:/Service:forge-system/carbide-pxe-external\",\"config.kubernetes.io/origin\":\"path: ../../../../overlays/forge-system/external-services.yaml\\n\",\"metallb.universe.tf/allow-shared-ip\":\"carbide-pxe\",\"metallb.universe.tf/loadBalancerIPs\":\"10.180.61.162\"},\"labels\":{\"app.kubernetes.io/part-of\":\"carbide-pxe\",\"argocd.argoproj.io/instance\":\"site-controller\"},\"name\":\"carbide-pxe-external\",\"namespace\":\"forge-system\"},\"spec\":{\"externalTrafficPolicy\":\"Local\",\"ports\":[{\"name\":\"http\",\"port\":8080,\"protocol\":\"TCP\",\"targetPort\":8080}],\"selector\":{\"app.kubernetes.io/name\":\"carbide-pxe\"},\"type\":\"LoadBalancer\"}}\n",
                    "metallb.universe.tf/allow-shared-ip": "carbide-pxe",
                    "metallb.universe.tf/ip-allocated-from-pool": "vip-pool-int-test",
                    "metallb.universe.tf/loadBalancerIPs": "10.180.61.162"
                },
                "creationTimestamp": "2026-01-27T14:57:56Z",
                "labels": {
                    "app.kubernetes.io/part-of": "carbide-pxe",
                    "argocd.argoproj.io/instance": "site-controller"
                },
                "name": "carbide-pxe-external",
                "namespace": "forge-system",
                "resourceVersion": "60182091",
                "uid": "86c3af56-6e98-4929-a66c-63066aac75d7"
            },
            "spec": {
                "allocateLoadBalancerNodePorts": true,
                "clusterIP": "10.233.55.156",
                "clusterIPs": [
                    "10.233.55.156"
                ],
                "externalTrafficPolicy": "Local",
                "healthCheckNodePort": 32538,
                "internalTrafficPolicy": "Cluster",
                "ipFamilies": [
                    "IPv4"
                ],
                "ipFamilyPolicy": "SingleStack",
                "ports": [
                    {
                        "name": "http",
                        "nodePort": 31312,
                        "port": 8080,
                        "protocol": "TCP",
                        "targetPort": 8080
                    }
                ],
                "selector": {
                    "app.kubernetes.io/name": "carbide-pxe"
                },
                "sessionAffinity": "None",
                "type": "LoadBalancer"
            },
            "status": {
                "loadBalancer": {
                    "ingress": [
                        {
                            "ip": "10.180.61.162",
                            "ipMode": "VIP"
                        }
                    ]
                }
            }
        }
                )
    }

    fn get_bfb_response(name: String) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "provisioning.dpu.nvidia.com/v1alpha1",
            "kind": "BFB",
            "metadata": {
                "annotations": {
                    "kubectl.kubernetes.io/last-applied-configuration": "{\"apiVersion\":\"provisioning.dpu.nvidia.com/v1alpha1\",\"kind\":\"BFB\",\"metadata\":{\"annotations\":{},\"name\":\"bf-bundle\",\"namespace\":\"dpf-operator-system\"},\"spec\":{\"url\":\"http://carbide-pxe.forge/public/blobs/internal/aarch64/forge.bfb\"}}\n"
                },
                "creationTimestamp": "2026-01-14T11:42:02Z",
                "finalizers": [
                    "provisioning.dpu.nvidia.com/bfb-protection"
                ],
                "generation": 1,
                "name": name,
                "namespace": "dpf-operator-system",
                "resourceVersion": "21519",
                "uid": "d37ade08-d98e-45ed-81f2-de88f1938714"
            },
            "spec": {
                "url": "http://carbide-pxe.forge/public/blobs/internal/aarch64/forge.bfb"
            },
            "status": {
                "conditions": [
                    {
                        "lastTransitionTime": "2026-01-14T11:42:02Z",
                        "message": "",
                        "observedGeneration": 1,
                        "reason": "Success",
                        "status": "True",
                        "type": "Ready"
                    },
                    {
                        "lastTransitionTime": "2026-01-14T11:42:02Z",
                        "message": "",
                        "observedGeneration": 1,
                        "reason": "Success",
                        "status": "True",
                        "type": "Downloaded"
                    },
                    {
                        "lastTransitionTime": "2026-01-14T11:42:02Z",
                        "message": "",
                        "observedGeneration": 1,
                        "reason": "Success",
                        "status": "True",
                        "type": "Initialized"
                    }
                ],
                "fileName": "dpf-operator-system-bf-bundle.bfb",
                "observedGeneration": 1,
                "phase": "Ready",
                "versions": {
                    "atf": "4.13.0-19-g5fcb148df",
                    "bsp": "4.13.0.13799",
                    "doca": "3.2.0",
                    "uefi": "4.13.0-26-g337fea6bfd"
                }
            }
        }
        )
    }

    fn get_secret_response() -> serde_json::Value {
        serde_json::json!({
                "apiVersion": "v1",
                "data": {
                    "password": "password"
                },
                "kind": "Secret",
                "metadata": {
                    "creationTimestamp": "2026-01-14T11:08:46Z",
                    "name": "bmc-shared-password",
                    "namespace": "dpf-operator-system",
                    "resourceVersion": "8703",
                    "uid": "aad44be3-af36-41a7-8cef-40818b991428"
                },
                "type": "Opaque"
        })
    }

    fn ok_json(value: serde_json::Value) -> http::Response<Body> {
        Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .body(Body::from(value.to_string().into_bytes()))
            .unwrap()
    }

    fn created_json(value: serde_json::Value) -> http::Response<Body> {
        Response::builder()
            .status(201)
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
}
