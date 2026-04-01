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

//! Carbide-specific DPU service definitions for DPUServiceTemplate / DPUServiceConfiguration.

use carbide_dpf::{
    ConfigPortsServiceType, ServiceChainSwitch, ServiceConfigPort, ServiceConfigPortProtocol,
    ServiceDefinition, ServiceInterface,
};

/// HBN network name used by service interfaces and service chains.
const HBN_NETWORK: &str = "mybrhbn";

/// HBN service name used in DPUServiceTemplate/DPUServiceConfiguration.
const HBN_SERVICE_NAME: &str = "doca-hbn";

/// Extended registry configuration for Carbide DPU services.
#[derive(Debug, Clone)]
pub struct CarbideServiceRegistryConfig {
    /// Helm chart repository URL for DOCA services (HBN, DTS).
    pub doca_helm_registry: String,
    /// Helm chart repository URL for Carbide services.
    pub carbide_helm_registry: String,
    /// Container image registry prefix for Carbide images.
    pub carbide_image_registry: String,
}

impl Default for CarbideServiceRegistryConfig {
    fn default() -> Self {
        Self {
            doca_helm_registry: carbide_dpf::services::DEFAULT_DOCA_HELM_REGISTRY.to_string(),
            carbide_helm_registry: "https://helm.ngc.nvidia.com/nvidia/carbide".to_string(),
            carbide_image_registry: "nvcr.io/nvidia/carbide".to_string(),
        }
    }
}

// TODO: wire into setup.rs when carbide services are deployed to DPUs
#[allow(dead_code)]
/// HBN (Host-Based Networking) service definition.
///
/// Configures HBN as a DPF service with interfaces for physical ports (p0, p1, pf0hpf)
/// and a carbide service interface, along with service chain switches that connect
/// physical ports to HBN interfaces.
pub fn hbn_service(reg: &CarbideServiceRegistryConfig) -> ServiceDefinition {
    ServiceDefinition {
        interfaces: vec![
            ServiceInterface {
                name: "p0_if".to_string(),
                network: HBN_NETWORK.to_string(),
            },
            ServiceInterface {
                name: "p1_if".to_string(),
                network: HBN_NETWORK.to_string(),
            },
            ServiceInterface {
                name: "pf0hpf_if".to_string(),
                network: HBN_NETWORK.to_string(),
            },
            ServiceInterface {
                name: "carbide_if".to_string(),
                network: HBN_NETWORK.to_string(),
            },
        ],
        config_values: Some(serde_json::json!({
            "service": {
                "nodePort": 30765,
                "type": "NodePort",
                "perDPUValuesYAML": "- hostnamePattern: \"*\"\n",
                "startupYAMLJ2": concat!(
                    "- header:\n",
                    "    model: bluefield\n",
                    "    nvue-api-version: nvue_v1\n",
                    "    rev-id: 1.0\n",
                    "    version: HBN 3.1.0\n",
                    "- set:\n",
                    "    system:\n",
                    "      api:\n",
                    "        listening-address:\n",
                    "          0.0.0.0: {}\n",
                )
            }
        })),
        config_ports: Some(vec![ServiceConfigPort {
            name: "nvueport".to_string(),
            port: 8765,
            protocol: ServiceConfigPortProtocol::Tcp,
            node_port: Some(30765),
        }]),
        config_ports_service_type: Some(ConfigPortsServiceType::NodePort),
        service_chain_switches: vec![
            ServiceChainSwitch {
                physical_interface: "p0".to_string(),
                service_name: HBN_SERVICE_NAME.to_string(),
                service_interface: "p0_if".to_string(),
            },
            ServiceChainSwitch {
                physical_interface: "p1".to_string(),
                service_name: HBN_SERVICE_NAME.to_string(),
                service_interface: "p1_if".to_string(),
            },
            ServiceChainSwitch {
                physical_interface: "pf0hpf".to_string(),
                service_name: HBN_SERVICE_NAME.to_string(),
                service_interface: "pf0hpf_if".to_string(),
            },
        ],
        service_daemon_set_annotations: Some(std::collections::BTreeMap::from([(
            "k8s.v1.cni.cncf.io/networks".to_string(),
            r#"[{"name":"iprequest","interface":"ip_lo","cni-args":{"poolNames":["loopback"],"poolType":"cidrpool"}},{"name":"iprequest","interface":"ip_pf0hpf","cni-args":{"poolNames":["pool1"],"poolType":"cidrpool","allocateDefaultGateway":true}},{"name":"iprequest","interface":"ip_pf1hpf","cni-args":{"poolNames":["pool2"],"poolType":"cidrpool","allocateDefaultGateway":true}}]"#
                .to_string(),
        )])),
        ..ServiceDefinition::new(
            HBN_SERVICE_NAME,
            &reg.doca_helm_registry,
            "doca-hbn",
            "3.1.0",
        )
    }
}

/// Build a Carbide service definition with standard image helm values.
fn carbide_service(
    reg: &CarbideServiceRegistryConfig,
    name: &str,
    image_name: &str,
    version: &str,
) -> ServiceDefinition {
    ServiceDefinition {
        helm_values: Some(serde_json::json!({
            "image": {
                "repository": format!("{}/{}", reg.carbide_image_registry, image_name),
                "tag": version
            }
        })),
        ..ServiceDefinition::new(name, &reg.carbide_helm_registry, name, version)
    }
}

// TODO: wire into setup.rs when carbide services are deployed to DPUs
#[allow(dead_code)]
/// OpenTelemetry Collector service definition.
pub fn otelcol_service(reg: &CarbideServiceRegistryConfig) -> ServiceDefinition {
    let mut svc = carbide_service(reg, "carbide-otelcol", "otelcol-contrib", "0.1.0");
    svc.config_ports = Some(vec![ServiceConfigPort {
        name: "prometheus".to_string(),
        port: 9999,
        protocol: ServiceConfigPortProtocol::Tcp,
        node_port: None,
    }]);
    svc.config_ports_service_type = Some(ConfigPortsServiceType::None);
    svc
}

// TODO: wire into setup.rs when carbide services are deployed to DPUs
#[allow(dead_code)]
/// Forge DPU Agent service definition.
pub fn dpu_agent_service(reg: &CarbideServiceRegistryConfig) -> ServiceDefinition {
    let mut svc = carbide_service(reg, "carbide-dpu-agent", "forge-dpu-agent", "0.1.0");
    svc.interfaces = vec![ServiceInterface {
        name: "carbide0".to_string(),
        network: HBN_NETWORK.to_string(),
    }];
    svc.config_ports = Some(vec![ServiceConfigPort {
        name: "metrics".to_string(),
        port: 8888,
        protocol: ServiceConfigPortProtocol::Tcp,
        node_port: None,
    }]);
    svc.config_ports_service_type = Some(ConfigPortsServiceType::None);
    svc.service_chain_switches = vec![ServiceChainSwitch {
        physical_interface: "carbide0".to_string(),
        service_name: HBN_SERVICE_NAME.to_string(),
        service_interface: "carbide_if".to_string(),
    }];
    svc
}

// TODO: wire into setup.rs when carbide services are deployed to DPUs
#[allow(dead_code)]
/// Forge DHCP Server service definition.
pub fn dhcp_server_service(reg: &CarbideServiceRegistryConfig) -> ServiceDefinition {
    carbide_service(reg, "carbide-dhcp-server", "forge-dhcp-server", "0.1.0")
}

// TODO: wire into setup.rs when carbide services are deployed to DPUs
#[allow(dead_code)]
/// Forge DPU OTel Agent service definition.
pub fn dpu_otel_agent_service(reg: &CarbideServiceRegistryConfig) -> ServiceDefinition {
    carbide_service(
        reg,
        "carbide-dpu-otel-agent",
        "forge-dpu-otel-agent",
        "0.1.0",
    )
}
