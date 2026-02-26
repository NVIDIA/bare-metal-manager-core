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

//! DPU service definitions (DTS, etc.) for DPUServiceTemplate and DPUServiceConfiguration.

use crate::types::{
    ConfigPortsServiceType, ServiceChainSwitch, ServiceConfigPort, ServiceConfigPortProtocol,
    ServiceDefinition, ServiceInterface,
};

/// Default DOCA helm registry (DPUServiceTemplate source.repoURL).
pub const DEFAULT_DOCA_HELM_REGISTRY: &str = "https://helm.ngc.nvidia.com/nvidia/doca";

/// Default Carbide helm registry for custom DPU services.
pub const DEFAULT_CARBIDE_HELM_REGISTRY: &str = "https://helm.ngc.nvidia.com/nvidia/carbide";

/// Default Carbide container image registry prefix.
pub const DEFAULT_CARBIDE_IMAGE_REGISTRY: &str = "nvcr.io/nvidia/carbide";

/// HBN network name used by service interfaces and service chains.
const HBN_NETWORK: &str = "mybrhbn";

/// HBN service name used in DPUServiceTemplate/DPUServiceConfiguration.
pub const HBN_SERVICE_NAME: &str = "doca-hbn";

/// Overridable registry and version configuration for DPU services.
///
/// Allows callers to redirect helm chart sources and container image
/// repositories for airgapped, development, or mirrored environments.
#[derive(Debug, Clone)]
pub struct ServiceRegistryConfig {
    /// Helm chart repository URL for DOCA services (HBN, DTS).
    pub doca_helm_registry: String,
    /// Helm chart repository URL for Carbide services.
    pub carbide_helm_registry: String,
    /// Container image registry prefix for Carbide images (e.g. "nvcr.io/nvidia/carbide").
    pub carbide_image_registry: String,
}

impl Default for ServiceRegistryConfig {
    fn default() -> Self {
        Self {
            doca_helm_registry: DEFAULT_DOCA_HELM_REGISTRY.to_string(),
            carbide_helm_registry: DEFAULT_CARBIDE_HELM_REGISTRY.to_string(),
            carbide_image_registry: DEFAULT_CARBIDE_IMAGE_REGISTRY.to_string(),
        }
    }
}

/// DTS (Doca Telemetry Service) service definition. Reusable by the API and SDK.
pub fn dts_service(reg: &ServiceRegistryConfig) -> ServiceDefinition {
    ServiceDefinition {
        helm_values: Some(serde_json::json!({
            "exposedPorts": { "ports": { "httpserverport": true } }
        })),
        config_ports: Some(vec![ServiceConfigPort {
            name: "httpserverport".to_string(),
            port: 9100,
            protocol: ServiceConfigPortProtocol::Tcp,
            node_port: None,
        }]),
        config_ports_service_type: Some(ConfigPortsServiceType::None),
        ..ServiceDefinition::new("dts", &reg.doca_helm_registry, "doca-telemetry", "1.22.1")
    }
}

/// HBN (Host-Based Networking) service definition.
///
/// Configures HBN as a DPF service with interfaces for physical ports (p0, p1, pf0hpf)
/// and a carbide service interface, along with service chain switches that connect
/// physical ports to HBN interfaces.
pub fn hbn_service(reg: &ServiceRegistryConfig) -> ServiceDefinition {
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
        ..ServiceDefinition::new(HBN_SERVICE_NAME, &reg.doca_helm_registry, "doca-hbn", "3.1.0")
    }
}

/// Build a Carbide service definition with standard image helm values.
fn carbide_service(
    reg: &ServiceRegistryConfig,
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

/// OpenTelemetry Collector service definition.
///
/// Deploys a custom otelcol-contrib build with fileresourceprocessor and
/// telemetrystatsprocessor. Scrapes forge-dpu-agent, DTS, and hostmetrics,
/// then exports logs and metrics to the Carbide OTLP backend via mTLS.
pub fn otelcol_service(reg: &ServiceRegistryConfig) -> ServiceDefinition {
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

/// Forge DPU Agent service definition.
///
/// Core Carbide runtime agent handling configuration fetch, NVUE apply, IMDS,
/// health checks, and status reporting. Uses an SFC chain to connect a
/// `carbide0` interface to HBN's `carbide_if` bridge port.
pub fn dpu_agent_service(reg: &ServiceRegistryConfig) -> ServiceDefinition {
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

/// Forge DHCP Server service definition.
///
/// Provides DHCP serving for VMs and containers connected through HBN.
pub fn dhcp_server_service(reg: &ServiceRegistryConfig) -> ServiceDefinition {
    carbide_service(reg, "carbide-dhcp-server", "forge-dhcp-server", "0.1.0")
}

/// Forge DPU OTel Agent service definition.
///
/// Handles mTLS certificate renewal for the otelcol-contrib connection to the
/// Carbide OTLP receiver at otel-receiver.forge:443.
pub fn dpu_otel_agent_service(reg: &ServiceRegistryConfig) -> ServiceDefinition {
    carbide_service(
        reg,
        "carbide-dpu-otel-agent",
        "forge-dpu-otel-agent",
        "0.1.0",
    )
}

/// Default DPU services per design. Used when config.services is empty.
pub fn default_services(reg: &ServiceRegistryConfig) -> Vec<ServiceDefinition> {
    vec![
        hbn_service(reg),
        dts_service(reg),
        otelcol_service(reg),
        dpu_agent_service(reg),
        dhcp_server_service(reg),
        dpu_otel_agent_service(reg),
    ]
}
