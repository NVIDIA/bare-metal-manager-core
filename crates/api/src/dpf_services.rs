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

use std::collections::BTreeMap;

use carbide_dpf::{
    ConfigPortsServiceType, ServiceConfigPort, ServiceConfigPortProtocol, ServiceDefinition,
    ServiceInterface, ServiceNAD, ServiceNADResourceType,
};

/// Default DOCA helm registry (DPUServiceTemplate source.repoURL).
pub const DEFAULT_DOCA_HELM_REGISTRY: &str = "https://helm.ngc.nvidia.com/nvidia/doca";

pub const DEFAULT_CARBIDE_HELM_REGISTRY: &str =
    "https://gitlab-master.nvidia.com/aadvani/my-helm-project/-/raw/main/charts-repo";

/// Default DOCA container image registry prefix.
pub const DEFAULT_DOCA_IMAGE_REGISTRY: &str = "nvcr.io/nvidia/doca";

/// Default Carbide container image registry prefix.
pub const DEFAULT_CARBIDE_IMAGE_REGISTRY: &str = "gitlab-master.nvidia.com/aadvani/my-helm-project";

/// HBN service Definitions
pub const DOCA_HBN_SERVICE_NAME: &str = "doca-hbn";
pub const DOCA_HBN_SERVICE_HELM_NAME: &str = "doca-hbn";
pub const DOCA_HBN_SERVICE_HELM_VERSION: &str = "1.0.5";
pub const DOCA_HBN_SERVICE_IMAGE_NAME: &str = "doca_hbn";
pub const DOCA_HBN_SERVICE_IMAGE_TAG: &str = "3.2.1-doca3.2.1";
pub const DOCA_HBN_SERVICE_NETWORK: &str = "mybrhbn";

/// DHCP Service Definitions
pub const DHCP_SERVER_SERVICE_NAME: &str = "carbide-dhcp-server";
pub const DHCP_SERVER_SERVICE_HELM_NAME: &str = "carbide-dhcp-server";
pub const DHCP_SERVER_SERVICE_HELM_VERSION: &str = "2.0.9";
pub const DHCP_SERVER_SERVICE_IMAGE_NAME: &str = "forge-dhcp-server";
pub const DHCP_SERVER_SERVICE_IMAGE_TAG: &str = "v1.9.5-arm64-distroless";
pub const DHCP_SERVER_SERVICE_NAD_NAME: &str = "mybrsfc-dhcp";
pub const DHCP_SERVER_SERVICE_MTU: i64 = 1500;

// DPU Agent Service Definitions
pub const DPU_AGENT_SERVICE_NAME: &str = "carbide-dpu-agent";
pub const DPU_AGENT_SERVICE_HELM_NAME: &str = "carbide-dpu-agent";
pub const DPU_AGENT_SERVICE_HELM_VERSION: &str = "0.4.0";
pub const DPU_AGENT_SERVICE_IMAGE_NAME: &str = "forge-dpu-agent";
pub const DPU_AGENT_SERVICE_IMAGE_TAG: &str = "v0.3-arm64-multistage";

/// Extended registry configuration for Carbide DPU services.
#[derive(Debug, Clone)]
pub struct CarbideServiceRegistryConfig {
    /// Helm chart repository URL for DOCA services (HBN, DTS).
    pub doca_helm_registry: String,
    /// Helm image repository for DOCA Services
    pub doca_image_registry: String,
    /// Helm chart repository URL for Carbide services.
    pub carbide_helm_registry: String,
    /// Container image registry prefix for Carbide images.
    pub carbide_image_registry: String,
}

impl Default for CarbideServiceRegistryConfig {
    fn default() -> Self {
        Self {
            doca_helm_registry: DEFAULT_DOCA_HELM_REGISTRY.to_string(),
            doca_image_registry: DEFAULT_DOCA_IMAGE_REGISTRY.to_string(),
            carbide_helm_registry: DEFAULT_CARBIDE_HELM_REGISTRY.to_string(),
            carbide_image_registry: DEFAULT_CARBIDE_IMAGE_REGISTRY.to_string(),
        }
    }
}

pub fn doca_hbn_service(reg: &CarbideServiceRegistryConfig) -> ServiceDefinition {
    ServiceDefinition {
        helm_values: Some(serde_json::json!({
            "image": {
                "repository": format!("{}/{}", reg.doca_image_registry,
                    DOCA_HBN_SERVICE_IMAGE_NAME),
                "tag": DOCA_HBN_SERVICE_IMAGE_TAG,
            },
            "resources": {
                "memory": "6Gi",
                "nvidia.com/bf_sf": 2
            },
        })),

        config_values: Some(serde_json::json!({
            "configuration": {
                "startupYAMLJ2": concat!(
                    "- header:\n",
                    "    model: BLUEFIELD\n",
                    "    nvue-api-version: nvue_v1\n",
                    "    rev-id: 1.0\n",
                    "    version: HBN 2.4.0\n",
                    "- set:\n",
                    "    interface:\n",
                    "      p0_if:\n",
                    "        type: swp\n",
                    "      pf0hpf_if:\n",
                    "        type: swp\n",
                )
            }
        })),

        service_daemon_set_annotations: Some(BTreeMap::new()),

        interfaces: vec![
            ServiceInterface {
                name: "p0_if".to_string(),
                network: DOCA_HBN_SERVICE_NETWORK.to_string(),
            },
            ServiceInterface {
                name: "pf0hpf_if".to_string(),
                network: DOCA_HBN_SERVICE_NETWORK.to_string(),
            },
        ],

        ..ServiceDefinition::new(
            DOCA_HBN_SERVICE_NAME,
            &reg.doca_helm_registry,
            DOCA_HBN_SERVICE_HELM_NAME,
            DOCA_HBN_SERVICE_HELM_VERSION,
        )
    }
}

/// Build a Carbide service definition with standard image helm values.
#[allow(dead_code)]
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
    ServiceDefinition {
        helm_values: Some(serde_json::json!({
            "image": {
                "repository": format!("{}/{}", reg.carbide_image_registry,
                    DPU_AGENT_SERVICE_IMAGE_NAME),
                "tag": DPU_AGENT_SERVICE_IMAGE_TAG,
            }
        })),

        service_daemon_set_annotations: Some(BTreeMap::new()),

        ..ServiceDefinition::new(
            DPU_AGENT_SERVICE_NAME,
            &reg.carbide_helm_registry,
            DPU_AGENT_SERVICE_HELM_NAME,
            DPU_AGENT_SERVICE_HELM_VERSION,
        )
    }
}

// TODO: wire into setup.rs when carbide services are deployed to DPUs
/// Forge DHCP Server service definition.
pub fn dhcp_server_service(reg: &CarbideServiceRegistryConfig) -> ServiceDefinition {
    ServiceDefinition {
        helm_values: Some(serde_json::json!({
            "image": {
                "repository": format!("{}/{}", reg.carbide_image_registry,
                    DHCP_SERVER_SERVICE_IMAGE_NAME),
                "tag": DHCP_SERVER_SERVICE_IMAGE_TAG,
            }
        })),

        interfaces: vec![ServiceInterface {
            name: "d_pf0hpf_if".to_string(),
            network: DHCP_SERVER_SERVICE_NAD_NAME.to_string(),
        }],

        service_daemon_set_annotations: Some(BTreeMap::new()),

        service_nad: Some(ServiceNAD {
            name: DHCP_SERVER_SERVICE_NAD_NAME.to_string(),
            bridge: Some("br-sfc".to_string()),
            resource_type: ServiceNADResourceType::Sf,
            ipam: Some(false),
            mtu: Some(DHCP_SERVER_SERVICE_MTU),
        }),

        ..ServiceDefinition::new(
            DHCP_SERVER_SERVICE_NAME,
            &reg.carbide_helm_registry,
            DHCP_SERVER_SERVICE_HELM_NAME,
            DHCP_SERVER_SERVICE_HELM_VERSION,
        )
    }
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
