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
use std::fmt::Write;

use carbide_dpf::sdk::build_dpu_interfaces_vec;
use carbide_dpf::types::{DHCP_SERVER_SERVICE_NAME, DOCA_HBN_SERVICE_NAME, FMDS_SERVICE_NAME};
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
pub const DOCA_HBN_SERVICE_HELM_NAME: &str = "doca-hbn";
pub const DOCA_HBN_SERVICE_HELM_VERSION: &str = "1.0.5";
pub const DOCA_HBN_SERVICE_IMAGE_NAME: &str = "doca_hbn";
pub const DOCA_HBN_SERVICE_IMAGE_TAG: &str = "3.2.1-doca3.2.1";
pub const DOCA_HBN_SERVICE_NETWORK: &str = "mybrhbn";

/// DHCP Service Definitions
pub const DHCP_SERVER_SERVICE_HELM_NAME: &str = "carbide-dhcp-server";
pub const DHCP_SERVER_SERVICE_HELM_VERSION: &str = "2.0.9";
pub const DHCP_SERVER_SERVICE_IMAGE_NAME: &str = "forge-dhcp-server";
pub const DHCP_SERVER_SERVICE_IMAGE_TAG: &str = "v1.9.5-arm64-distroless";
pub const DHCP_SERVER_SERVICE_NAD_NAME: &str = "mybrsfc-dhcp";
pub const DHCP_SERVER_SERVICE_MTU: i64 = 1500;

// DPU Agent Service Definitions
pub const DPU_AGENT_SERVICE_NAME: &str = "carbide-dpu-agent";
pub const DPU_AGENT_SERVICE_HELM_NAME: &str = "carbide-dpu-agent";
pub const DPU_AGENT_SERVICE_HELM_VERSION: &str = "0.9.0";
pub const DPU_AGENT_SERVICE_IMAGE_NAME: &str = "forge-dpu-agent";
pub const DPU_AGENT_SERVICE_IMAGE_TAG: &str = "v0.5-arm64-multistage";

/// FMDS Agent Service Definitions
pub const FMDS_SERVICE_HELM_NAME: &str = "carbide-fmds";
pub const FMDS_SERVICE_HELM_VERSION: &str = "0.1.0";
pub const FMDS_SERVICE_IMAGE_NAME: &str = "carbide-fmds";
pub const FMDS_SERVICE_NAD_NAME: &str = "mybrsfc-fmds";
pub const FMDS_SERVICE_IMAGE_TAG: &str = "v0.1-arm64-distroless";
pub const FMDS_SERVICE_MTU: i64 = 1500;

fn doca_hbn_service_interfaces() -> Vec<ServiceInterface> {
    dpu_service_interfaces(DOCA_HBN_SERVICE_NAME, DOCA_HBN_SERVICE_NETWORK)
}
fn dhcp_server_service_interfaces() -> Vec<ServiceInterface> {
    dpu_service_interfaces(DHCP_SERVER_SERVICE_NAME, DHCP_SERVER_SERVICE_NAD_NAME)
}

fn dpu_service_interfaces(service_name: &str, network: &str) -> Vec<ServiceInterface> {
    build_dpu_interfaces_vec()
        .into_iter()
        .filter_map(|iface| {
            iface.chained_svc_if.and_then(|chains| {
                chains
                    .into_iter()
                    .find_map(|(chained_service_name, interface_name)| {
                        (chained_service_name == service_name).then(|| ServiceInterface {
                            name: interface_name,
                            network: network.to_string(),
                        })
                    })
            })
        })
        .collect()
}

fn doca_hbn_startup_yaml(interfaces: &[ServiceInterface]) -> String {
    let mut startup_yaml = String::from(concat!(
        "- header:\n",
        "    model: BLUEFIELD\n",
        "    nvue-api-version: nvue_v1\n",
        "    rev-id: 1.0\n",
        "    version: HBN 2.4.0\n",
        "- set:\n",
        "    interface:\n",
    ));

    for interface in interfaces {
        let _ = writeln!(startup_yaml, "      {}:", interface.name);
        startup_yaml.push_str("        type: swp\n");
    }

    startup_yaml
}

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
    let interfaces = doca_hbn_service_interfaces();

    ServiceDefinition {
        helm_values: Some(serde_json::json!({
            "image": {
                "repository": format!("{}/{}", reg.doca_image_registry,
                    DOCA_HBN_SERVICE_IMAGE_NAME),
                "tag": DOCA_HBN_SERVICE_IMAGE_TAG,
            },
            "resources": {
                "memory": "6Gi",
                "nvidia.com/bf_sf": interfaces.len(),
            },
            "configuration": {
                "user": {
                    "create": true,
                    "username": {
                        "secretName": "hbn-user-password",
                        "secretKey": "username",
                    },
                    "password": {
                        "secretName": "hbn-user-password",
                        "secretKey": "password",
                    },
                },
            },
        })),

        config_values: Some(serde_json::json!({
            "configuration": {
                "startupYAMLJ2": doca_hbn_startup_yaml(&interfaces)
            }
        })),

        service_daemon_set_annotations: Some(BTreeMap::new()),

        interfaces,

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

/// Forge DPU Agent service definition.
pub fn dpu_agent_service(reg: &CarbideServiceRegistryConfig) -> ServiceDefinition {
    ServiceDefinition {
        helm_values: Some(serde_json::json!({
            "image": {
                "repository": format!("{}/{}", reg.carbide_image_registry,
                    DPU_AGENT_SERVICE_IMAGE_NAME),
                "tag": DPU_AGENT_SERVICE_IMAGE_TAG,
            },
            "hbn": {
                "nvue_https_address": "nvue",
                "nvue_credentials_secret_name": "hbn-user-password",
                "nvue_username_key": "username",
                "nvue_password_key": "password",
            },
        })),

        service_daemon_set_annotations: Some(BTreeMap::new()),

        config_values: Some(serde_json::json!({
            "dhcp_server": {
                "service_name": "{{ (index .Services \"carbide-dhcp-server\").Name }}"
            },
            "carbide_fmds": {
                "service_name": "{{ (index .Services \"carbide-fmds\").Name }}"
            }
        })),

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

        interfaces: dhcp_server_service_interfaces(),

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

/// FMDS Service
pub fn fmds_service(reg: &CarbideServiceRegistryConfig) -> ServiceDefinition {
    ServiceDefinition {
        helm_values: Some(serde_json::json!({
            "image": {
                "repository": format!("{}/{}", reg.carbide_image_registry,
                    FMDS_SERVICE_IMAGE_NAME),
                "tag": FMDS_SERVICE_IMAGE_TAG,
            }
        })),

        interfaces: vec![ServiceInterface {
            name: "f_pf0hpf_if".to_string(),
            network: FMDS_SERVICE_NAD_NAME.to_string(),
        }],

        service_daemon_set_annotations: Some(BTreeMap::new()),

        service_nad: Some(ServiceNAD {
            name: FMDS_SERVICE_NAD_NAME.to_string(),
            bridge: Some("br-sfc".to_string()),
            resource_type: ServiceNADResourceType::Sf,
            ipam: Some(false),
            mtu: Some(FMDS_SERVICE_MTU),
        }),

        ..ServiceDefinition::new(
            FMDS_SERVICE_NAME,
            &reg.carbide_helm_registry,
            FMDS_SERVICE_HELM_NAME,
            FMDS_SERVICE_HELM_VERSION,
        )
    }
}

#[cfg(test)]
mod tests {
    use carbide_dpf::sdk::build_dpu_interfaces_vec;
    use carbide_dpf::types::DpuServiceInterfaceTemplateType;
    use carbide_dpf::{
        NoLabels, build_deployment, build_service_configuration, build_service_interface,
        build_service_nad, build_service_template,
    };

    use super::*;

    const TEST_NS: &str = "dpf-operator-system";

    // ---- dpu_service_interfaces ----

    #[test]
    fn test_dpu_service_interfaces_hbn_uses_correct_network() {
        let ifaces = dpu_service_interfaces(DOCA_HBN_SERVICE_NAME, DOCA_HBN_SERVICE_NETWORK);
        assert!(!ifaces.is_empty(), "HBN should have at least one interface");
        for iface in &ifaces {
            assert_eq!(
                iface.network, DOCA_HBN_SERVICE_NETWORK,
                "HBN interface '{}' has wrong network",
                iface.name
            );
        }
    }

    #[test]
    fn test_dpu_service_interfaces_dhcp_uses_correct_network() {
        let ifaces = dpu_service_interfaces(DHCP_SERVER_SERVICE_NAME, DHCP_SERVER_SERVICE_NAD_NAME);
        assert!(
            !ifaces.is_empty(),
            "DHCP server should have at least one interface"
        );
        for iface in &ifaces {
            assert_eq!(
                iface.network, DHCP_SERVER_SERVICE_NAD_NAME,
                "DHCP interface '{}' has wrong network",
                iface.name
            );
        }
    }

    #[test]
    fn test_dpu_service_interfaces_derived_from_build_dpu_interfaces_vec() {
        // Every interface returned for HBN must originate from build_dpu_interfaces_vec.
        let all_ifaces = build_dpu_interfaces_vec();
        let hbn_ifaces = dpu_service_interfaces(DOCA_HBN_SERVICE_NAME, DOCA_HBN_SERVICE_NETWORK);
        let dhcp_ifaces =
            dpu_service_interfaces(DHCP_SERVER_SERVICE_NAME, DHCP_SERVER_SERVICE_NAD_NAME);

        let all_chained_names: Vec<String> = all_ifaces
            .iter()
            .flat_map(|i| i.chained_svc_if.iter().flatten())
            .map(|(_, ifname)| ifname.clone())
            .collect();

        for iface in hbn_ifaces.iter().chain(dhcp_ifaces.iter()) {
            assert!(
                all_chained_names.contains(&iface.name),
                "Interface '{}' was not derived from build_dpu_interfaces_vec",
                iface.name
            );
        }
    }

    // ---- doca_hbn_service ----

    #[test]
    fn test_doca_hbn_service_name_and_helm() {
        let reg = CarbideServiceRegistryConfig::default();
        let svc = doca_hbn_service(&reg);
        assert_eq!(svc.name, DOCA_HBN_SERVICE_NAME);
        assert_eq!(svc.helm_chart, DOCA_HBN_SERVICE_HELM_NAME);
        assert_eq!(svc.helm_version, DOCA_HBN_SERVICE_HELM_VERSION);
        assert!(svc.helm_repo_url.contains("helm.ngc.nvidia.com"));
    }

    #[test]
    fn test_doca_hbn_service_interfaces_match_derived() {
        let reg = CarbideServiceRegistryConfig::default();
        let svc = doca_hbn_service(&reg);
        let expected = dpu_service_interfaces(DOCA_HBN_SERVICE_NAME, DOCA_HBN_SERVICE_NETWORK);
        assert_eq!(
            svc.interfaces.len(),
            expected.len(),
            "HBN service interface count mismatch"
        );
        for (a, b) in svc.interfaces.iter().zip(expected.iter()) {
            assert_eq!(a.name, b.name);
            assert_eq!(a.network, b.network);
        }
    }

    #[test]
    fn test_doca_hbn_service_startup_yaml_contains_interfaces() {
        let reg = CarbideServiceRegistryConfig::default();
        let svc = doca_hbn_service(&reg);
        let config_values = svc
            .config_values
            .as_ref()
            .expect("config_values must be set");
        let startup_yaml = config_values["configuration"]["startupYAMLJ2"]
            .as_str()
            .expect("startupYAMLJ2 must be a string");
        for iface in &svc.interfaces {
            assert!(
                startup_yaml.contains(&iface.name),
                "startupYAMLJ2 missing interface '{}'",
                iface.name
            );
        }
    }

    #[test]
    fn test_doca_hbn_service_image_uses_registry() {
        let reg = CarbideServiceRegistryConfig::default();
        let svc = doca_hbn_service(&reg);
        let helm_values = svc.helm_values.as_ref().unwrap();
        let repo = helm_values["image"]["repository"].as_str().unwrap();
        assert!(
            repo.contains(DOCA_HBN_SERVICE_IMAGE_NAME),
            "image repository should contain image name"
        );
        assert!(
            repo.starts_with(&reg.doca_image_registry),
            "image repository should use doca_image_registry"
        );
    }

    // ---- dhcp_server_service ----

    #[test]
    fn test_dhcp_server_service_name_and_helm() {
        let reg = CarbideServiceRegistryConfig::default();
        let svc = dhcp_server_service(&reg);
        assert_eq!(svc.name, DHCP_SERVER_SERVICE_NAME);
        assert_eq!(svc.helm_chart, DHCP_SERVER_SERVICE_HELM_NAME);
        assert_eq!(svc.helm_version, DHCP_SERVER_SERVICE_HELM_VERSION);
    }

    #[test]
    fn test_dhcp_server_service_interfaces_match_derived() {
        let reg = CarbideServiceRegistryConfig::default();
        let svc = dhcp_server_service(&reg);
        let expected =
            dpu_service_interfaces(DHCP_SERVER_SERVICE_NAME, DHCP_SERVER_SERVICE_NAD_NAME);
        assert_eq!(
            svc.interfaces.len(),
            expected.len(),
            "DHCP service interface count mismatch"
        );
        for (a, b) in svc.interfaces.iter().zip(expected.iter()) {
            assert_eq!(a.name, b.name);
            assert_eq!(a.network, b.network);
        }
    }

    #[test]
    fn test_dhcp_server_service_nad_properties() {
        let reg = CarbideServiceRegistryConfig::default();
        let svc = dhcp_server_service(&reg);
        let nad = svc
            .service_nad
            .as_ref()
            .expect("DHCP service must have a NAD");
        assert_eq!(nad.name, DHCP_SERVER_SERVICE_NAD_NAME);
        assert_eq!(nad.mtu, Some(DHCP_SERVER_SERVICE_MTU));
        assert_eq!(nad.ipam, Some(false));
        assert_eq!(nad.bridge.as_deref(), Some("br-sfc"));
    }

    // ---- dpu_agent_service ----

    #[test]
    fn test_dpu_agent_service_name_and_helm() {
        let reg = CarbideServiceRegistryConfig::default();
        let svc = dpu_agent_service(&reg);
        assert_eq!(svc.name, DPU_AGENT_SERVICE_NAME);
        assert_eq!(svc.helm_chart, DPU_AGENT_SERVICE_HELM_NAME);
        assert_eq!(svc.helm_version, DPU_AGENT_SERVICE_HELM_VERSION);
    }

    #[test]
    fn test_dpu_agent_service_image_uses_registry() {
        let reg = CarbideServiceRegistryConfig::default();
        let svc = dpu_agent_service(&reg);
        let helm_values = svc.helm_values.as_ref().unwrap();
        let repo = helm_values["image"]["repository"].as_str().unwrap();
        assert!(repo.contains(DPU_AGENT_SERVICE_IMAGE_NAME));
        assert!(repo.starts_with(&reg.carbide_image_registry));
    }

    // ---- build_service_template ----

    #[test]
    fn test_build_service_template_metadata() {
        let reg = CarbideServiceRegistryConfig::default();
        let svc = dhcp_server_service(&reg);
        let tmpl = build_service_template(&svc, TEST_NS);
        assert_eq!(
            tmpl.metadata.name.as_deref(),
            Some(DHCP_SERVER_SERVICE_NAME)
        );
        assert_eq!(tmpl.metadata.namespace.as_deref(), Some(TEST_NS));
        assert_eq!(tmpl.spec.deployment_service_name, DHCP_SERVER_SERVICE_NAME);
        assert_eq!(
            tmpl.spec.helm_chart.source.version.as_str(),
            DHCP_SERVER_SERVICE_HELM_VERSION
        );
    }

    #[test]
    fn test_build_service_template_helm_values_included() {
        let reg = CarbideServiceRegistryConfig::default();
        let svc = doca_hbn_service(&reg);
        let tmpl = build_service_template(&svc, TEST_NS);
        let values = tmpl
            .spec
            .helm_chart
            .values
            .as_ref()
            .expect("helm values must be present");
        assert!(
            values.contains_key("image"),
            "helm values must include 'image'"
        );
    }

    // ---- build_service_configuration ----

    #[test]
    fn test_build_service_configuration_interfaces() {
        let reg = CarbideServiceRegistryConfig::default();
        let svc = dhcp_server_service(&reg);
        let cfg = build_service_configuration(&svc, TEST_NS);
        let ifaces = cfg
            .spec
            .interfaces
            .as_ref()
            .expect("interfaces must be present");
        assert_eq!(ifaces.len(), svc.interfaces.len());
        for (actual, expected) in ifaces.iter().zip(svc.interfaces.iter()) {
            assert_eq!(actual.name, expected.name);
            assert_eq!(actual.network, expected.network);
        }
    }

    #[test]
    fn test_build_service_configuration_config_values() {
        let reg = CarbideServiceRegistryConfig::default();
        let svc = doca_hbn_service(&reg);
        let cfg = build_service_configuration(&svc, TEST_NS);
        let svc_cfg = cfg
            .spec
            .service_configuration
            .as_ref()
            .expect("service_configuration must be present");
        let helm = svc_cfg
            .helm_chart
            .as_ref()
            .expect("helm_chart config must be present");
        let values = helm
            .values
            .as_ref()
            .expect("helm chart values must be present");
        assert!(
            values.contains_key("configuration"),
            "config_values must include 'configuration'"
        );
    }

    #[test]
    fn test_build_service_configuration_no_interfaces_for_agents() {
        // dpu_agent_service has no interfaces — spec.interfaces should be None
        let reg = CarbideServiceRegistryConfig::default();
        let svc = dpu_agent_service(&reg);
        let cfg = build_service_configuration(&svc, TEST_NS);
        assert!(
            cfg.spec.interfaces.is_none(),
            "agent service must have no interfaces in config"
        );
    }

    // ---- build_service_nad ----

    #[test]
    fn test_build_service_nad_present_for_dhcp() {
        let reg = CarbideServiceRegistryConfig::default();
        let svc = dhcp_server_service(&reg);
        let nad = build_service_nad(&svc, TEST_NS).expect("DHCP must produce a NAD");
        assert_eq!(
            nad.metadata.name.as_deref(),
            Some(DHCP_SERVER_SERVICE_NAD_NAME)
        );
        assert_eq!(nad.metadata.namespace.as_deref(), Some(TEST_NS));
    }

    #[test]
    fn test_build_service_nad_absent_for_hbn() {
        let reg = CarbideServiceRegistryConfig::default();
        let svc = doca_hbn_service(&reg);
        assert!(
            build_service_nad(&svc, TEST_NS).is_none(),
            "HBN service should not produce a NAD"
        );
    }

    // ---- build_service_interface ----

    #[test]
    fn test_build_service_interface_physical() {
        let interfaces = build_dpu_interfaces_vec();
        let p0 = interfaces
            .iter()
            .find(|i| i.name == "p0")
            .expect("p0 must exist");
        assert!(matches!(
            p0.iface_type,
            DpuServiceInterfaceTemplateType::Physical
        ));
        let cr = build_service_interface(p0, TEST_NS);
        assert_eq!(cr.metadata.name.as_deref(), Some("p0"));
        assert_eq!(cr.metadata.namespace.as_deref(), Some(TEST_NS));
        let template_spec = &cr.spec.template.spec.template.spec;
        assert!(
            template_spec.physical.is_some(),
            "physical spec must be set for Physical type"
        );
        assert!(template_spec.pf.is_none());
        assert!(template_spec.vf.is_none());
    }

    #[test]
    fn test_build_service_interface_pf() {
        let interfaces = build_dpu_interfaces_vec();
        let pf0hpf = interfaces
            .iter()
            .find(|i| i.name == "pf0hpf")
            .expect("pf0hpf must exist");
        assert!(matches!(
            pf0hpf.iface_type,
            DpuServiceInterfaceTemplateType::Pf
        ));
        let cr = build_service_interface(pf0hpf, TEST_NS);
        let template_spec = &cr.spec.template.spec.template.spec;
        assert!(
            template_spec.pf.is_some(),
            "pf spec must be set for Pf type"
        );
        assert!(template_spec.physical.is_none());
        assert!(template_spec.vf.is_none());
    }

    #[test]
    fn test_build_service_interface_vf() {
        let interfaces = build_dpu_interfaces_vec();
        let pf0vf0 = interfaces
            .iter()
            .find(|i| i.name == "pf0vf0")
            .expect("pf0vf0 must exist");
        assert!(matches!(
            pf0vf0.iface_type,
            DpuServiceInterfaceTemplateType::Vf
        ));
        let cr = build_service_interface(pf0vf0, TEST_NS);
        let template_spec = &cr.spec.template.spec.template.spec;
        assert!(
            template_spec.vf.is_some(),
            "vf spec must be set for Vf type"
        );
        let vf = template_spec.vf.as_ref().unwrap();
        assert_eq!(vf.pf_id, 0);
        assert_eq!(vf.vf_id, 0);
        assert_eq!(vf.parent_interface_ref.as_deref(), Some("p0"));
        assert!(template_spec.physical.is_none());
        assert!(template_spec.pf.is_none());
    }

    #[test]
    fn test_build_service_interface_label_matches_name() {
        let interfaces = build_dpu_interfaces_vec();
        for iface in &interfaces {
            let cr = build_service_interface(iface, TEST_NS);
            let labels = cr
                .spec
                .template
                .spec
                .template
                .metadata
                .as_ref()
                .and_then(|m| m.labels.as_ref())
                .expect("labels must be present");
            assert_eq!(
                labels.get("interface").map(String::as_str),
                Some(iface.name.as_str()),
                "'interface' label must match iface name for '{}'",
                iface.name
            );
        }
    }

    // ---- build_deployment ----

    #[test]
    fn test_build_deployment_lists_all_services() {
        let reg = CarbideServiceRegistryConfig::default();
        let services = vec![dhcp_server_service(&reg), doca_hbn_service(&reg)];
        let interfaces = build_dpu_interfaces_vec();
        let deployment = build_deployment(
            &services,
            "carbide-deployment",
            "test-bfb",
            "dpu-flavor",
            TEST_NS,
            &NoLabels,
            &interfaces,
        );
        assert_eq!(
            deployment.metadata.name.as_deref(),
            Some("carbide-deployment")
        );
        assert_eq!(deployment.spec.dpus.bfb, "test-bfb");
        assert_eq!(deployment.spec.dpus.flavor, "dpu-flavor");
        assert_eq!(deployment.spec.services.len(), 2);
        assert!(
            deployment
                .spec
                .services
                .contains_key(DHCP_SERVER_SERVICE_NAME)
        );
        assert!(deployment.spec.services.contains_key(DOCA_HBN_SERVICE_NAME));
    }

    #[test]
    fn test_build_deployment_service_chain_count_matches_chained_interfaces() {
        let reg = CarbideServiceRegistryConfig::default();
        let services = vec![dhcp_server_service(&reg), doca_hbn_service(&reg)];
        let interfaces = build_dpu_interfaces_vec();
        let expected_switches = interfaces
            .iter()
            .filter(|i| i.chained_svc_if.is_some())
            .count();
        let deployment = build_deployment(
            &services,
            "carbide-deployment",
            "test-bfb",
            "dpu-flavor",
            TEST_NS,
            &NoLabels,
            &interfaces,
        );
        let switches = deployment
            .spec
            .service_chains
            .as_ref()
            .expect("service_chains must be present")
            .switches
            .len();
        assert_eq!(switches, expected_switches);
    }
}
