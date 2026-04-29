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

use crate::cfg::file::DpfServiceConfig;

/// Default DOCA helm registry (DPUServiceTemplate source.repoURL).
pub const DEFAULT_DOCA_HELM_REGISTRY: &str = "https://helm.ngc.nvidia.com/nvidia/doca";

pub const DEFAULT_CARBIDE_HELM_REGISTRY: &str =
    "https://helm.ngc.nvidia.com/0837451325059433/carbide-dev";

/// Default DOCA container image registry prefix.
pub const DEFAULT_DOCA_IMAGE_REGISTRY: &str = "nvcr.io/nvidia/doca";

/// Default Carbide container image registry prefix.
pub const DEFAULT_CARBIDE_IMAGE_REGISTRY: &str = "nvcr.io/0837451325059433/carbide-dev";

/// HBN service Definitions
pub const DOCA_HBN_SERVICE_HELM_NAME: &str = "doca-hbn";
pub const DOCA_HBN_SERVICE_HELM_VERSION: &str = "1.0.5";
pub const DOCA_HBN_SERVICE_IMAGE_NAME: &str = "doca_hbn";
pub const DOCA_HBN_SERVICE_IMAGE_TAG: &str = "3.2.1-doca3.2.1";
pub const DOCA_HBN_SERVICE_NETWORK: &str = "mybrhbn";

/// DHCP Service Definitions
pub const DHCP_SERVER_SERVICE_HELM_NAME: &str = "carbide-dhcp-server";
pub const DHCP_SERVER_SERVICE_NAD_NAME: &str = "mybrsfc-dhcp";
pub const DHCP_SERVER_SERVICE_MTU: i64 = 1500;
pub const DHCP_SERVER_SERVICE_IMAGE_NAME: &str = "forge-dhcp-server";

/// DTS service definitions
pub const DTS_SERVICE_NAME: &str = "dts";
pub const DTS_SERVICE_HELM_NAME: &str = "doca-telemetry";
pub const DTS_SERVICE_HELM_VERSION: &str = "1.22.1";

// DPU Agent Service Definitions
pub const DPU_AGENT_SERVICE_NAME: &str = "carbide-dpu-agent";
pub const DPU_AGENT_SERVICE_HELM_NAME: &str = "carbide-dpu-agent";
pub const DPU_AGENT_SERVICE_IMAGE_NAME: &str = "forge-dpu-agent";

/// FMDS Agent Service Definitions
pub const FMDS_SERVICE_HELM_NAME: &str = "carbide-fmds";
pub const FMDS_SERVICE_IMAGE_NAME: &str = "carbide-fmds";
pub const FMDS_SERVICE_NAD_NAME: &str = "mybrsfc-fmds";
pub const FMDS_SERVICE_MTU: i64 = 1500;

/// Compile-time helm version (set by CI via VERSION env var). Empty on PR/fork builds.
pub(crate) const COMPILE_TIME_HELM_VERSION: &str = match option_env!("CARBIDE_BUILD_HELM_VERSION") {
    Some(v) => v,
    None => "",
};

/// Compile-time image tag (set by CI via VERSION env var). Empty on PR/fork builds.
pub(crate) const COMPILE_TIME_IMAGE_TAG: &str = match option_env!("CARBIDE_BUILD_GIT_TAG") {
    Some(v) => v,
    None => "",
};

fn doca_hbn_service_interfaces() -> Vec<ServiceInterface> {
    dpu_service_interfaces(DOCA_HBN_SERVICE_NAME, DOCA_HBN_SERVICE_NETWORK)
}
fn dhcp_server_service_interfaces() -> Vec<ServiceInterface> {
    dpu_service_interfaces(DHCP_SERVER_SERVICE_NAME, DHCP_SERVER_SERVICE_NAD_NAME)
}
fn fmds_service_interfaces() -> Vec<ServiceInterface> {
    dpu_service_interfaces(FMDS_SERVICE_NAME, FMDS_SERVICE_NAD_NAME)
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
        "    system:\n",
        "      api:\n",
        "        listening-address:\n",
        "          0.0.0.0: {}\n",
        "    interface:\n",
    ));

    for interface in interfaces {
        let _ = writeln!(startup_yaml, "      {}:", interface.name);
        startup_yaml.push_str("        type: swp\n");
    }

    startup_yaml
}

pub(crate) fn default_dts_service() -> DpfServiceConfig {
    DpfServiceConfig {
        name: DTS_SERVICE_NAME.to_string(),
        helm_repo_url: DEFAULT_DOCA_HELM_REGISTRY.to_string(),
        helm_chart: DTS_SERVICE_HELM_NAME.to_string(),
        helm_version: DTS_SERVICE_HELM_VERSION.to_string(),
        docker_repo_url: String::new(),
        docker_image_tag: String::new(),
    }
}

pub(crate) fn default_doca_hbn_service() -> DpfServiceConfig {
    DpfServiceConfig {
        name: DOCA_HBN_SERVICE_NAME.to_string(),
        helm_repo_url: DEFAULT_DOCA_HELM_REGISTRY.to_string(),
        helm_chart: DOCA_HBN_SERVICE_HELM_NAME.to_string(),
        helm_version: DOCA_HBN_SERVICE_HELM_VERSION.to_string(),
        docker_repo_url: format!("{DEFAULT_DOCA_IMAGE_REGISTRY}/{DOCA_HBN_SERVICE_IMAGE_NAME}"),
        docker_image_tag: DOCA_HBN_SERVICE_IMAGE_TAG.to_string(),
    }
}

pub(crate) fn default_dpu_agent_service() -> DpfServiceConfig {
    DpfServiceConfig {
        name: DPU_AGENT_SERVICE_NAME.to_string(),
        helm_repo_url: DEFAULT_CARBIDE_HELM_REGISTRY.to_string(),
        helm_chart: DPU_AGENT_SERVICE_HELM_NAME.to_string(),
        helm_version: COMPILE_TIME_HELM_VERSION.to_string(),
        docker_repo_url: format!("{DEFAULT_CARBIDE_IMAGE_REGISTRY}/{DPU_AGENT_SERVICE_IMAGE_NAME}"),
        docker_image_tag: COMPILE_TIME_IMAGE_TAG.to_string(),
    }
}

pub(crate) fn default_dhcp_server_service() -> DpfServiceConfig {
    DpfServiceConfig {
        name: DHCP_SERVER_SERVICE_NAME.to_string(),
        helm_repo_url: DEFAULT_CARBIDE_HELM_REGISTRY.to_string(),
        helm_chart: DHCP_SERVER_SERVICE_HELM_NAME.to_string(),
        helm_version: COMPILE_TIME_HELM_VERSION.to_string(),
        docker_repo_url: format!(
            "{DEFAULT_CARBIDE_IMAGE_REGISTRY}/{DHCP_SERVER_SERVICE_IMAGE_NAME}"
        ),
        docker_image_tag: COMPILE_TIME_IMAGE_TAG.to_string(),
    }
}

pub(crate) fn default_fmds_service() -> DpfServiceConfig {
    DpfServiceConfig {
        name: FMDS_SERVICE_NAME.to_string(),
        helm_repo_url: DEFAULT_CARBIDE_HELM_REGISTRY.to_string(),
        helm_chart: FMDS_SERVICE_HELM_NAME.to_string(),
        helm_version: COMPILE_TIME_HELM_VERSION.to_string(),
        docker_repo_url: format!("{DEFAULT_CARBIDE_IMAGE_REGISTRY}/{FMDS_SERVICE_IMAGE_NAME}"),
        docker_image_tag: COMPILE_TIME_IMAGE_TAG.to_string(),
    }
}

pub(crate) fn default_otel_service() -> DpfServiceConfig {
    DpfServiceConfig::default()
}

/// DOCA HBN service definition.
pub fn doca_hbn_service(cfg: &DpfServiceConfig) -> ServiceDefinition {
    let interfaces = doca_hbn_service_interfaces();
    ServiceDefinition {
        helm_values: Some(serde_json::json!({
            "image": {
                "repository": cfg.docker_repo_url,
                "tag": cfg.docker_image_tag,
            },
            "resources": {
                "memory": "6Gi",
                "nvidia.com/bf_sf": interfaces.len(),
            },
            "configuration": {
                "user": {
                    "create": true,
                    "username": "carbide",
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
            &cfg.name,
            &cfg.helm_repo_url,
            &cfg.helm_chart,
            &cfg.helm_version,
        )
    }
}

/// DTS (DOCA Telemetry Service) service definition.
pub fn dts_service(cfg: &DpfServiceConfig) -> ServiceDefinition {
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
        ..ServiceDefinition::new(
            &cfg.name,
            &cfg.helm_repo_url,
            &cfg.helm_chart,
            &cfg.helm_version,
        )
    }
}

/// Forge DPU Agent service definition.
pub fn dpu_agent_service(cfg: &DpfServiceConfig) -> ServiceDefinition {
    ServiceDefinition {
        helm_values: Some(serde_json::json!({
            "image": {
                "repository": cfg.docker_repo_url,
                "tag": cfg.docker_image_tag,
            },
            "hbn": {
                "nvue_https_address": "nvue",
                "nvue_credentials_secret_name": "hbn-user-password",
                "nvue_password_key": "password",
            },
            "imagePullSecrets": [
                {
                    "name": "dpf-pull-secret"
                }
            ]
        })),

        service_daemon_set_annotations: Some(BTreeMap::new()),

        config_values: Some(serde_json::json!({
            "dhcp_server": {
                "service_name": "{{ (index .Services \"carbide-dhcp-server\").Name }}",
                "interface_prepend": "d_"
            },
            "fmds": {
                "service_name": "{{ (index .Services \"carbide-fmds\").Name }}"
            },
            "hbn": {
                "nvue_https_address": "{{ (index .Services \"doca-hbn\").Name }}"
            }
        })),

        ..ServiceDefinition::new(
            &cfg.name,
            &cfg.helm_repo_url,
            &cfg.helm_chart,
            &cfg.helm_version,
        )
    }
}

/// Forge DHCP Server service definition.
pub fn dhcp_server_service(cfg: &DpfServiceConfig) -> ServiceDefinition {
    ServiceDefinition {
        helm_values: Some(serde_json::json!({
            "image": {
                "repository": cfg.docker_repo_url,
                "tag": cfg.docker_image_tag,
            },
            "imagePullSecrets": [
                {
                    "name": "dpf-pull-secret"
                }
            ]
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
            &cfg.name,
            &cfg.helm_repo_url,
            &cfg.helm_chart,
            &cfg.helm_version,
        )
    }
}

/// Forge FMDS service definition.
pub fn fmds_service(cfg: &DpfServiceConfig) -> ServiceDefinition {
    ServiceDefinition {
        helm_values: Some(serde_json::json!({
            "image": {
                "repository": cfg.docker_repo_url,
                "tag": cfg.docker_image_tag,
            },
            "imagePullSecrets": [
                {
                    "name": "dpf-pull-secret"
                }
            ]
        })),

        interfaces: fmds_service_interfaces(),

        service_daemon_set_annotations: Some(BTreeMap::new()),

        service_nad: Some(ServiceNAD {
            name: FMDS_SERVICE_NAD_NAME.to_string(),
            bridge: Some("br-sfc".to_string()),
            resource_type: ServiceNADResourceType::Sf,
            ipam: Some(false),
            mtu: Some(FMDS_SERVICE_MTU),
        }),

        ..ServiceDefinition::new(
            &cfg.name,
            &cfg.helm_repo_url,
            &cfg.helm_chart,
            &cfg.helm_version,
        )
    }
}

/// OTel service definition.
#[allow(dead_code)]
pub fn otel_service(cfg: &DpfServiceConfig) -> ServiceDefinition {
    ServiceDefinition {
        helm_values: Some(serde_json::json!({
            "image": {
                "repository": cfg.docker_repo_url,
                "tag": cfg.docker_image_tag,
            },
            "imagePullSecrets": [
                {
                    "name": "dpf-pull-secret"
                }
            ]
        })),
        config_ports: Some(vec![ServiceConfigPort {
            name: "prometheus".to_string(),
            port: 9999,
            protocol: ServiceConfigPortProtocol::Tcp,
            node_port: None,
        }]),
        config_ports_service_type: Some(ConfigPortsServiceType::None),
        ..ServiceDefinition::new(
            &cfg.name,
            &cfg.helm_repo_url,
            &cfg.helm_chart,
            &cfg.helm_version,
        )
    }
}

#[cfg(test)]
mod tests {
    use carbide_dpf::build_service_interface;
    use carbide_dpf::sdk::build_dpu_interfaces_vec;
    use carbide_dpf::types::DpuServiceInterfaceTemplateType;

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
}
