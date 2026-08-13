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
use carbide_dpf::types::{
    DHCP_SERVER_SERVICE_NAME, DOCA_HBN_SERVICE_NAME, DOCA_WEAVE_DHCP_AGENT_SERVICE_NAME,
    DOCA_WEAVE_FLOW_CONTROLLER_SERVICE_NAME, DOCA_XPLANE_SERVICE_NAME, DPU_AGENT_SERVICE_NAME,
    DTS_SERVICE_NAME, FMDS_SERVICE_NAME, OTEL_COLLECTOR_SERVICE_NAME,
};
use carbide_dpf::{
    IntOrString, ServiceDefinition, ServiceInterface, ServiceNAD, ServiceNADResourceType,
};

use crate::cfg::file::{
    DpfBootstrapCaObjectKind, DpfDpuAgentBootstrapCa, DpfExtraService,
    DpfResolvedMandatoryServicesConfig, DpfServiceConfig,
};

/// Default DOCA helm registry (DPUServiceTemplate source.repoURL).
pub const DEFAULT_DOCA_HELM_REGISTRY: &str = "https://helm.ngc.nvidia.com/nvidia/doca";

pub const DEFAULT_CARBIDE_HELM_REGISTRY: &str =
    "https://helm.ngc.nvidia.com/0837451325059433/carbide-dev";

/// Default DOCA container image registry prefix.
pub const DEFAULT_DOCA_IMAGE_REGISTRY: &str = "nvcr.io/nvidia/doca";

/// Default Carbide container image registry prefix.
pub const DEFAULT_CARBIDE_IMAGE_REGISTRY: &str = "nvcr.io/0837451325059433/carbide-dev";

/// Astra Service Helm and Image Registries
pub const DOCA_WEAVE_CHART_REPO_URL: &str = "oci://harbor.mellanox.com/cloud-orchestration-dev/dpf";
pub const DOCA_WEAVE_IMAGE_REGISTRY: &str = "nvcr.io/nvstaging/doca";

/// HBN service Definitions
pub const DOCA_HBN_SERVICE_HELM_NAME: &str = "doca-hbn";
pub const DOCA_HBN_SERVICE_HELM_VERSION: &str = "3.4.0";
pub const DOCA_HBN_SERVICE_IMAGE_NAME: &str = "doca_hbn";
pub const DOCA_HBN_SERVICE_IMAGE_TAG: &str = "3.4.0-doca3.4.0";
pub const DOCA_HBN_SERVICE_NETWORK: &str = "mybrhbn";

/// DHCP Service Definitions
pub const DHCP_SERVER_SERVICE_HELM_NAME: &str = "nico-dhcp-server";
pub const DHCP_SERVER_SERVICE_NAD_NAME: &str = "mybrsfc-dhcp";
pub const DHCP_SERVER_SERVICE_MTU: i64 = 1500;
pub const DHCP_SERVER_SERVICE_IMAGE_NAME: &str = "forge-dhcp-server";

/// DTS service definitions
/// (DTS_SERVICE_NAME lives in carbide_dpf::types so the DPF SDK can wire its dependencies.)
pub const DTS_SERVICE_HELM_NAME: &str = "doca-telemetry";
pub const DTS_SERVICE_HELM_VERSION: &str = "1.25.5";

// DPU Agent Service Definitions
pub const DPU_AGENT_SERVICE_HELM_NAME: &str = "nico-dpu-agent";
pub const DPU_AGENT_SERVICE_IMAGE_NAME: &str = "forge-dpu-agent";

/// FMDS Agent Service Definitions
pub const FMDS_SERVICE_HELM_NAME: &str = "nico-fmds";
pub const FMDS_SERVICE_IMAGE_NAME: &str = "carbide-fmds";
pub const FMDS_SERVICE_NAD_NAME: &str = "mybrsfc-fmds";
pub const FMDS_SERVICE_MTU: i64 = 1500;

/// OTel Collector Service Definitions
pub const OTEL_COLLECTOR_SERVICE_HELM_NAME: &str = "nico-otelcol";
pub const OTEL_COLLECTOR_SERVICE_IMAGE_NAME: &str = "otelcol-contrib";

/// Weave DHCP agent service definitions.
pub const DOCA_WEAVE_DHCP_AGENT_SERVICE_HELM_NAME: &str = "dpf-weave";
pub const DOCA_WEAVE_DHCP_AGENT_SERVICE_HELM_VERSION: &str = "v26.5.0-1f8f4e1e";
pub const DOCA_WEAVE_DHCP_AGENT_SERVICE_IMAGE_NAME: &str = "weave-system";
pub const DOCA_WEAVE_DHCP_AGENT_SERVICE_IMAGE_TAG: &str = "v26.5.0-f2c9f7c4-nightly";

/// Weave flow (ovs) controller service definitions.
pub const DOCA_WEAVE_FLOW_CONTROLLER_SERVICE_HELM_NAME: &str = "dpf-weave";
pub const DOCA_WEAVE_FLOW_CONTROLLER_SERVICE_HELM_VERSION: &str = "v26.5.0-1f8f4e1e";
pub const DOCA_WEAVE_FLOW_CONTROLLER_SERVICE_IMAGE_NAME: &str = "weave-system";
pub const DOCA_WEAVE_FLOW_CONTROLLER_SERVICE_IMAGE_TAG: &str = "v26.5.0-f2c9f7c4-nightly";

/// Xplane service definitions.
pub const DOCA_XPLANE_SERVICE_HELM_NAME: &str = "doca-xplane";
pub const DOCA_XPLANE_SERVICE_HELM_VERSION: &str = "1.0";
pub const DOCA_XPLANE_SERVICE_IMAGE_NAME: &str = "doca_xplane";
pub const DOCA_XPLANE_SERVICE_IMAGE_TAG: &str = "3.2.1-doca3.2.1";

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
        docker_image_pull_secret: None,
        extra_helm_values: None,
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
        docker_image_pull_secret: None,
        extra_helm_values: None,
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
        docker_image_pull_secret: None,
        extra_helm_values: None,
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
        docker_image_pull_secret: None,
        extra_helm_values: None,
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
        docker_image_pull_secret: None,
        extra_helm_values: None,
    }
}

pub(crate) fn default_otelcol_service() -> DpfServiceConfig {
    DpfServiceConfig {
        name: OTEL_COLLECTOR_SERVICE_NAME.to_string(),
        helm_repo_url: DEFAULT_CARBIDE_HELM_REGISTRY.to_string(),
        helm_chart: OTEL_COLLECTOR_SERVICE_HELM_NAME.to_string(),
        helm_version: COMPILE_TIME_HELM_VERSION.to_string(),
        docker_repo_url: format!(
            "{DEFAULT_CARBIDE_IMAGE_REGISTRY}/{OTEL_COLLECTOR_SERVICE_IMAGE_NAME}"
        ),
        docker_image_tag: COMPILE_TIME_IMAGE_TAG.to_string(),
        docker_image_pull_secret: None,
        extra_helm_values: None,
    }
}

pub(crate) fn default_doca_weave_dhcp_agent_service() -> DpfServiceConfig {
    DpfServiceConfig {
        name: DOCA_WEAVE_DHCP_AGENT_SERVICE_NAME.to_string(),
        helm_repo_url: DOCA_WEAVE_CHART_REPO_URL.to_string(),
        helm_chart: DOCA_WEAVE_DHCP_AGENT_SERVICE_HELM_NAME.to_string(),
        helm_version: DOCA_WEAVE_DHCP_AGENT_SERVICE_HELM_VERSION.to_string(),
        docker_repo_url: format!(
            "{DOCA_WEAVE_IMAGE_REGISTRY}/{DOCA_WEAVE_DHCP_AGENT_SERVICE_IMAGE_NAME}"
        ),
        docker_image_tag: DOCA_WEAVE_DHCP_AGENT_SERVICE_IMAGE_TAG.to_string(),
        docker_image_pull_secret: None,
        extra_helm_values: None,
    }
}

pub(crate) fn default_doca_weave_flow_controller_service() -> DpfServiceConfig {
    DpfServiceConfig {
        name: DOCA_WEAVE_FLOW_CONTROLLER_SERVICE_NAME.to_string(),
        helm_repo_url: DOCA_WEAVE_CHART_REPO_URL.to_string(),
        helm_chart: DOCA_WEAVE_FLOW_CONTROLLER_SERVICE_HELM_NAME.to_string(),
        helm_version: DOCA_WEAVE_FLOW_CONTROLLER_SERVICE_HELM_VERSION.to_string(),
        docker_repo_url: format!(
            "{DOCA_WEAVE_IMAGE_REGISTRY}/{DOCA_WEAVE_FLOW_CONTROLLER_SERVICE_IMAGE_NAME}"
        ),
        docker_image_tag: DOCA_WEAVE_FLOW_CONTROLLER_SERVICE_IMAGE_TAG.to_string(),
        docker_image_pull_secret: None,
        extra_helm_values: None,
    }
}

pub(crate) fn default_doca_xplane_service() -> DpfServiceConfig {
    DpfServiceConfig {
        name: DOCA_XPLANE_SERVICE_NAME.to_string(),
        helm_repo_url: DEFAULT_DOCA_HELM_REGISTRY.to_string(),
        helm_chart: DOCA_XPLANE_SERVICE_HELM_NAME.to_string(),
        helm_version: DOCA_XPLANE_SERVICE_HELM_VERSION.to_string(),
        docker_repo_url: format!("{DEFAULT_DOCA_IMAGE_REGISTRY}/{DOCA_XPLANE_SERVICE_IMAGE_NAME}"),
        docker_image_tag: DOCA_XPLANE_SERVICE_IMAGE_TAG.to_string(),
        docker_image_pull_secret: None,
        extra_helm_values: None,
    }
}

/// Adds an `imagePullSecrets` block to a service's Helm values when the service has
/// a configured pull secret, omitting it entirely otherwise. Mandatory services carry
/// no pull secret by default (public-registry pulls); one is emitted only when set via
/// the service's per-service config or the top-level `docker_image_pull_secret`
/// override, and a `None` renders no `imagePullSecrets` rather than an invalid null.
fn apply_image_pull_secrets(helm_values: &mut serde_json::Value, cfg: &DpfServiceConfig) {
    let Some(secret) = cfg.docker_image_pull_secret.as_ref() else {
        return;
    };
    helm_values
        .as_object_mut()
        .expect("service Helm values must be a JSON object")
        .insert(
            "imagePullSecrets".to_string(),
            serde_json::json!([{ "name": secret }]),
        );
}

fn merge_helm_values(
    base: &mut serde_json::Map<String, serde_json::Value>,
    overlay: &serde_json::Map<String, serde_json::Value>,
) {
    for (key, value) in overlay {
        match (base.get_mut(key), value) {
            (Some(serde_json::Value::Object(base)), serde_json::Value::Object(overlay)) => {
                merge_helm_values(base, overlay);
            }
            _ => {
                base.insert(key.clone(), value.clone());
            }
        }
    }
}

fn apply_helm_values(helm_values: &mut serde_json::Value, cfg: &DpfServiceConfig) {
    apply_image_pull_secrets(helm_values, cfg);
    if let Some(overlay) = &cfg.extra_helm_values {
        merge_helm_values(
            helm_values
                .as_object_mut()
                .expect("generated Helm values must be an object"),
            overlay,
        );
    }
}

/// DOCA HBN service definition.
pub fn doca_hbn_service(cfg: &DpfServiceConfig) -> ServiceDefinition {
    let interfaces = doca_hbn_service_interfaces();
    let mut helm_values = serde_json::json!({
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
        }
    });
    apply_helm_values(&mut helm_values, cfg);
    ServiceDefinition {
        helm_values: Some(helm_values),

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
    let mut helm_values = serde_json::json!({
        "exposedPorts": { "ports": { "httpserverport": true } }
    });
    apply_helm_values(&mut helm_values, cfg);
    ServiceDefinition {
        helm_values: Some(helm_values),
        config_ports: None,
        config_ports_service_type: None,
        ..ServiceDefinition::new(
            &cfg.name,
            &cfg.helm_repo_url,
            &cfg.helm_chart,
            &cfg.helm_version,
        )
    }
}

fn dpu_agent_helm_values(
    cfg: &DpfServiceConfig,
    bootstrap_ca: &DpfDpuAgentBootstrapCa,
) -> serde_json::Value {
    let mut values = serde_json::json!({
        "image": {
            "repository": cfg.docker_repo_url,
            "tag": cfg.docker_image_tag,
        },
        "hbn": {
            "nvue_https_address": "nvue",
            "nvue_credentials_secret_name": "hbn-user-password",
            "nvue_password_key": "password",
        }
    });
    let bootstrap_ca_values = match bootstrap_ca {
        DpfDpuAgentBootstrapCa::LegacyDownload { url: None } => None,
        DpfDpuAgentBootstrapCa::LegacyDownload { url: Some(url) } => Some(serde_json::json!({
            "source": "legacy_download",
            "url": url,
        })),
        DpfDpuAgentBootstrapCa::Mounted {
            object_kind,
            name,
            key,
        } => Some(serde_json::json!({
            "source": "mounted",
            "object": {
                "kind": match object_kind {
                    DpfBootstrapCaObjectKind::Secret => "Secret",
                    DpfBootstrapCaObjectKind::ConfigMap => "ConfigMap",
                },
                "name": name,
                "key": key,
            },
        })),
    };

    if let Some(bootstrap_ca_values) = bootstrap_ca_values {
        values
            .as_object_mut()
            .expect("DPU agent Helm values are an object")
            .insert("bootstrapCa".to_string(), bootstrap_ca_values);
    }
    apply_helm_values(&mut values, cfg);

    values
}

/// Forge DPU Agent service definition.
pub fn dpu_agent_service(
    cfg: &DpfServiceConfig,
    bootstrap_ca: &DpfDpuAgentBootstrapCa,
) -> ServiceDefinition {
    ServiceDefinition {
        helm_values: Some(dpu_agent_helm_values(cfg, bootstrap_ca)),

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
    let mut helm_values = serde_json::json!({
        "image": {
            "repository": cfg.docker_repo_url,
            "tag": cfg.docker_image_tag,
        }
    });
    apply_helm_values(&mut helm_values, cfg);
    ServiceDefinition {
        helm_values: Some(helm_values),

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
    let mut helm_values = serde_json::json!({
        "image": {
            "repository": cfg.docker_repo_url,
            "tag": cfg.docker_image_tag,
        }
    });
    apply_helm_values(&mut helm_values, cfg);
    ServiceDefinition {
        helm_values: Some(helm_values),

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
pub fn otelcol_service(cfg: &DpfServiceConfig) -> ServiceDefinition {
    let mut helm_values = serde_json::json!({
        "image": {
            "repository": cfg.docker_repo_url,
            "tag": cfg.docker_image_tag,
        }
    });
    apply_helm_values(&mut helm_values, cfg);
    ServiceDefinition {
        helm_values: Some(helm_values),
        service_daemon_set_annotations: Some(BTreeMap::new()),
        config_values: Some(serde_json::json!({
            "nico_dpu_agent": "{{ (index .Services \"carbide-dpu-agent\").Name }}",
            "nico_fmds": "{{ (index .Services \"carbide-fmds\").Name }}",
            "nico_dts": "{{ (index .Services \"dts\").Name }}"
        })),

        ..ServiceDefinition::new(
            &cfg.name,
            &cfg.helm_repo_url,
            &cfg.helm_chart,
            &cfg.helm_version,
        )
    }
}

pub fn doca_weave_dhcp_agent_service(cfg: &DpfServiceConfig) -> ServiceDefinition {
    let mut helm_values = serde_json::json!({
        "weaveDHCPAgent": {
            "containers": {
                "weaveDHCPAgent": {
                    "image": {
                        "repository": cfg.docker_repo_url,
                        "tag": cfg.docker_image_tag,
                    }
                }
            }
        }
    });
    apply_helm_values(&mut helm_values, cfg);
    ServiceDefinition {
        helm_values: Some(helm_values),
        config_values: Some(serde_json::json!({
            "weaveDHCPAgent": {
                "enabled": true,
                "dhcpNetworks": {
                    "createNADs": true,
                    "networks": weave_dhcp_agent_networks(),
                }
            }
        })),
        service_daemon_set_resources: Some(BTreeMap::from([(
            "nvidia.com/bf_sf".to_string(),
            IntOrString::Int(WEAVE_DHCP_AGENT_NETWORKS.len() as i32),
        )])),
        ..ServiceDefinition::new(
            &cfg.name,
            &cfg.helm_repo_url,
            &cfg.helm_chart,
            &cfg.helm_version,
        )
    }
}

const WEAVE_DHCP_AGENT_NETWORKS: &[&str] = &[
    "r0swpln0", "r1swpln0", "r0swpln1", "r1swpln1", "r2swpln0", "r3swpln0", "r2swpln1", "r3swpln1",
];

fn weave_dhcp_agent_networks() -> Vec<serde_json::Value> {
    WEAVE_DHCP_AGENT_NETWORKS
        .iter()
        .map(|port| {
            serde_json::json!({
                "name": format!("dhcp-{port}"),
                "bridge": format!("br-dhcp-{port}"),
                "resourceName": "nvidia.com/bf_sf",
                "interfaceName": port,
            })
        })
        .collect()
}

/// PCI address of each BF4 Astra uplink paired with the switch port it carries.
/// The underlay, overlay, and bridge names are all derived from the port name.
const WEAVE_FLOW_CONTROLLER_UNDERLAY_PORTS: &[(&str, &str)] = &[
    ("0005:06:00.0", "r0swpln0"),
    ("0005:03:00.0", "r1swpln0"),
    ("0000:06:00.0", "r2swpln0"),
    ("0000:03:00.0", "r3swpln0"),
    ("0004:03:00.0", "r0swpln1"),
    ("0004:06:00.0", "r1swpln1"),
    ("0001:03:00.0", "r2swpln1"),
    ("0001:06:00.0", "r3swpln1"),
];

fn weave_flow_controller_underlay_interfaces() -> Vec<serde_json::Value> {
    WEAVE_FLOW_CONTROLLER_UNDERLAY_PORTS
        .iter()
        .map(|(pci_address, port)| {
            serde_json::json!({
                "pciAddress": pci_address,
                "underlayInterface": format!("brcx-{port}"),
                "overlayDHCPInterface": port,
                "dhcpBridgeName": format!("br-dhcp-{port}"),
                "dropBridgeName": format!("br-drop-{port}"),
            })
        })
        .collect()
}

pub fn doca_weave_flow_controller_service(cfg: &DpfServiceConfig) -> ServiceDefinition {
    let mut helm_values = serde_json::json!({
        "weaveFlowController": {
            "containers": {
                "weaveFlowController": {
                    "image": {
                        "repository": cfg.docker_repo_url,
                        "tag": cfg.docker_image_tag,
                    }
                }
            }
        }
    });
    apply_helm_values(&mut helm_values, cfg);
    ServiceDefinition {
        helm_values: Some(helm_values),
        config_values: Some(serde_json::json!({
            "weaveFlowController": {
                "enabled": true,
                "underlayConfigMapData": {
                    "nicIDType": "mac",
                    "interfaces": weave_flow_controller_underlay_interfaces(),
                }
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

pub fn doca_xplane_service(cfg: &DpfServiceConfig) -> ServiceDefinition {
    let mut helm_values = serde_json::json!({
        "image": {
            "repository": cfg.docker_repo_url,
            "tag": cfg.docker_image_tag,
        }
    });
    apply_helm_values(&mut helm_values, cfg);
    ServiceDefinition {
        helm_values: Some(helm_values),
        ..ServiceDefinition::new(
            &cfg.name,
            &cfg.helm_repo_url,
            &cfg.helm_chart,
            &cfg.helm_version,
        )
    }
}

/// Build the full list of resolved mandatory DPU services.
pub fn mandatory_services(
    resolved: &DpfResolvedMandatoryServicesConfig,
    bootstrap_ca: &DpfDpuAgentBootstrapCa,
) -> Vec<ServiceDefinition> {
    let mut service_vec = vec![
        dts_service(&resolved.base.dts),
        doca_hbn_service(&resolved.base.doca_hbn),
        dhcp_server_service(&resolved.base.dhcp_server),
        dpu_agent_service(&resolved.base.dpu_agent, bootstrap_ca),
        fmds_service(&resolved.base.fmds),
        otelcol_service(&resolved.base.otel),
    ];

    for (service, cfg) in &resolved.extra {
        match service {
            DpfExtraService::DocaWeaveDhcpAgent => {
                service_vec.push(doca_weave_dhcp_agent_service(cfg))
            }
            DpfExtraService::DocaWeaveFlowController => {
                service_vec.push(doca_weave_flow_controller_service(cfg))
            }
            DpfExtraService::DocaXplane => service_vec.push(doca_xplane_service(cfg)),
        }
    }

    service_vec
}

#[cfg(test)]
mod tests {
    use carbide_dpf::sdk::build_dpu_interfaces_vec;
    use carbide_dpf::types::DpuServiceInterfaceTemplateType;
    use carbide_dpf::{
        build_service_configuration, build_service_interface, build_service_template,
    };
    use carbide_test_support::value_scenarios;
    use url::Url;

    use super::*;

    const TEST_NS: &str = "dpf-operator-system";

    #[test]
    fn helm_value_tables_merge_recursively() {
        let mut values = serde_json::json!({
            "image": {
                "repository": "generated",
                "tag": "generated",
            }
        });

        let overlay = serde_json::json!({
            "image": { "tag": "configured" },
            "fmds": { "sign_proxy_url": "http://dsx-imds" },
        });
        merge_helm_values(
            values.as_object_mut().unwrap(),
            overlay.as_object().unwrap(),
        );

        assert_eq!(
            values,
            serde_json::json!({
                "image": {
                    "repository": "generated",
                    "tag": "configured",
                },
                "fmds": { "sign_proxy_url": "http://dsx-imds" },
            })
        );
    }

    #[test]
    fn helm_value_scalars_and_arrays_replace_generated_values() {
        let mut values = serde_json::json!({
            "enabled": false,
            "tolerations": [{ "key": "generated" }],
        });

        let overlay = serde_json::json!({
            "enabled": true,
            "tolerations": [{ "key": "configured" }],
        });
        merge_helm_values(
            values.as_object_mut().unwrap(),
            overlay.as_object().unwrap(),
        );

        assert_eq!(
            values,
            serde_json::json!({
                "enabled": true,
                "tolerations": [{ "key": "configured" }],
            })
        );
    }

    #[test]
    fn dpu_agent_bootstrap_ca_helm_values_follow_site_policy() {
        value_scenarios!(
            run = |policy| {
                dpu_agent_helm_values(&default_dpu_agent_service(), &policy)
                    .get("bootstrapCa")
                    .cloned()
            };
            "legacy download" {
                DpfDpuAgentBootstrapCa::default() => None,
                DpfDpuAgentBootstrapCa::LegacyDownload {
                    url: Some(Url::parse("https://pxe.example.test/site-ca.pem").unwrap()),
                } => Some(serde_json::json!({
                    "source": "legacy_download",
                    "url": "https://pxe.example.test/site-ca.pem",
                })),
            }

            "mounted Kubernetes object" {
                DpfDpuAgentBootstrapCa::Mounted {
                    object_kind: DpfBootstrapCaObjectKind::Secret,
                    name: "nico-bootstrap-ca-v1".to_string(),
                    key: "root.pem".to_string(),
                } => Some(serde_json::json!({
                    "source": "mounted",
                    "object": {
                        "kind": "Secret",
                        "name": "nico-bootstrap-ca-v1",
                        "key": "root.pem",
                    },
                })),
                DpfDpuAgentBootstrapCa::Mounted {
                    object_kind: DpfBootstrapCaObjectKind::ConfigMap,
                    name: "nico-bootstrap-ca-v2".to_string(),
                    key: "ca.crt".to_string(),
                } => Some(serde_json::json!({
                    "source": "mounted",
                    "object": {
                        "kind": "ConfigMap",
                        "name": "nico-bootstrap-ca-v2",
                        "key": "ca.crt",
                    },
                })),
            }
        );
    }

    // ---- imagePullSecrets ----

    #[test]
    fn hbn_and_dts_omit_image_pull_secrets_by_default() {
        // HBN and DTS pull from the public DOCA registry: no imagePullSecrets unless configured.
        let hbn = doca_hbn_service(&default_doca_hbn_service());
        assert!(
            hbn.helm_values.unwrap().get("imagePullSecrets").is_none(),
            "HBN must not emit imagePullSecrets without a configured secret"
        );

        let dts = dts_service(&default_dts_service());
        assert!(
            dts.helm_values.unwrap().get("imagePullSecrets").is_none(),
            "DTS must not emit imagePullSecrets without a configured secret"
        );
    }

    #[test]
    fn hbn_and_dts_emit_image_pull_secrets_when_configured() {
        let expected = serde_json::json!([{ "name": "private-pull-secret" }]);

        let mut hbn_cfg = default_doca_hbn_service();
        hbn_cfg.docker_image_pull_secret = Some("private-pull-secret".to_string());
        assert_eq!(
            doca_hbn_service(&hbn_cfg).helm_values.unwrap()["imagePullSecrets"],
            expected
        );

        let mut dts_cfg = default_dts_service();
        dts_cfg.docker_image_pull_secret = Some("private-pull-secret".to_string());
        assert_eq!(
            dts_service(&dts_cfg).helm_values.unwrap()["imagePullSecrets"],
            expected
        );
    }

    #[test]
    fn deployment_specific_services_emit_image_pull_secrets_when_configured() {
        value_scenarios!(
            run = |service| {
                let (mut config, build): (
                    DpfServiceConfig,
                    fn(&DpfServiceConfig) -> ServiceDefinition,
                ) = match service {
                    DpfExtraService::DocaWeaveDhcpAgent => (
                        default_doca_weave_dhcp_agent_service(),
                        doca_weave_dhcp_agent_service,
                    ),
                    DpfExtraService::DocaWeaveFlowController => (
                        default_doca_weave_flow_controller_service(),
                        doca_weave_flow_controller_service,
                    ),
                    DpfExtraService::DocaXplane => (
                        default_doca_xplane_service(),
                        doca_xplane_service,
                    ),
                };
                let rendered_secret = |definition: ServiceDefinition| {
                    definition
                        .helm_values
                        .and_then(|values| {
                            values["imagePullSecrets"][0]["name"]
                                .as_str()
                                .map(str::to_string)
                        })
                };
                let default_secret = rendered_secret(build(&config));
                config.docker_image_pull_secret = Some("private-doca-secret".to_string());
                let configured_secret = rendered_secret(build(&config));
                (default_secret, configured_secret)
            };
            "Weave DHCP agent" {
                DpfExtraService::DocaWeaveDhcpAgent
                    => (None, Some("private-doca-secret".to_string())),
            }

            "Weave flow controller" {
                DpfExtraService::DocaWeaveFlowController
                    => (None, Some("private-doca-secret".to_string())),
            }

            "Xplane" {
                DpfExtraService::DocaXplane
                    => (None, Some("private-doca-secret".to_string())),
            }
        );
    }

    #[test]
    fn carbide_service_image_pull_secrets_are_conditional() {
        // By default a carbide service carries no pull secret and omits the block,
        // rather than rendering the invalid imagePullSecrets: [{ name: null }].
        let dpu_agent = dpu_agent_service(
            &default_dpu_agent_service(),
            &DpfDpuAgentBootstrapCa::default(),
        );
        assert!(
            dpu_agent
                .helm_values
                .unwrap()
                .get("imagePullSecrets")
                .is_none(),
            "a carbide service without a pull secret must omit imagePullSecrets"
        );

        // When a pull secret is configured, the block is emitted with its name.
        let mut cfg = default_dpu_agent_service();
        cfg.docker_image_pull_secret = Some("nico-pull-secret".to_string());
        let agent = dpu_agent_service(&cfg, &DpfDpuAgentBootstrapCa::default());
        assert_eq!(
            agent.helm_values.unwrap()["imagePullSecrets"],
            serde_json::json!([{ "name": "nico-pull-secret" }])
        );
    }

    #[test]
    fn dpu_agent_template_merges_extra_helm_values() {
        let mut config = default_dpu_agent_service();
        config.extra_helm_values = serde_json::json!({
            "fmds": {
                "sign_proxy_url": "http://dsx-imds.dpf-operator-system.svc.cluster.local:8080"
            },
            "image": {
                "tag": "configured-tag"
            }
        })
        .as_object()
        .cloned();
        let service = dpu_agent_service(&config, &DpfDpuAgentBootstrapCa::default());
        let template = build_service_template(&service, TEST_NS, "");
        let values = template.spec.helm_chart.values.unwrap();

        assert_eq!(
            values["fmds"]["sign_proxy_url"],
            "http://dsx-imds.dpf-operator-system.svc.cluster.local:8080"
        );
        assert_eq!(values["image"]["repository"], config.docker_repo_url);
        assert_eq!(values["image"]["tag"], "configured-tag");
    }

    // ---- weave services ----

    #[test]
    fn weave_dhcp_agent_service_emits_networks_and_sf_resources() {
        let svc = doca_weave_dhcp_agent_service(&default_doca_weave_dhcp_agent_service());
        let helm_values = svc.helm_values.as_ref().expect("helm_values must be set");
        assert_eq!(
            helm_values["weaveDHCPAgent"]["containers"]["weaveDHCPAgent"]["image"]["repository"],
            format!("{DOCA_WEAVE_IMAGE_REGISTRY}/{DOCA_WEAVE_DHCP_AGENT_SERVICE_IMAGE_NAME}")
        );
        assert!(
            helm_values.get("image").is_none(),
            "DHCP-agent image must not use a top-level image key"
        );

        let configuration =
            build_service_configuration(&svc, TEST_NS, "bf4astra", &BTreeMap::new());
        let service_configuration = configuration
            .spec
            .service_configuration
            .expect("serviceConfiguration must be set");
        let values = service_configuration
            .helm_chart
            .expect("helmChart must be set")
            .values
            .expect("helmChart values must be set");

        assert_eq!(values["weaveDHCPAgent"]["enabled"], true);
        assert_eq!(values["weaveDHCPAgent"]["dhcpNetworks"]["createNADs"], true);
        assert_eq!(
            values["weaveDHCPAgent"]["dhcpNetworks"]["networks"],
            serde_json::Value::Array(weave_dhcp_agent_networks())
        );

        let resources = service_configuration
            .service_daemon_set
            .expect("serviceDaemonSet must be set")
            .resources
            .expect("serviceDaemonSet resources must be set");
        assert_eq!(
            resources.get("nvidia.com/bf_sf"),
            Some(&IntOrString::Int(8))
        );
    }

    #[test]
    fn weave_flow_controller_service_emits_underlay_config_values() {
        let svc = doca_weave_flow_controller_service(&default_doca_weave_flow_controller_service());
        let helm_values = svc.helm_values.expect("helm_values must be set");
        assert_eq!(
            helm_values["weaveFlowController"]["containers"]["weaveFlowController"]["image"]["repository"],
            format!("{DOCA_WEAVE_IMAGE_REGISTRY}/{DOCA_WEAVE_FLOW_CONTROLLER_SERVICE_IMAGE_NAME}")
        );
        assert!(
            helm_values.get("image").is_none(),
            "flow-controller image must not use a top-level image key"
        );

        let config = svc.config_values.expect("config_values must be set");
        assert_eq!(
            config["weaveFlowController"]["enabled"],
            serde_json::json!(true)
        );
        assert_eq!(
            config["weaveFlowController"]["underlayConfigMapData"]["nicIDType"],
            "mac"
        );

        let interfaces = config["weaveFlowController"]["underlayConfigMapData"]["interfaces"]
            .as_array()
            .expect("interfaces must be an array");
        assert_eq!(
            interfaces.len(),
            WEAVE_FLOW_CONTROLLER_UNDERLAY_PORTS.len(),
            "every Astra uplink must be present in underlayConfigMapData.interfaces"
        );
        assert_eq!(
            interfaces.as_slice(),
            weave_flow_controller_underlay_interfaces().as_slice()
        );
    }

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
