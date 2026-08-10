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

//! DPUFlavor configuration for HBN.

use kube::core::ObjectMeta;
use sha2::{Digest, Sha256};

use crate::crds::dpuflavors_generated::{
    DPUFlavor, DpuFlavorConfigFiles, DpuFlavorConfigFilesOperation, DpuFlavorContainerdConfig,
    DpuFlavorDpuMode, DpuFlavorEwNicConfigurations, DpuFlavorEwNicConfigurationsNetworkBay,
    DpuFlavorEwNicConfigurationsRawNvConfig, DpuFlavorEwNicConfigurationsSpectrumXOptimized,
    DpuFlavorEwNicConfigurationsSpectrumXOptimizedMultiplaneMode,
    DpuFlavorEwNicConfigurationsSpectrumXOptimizedOverlay, DpuFlavorGrub, DpuFlavorNvconfig,
    DpuFlavorNvconfigDevice, DpuFlavorOvs, DpuFlavorSpec, DpuFlavorSysctl,
};
use crate::types::{DpfProxyDetails, DpuDeploymentType};

pub const DEFAULT_FLAVOR_NAME: &str = "dpu-flavor";

impl DPUFlavor {
    /// Returns `"{default_flavor_name}-{hash}"` where the hash is the first 8 bytes (16 hex chars)
    /// of a stable SHA-256 digest of the spec. The name changes whenever the spec changes, which
    /// causes outdated DPUs to be reprovisioned by MachineUpdateManager.
    pub fn unique_name(&self, default_flavor_name: &str) -> Result<String, crate::error::DpfError> {
        let json = serde_json::to_string(&self.spec)?;
        let short_hash = hex::encode(&Sha256::digest(json.as_bytes())[..8]);
        Ok(format!("{default_flavor_name}-{short_hash}"))
    }
}

fn get_default_ovs_defaults() -> String {
    concat!(
        "_ovs-vsctl() {\n",
            "ovs-vsctl --timeout 15 \"$@\"\n",
        "}\n",

        "# Remove default OVS configuration on the DPU and ensure no leftovers on the OVS kernel side\n",
        "_ovs-vsctl --if-exists del-br ovsbr1\n",
        "_ovs-vsctl --if-exists del-br ovsbr2\n",
        "ovs-appctl --timeout 15 dpctl/del-dp system@ovs-system || true\n",

        "_ovs-vsctl set Open_vSwitch . other_config:doca-init=true\n",
        "_ovs-vsctl set Open_vSwitch . other_config:dpdk-max-memzones=50000\n",
        "_ovs-vsctl set Open_vSwitch . other_config:hw-offload=true\n",
        "_ovs-vsctl set Open_vSwitch . other_config:pmd-quiet-idle=true\n",
        "_ovs-vsctl set Open_vSwitch . other_config:max-idle=20000\n",
        "_ovs-vsctl set Open_vSwitch . other_config:max-revalidator=5000\n",
        "_ovs-vsctl remove Open_vSwitch . other_config default-datapath-type || true\n",

        "if systemctl list-unit-files openvswitch-switch.service &>/dev/null; then\n",
            "systemctl restart openvswitch-switch\n",
        "elif systemctl list-unit-files openvswitch.service &>/dev/null; then\n",
            "systemctl restart openvswitch\n",
        "fi\n",
        "_ovs-vsctl --may-exist add-br br-sfc\n",
        "_ovs-vsctl set bridge br-sfc datapath_type=netdev\n",
        "_ovs-vsctl set bridge br-sfc fail_mode=secure\n",
        "_ovs-vsctl --may-exist add-port br-sfc p0\n",
        "_ovs-vsctl set Interface p0 type=dpdk\n",
        "_ovs-vsctl set Interface p0 mtu_request=9216\n",
        "_ovs-vsctl set Port p0 external_ids:dpf-type=physical\n",
        "_ovs-vsctl --may-exist add-br br-hbn\n",
        "_ovs-vsctl set bridge br-hbn datapath_type=netdev\n",
        "_ovs-vsctl set bridge br-hbn fail_mode=secure\n",
    )
    .to_string()
}

/// OVS raw config script for the BF4 flavor.
fn get_bf4_ovs_defaults() -> String {
    concat!(
        "_ovs-vsctl() {\n",
        "    ovs-vsctl --timeout 15 \"$@\"\n",
        "}\n",

        "# Remove default OVS configuration on the DPU and ensure no leftovers on the OVS kernel side\n",
        "for i in $(seq 1 99); do\n",
        "    ovs-vsctl --if-exists del-br \"ovsbr${i}\"\n",
        "done\n",

        "ovs-appctl --timeout 15 dpctl/del-dp system@ovs-system || true\n",

        "_ovs-vsctl set Open_vSwitch . other_config:doca-init=true\n",
        "_ovs-vsctl set Open_vSwitch . other_config:dpdk-max-memzones=50000\n",
        "_ovs-vsctl set Open_vSwitch . other_config:hw-offload=true\n",
        "_ovs-vsctl set Open_vSwitch . other_config:pmd-quiet-idle=true\n",
        "_ovs-vsctl set Open_vSwitch . other_config:max-idle=20000\n",
        "_ovs-vsctl set Open_vSwitch . other_config:max-revalidator=5000\n",
        "_ovs-vsctl set Open_vSwitch . other_config:doca-congestion-threshold=60\n",
        "_ovs-vsctl set Open_vSwitch . other_config:flow-limit=500000\n",
        "_ovs-vsctl set Open_vSwitch . other_config:hw-offload-ct-unidir-udp-enabled=true\n",
        "_ovs-vsctl remove Open_vSwitch . other_config default-datapath-type || true\n",

        "if systemctl list-unit-files openvswitch-switch.service &>/dev/null; then\n",
        "    systemctl restart openvswitch-switch\n",
        "elif systemctl list-unit-files openvswitch.service &>/dev/null; then\n",
        "    systemctl restart openvswitch\n",
        "fi\n",

        "_ovs-vsctl --may-exist add-br br-sfc\n",
        "_ovs-vsctl set bridge br-sfc datapath_type=netdev\n",
        "_ovs-vsctl set bridge br-sfc fail_mode=secure\n",
        "_ovs-vsctl --may-exist add-port br-sfc p0\n",
        "_ovs-vsctl set Interface p0 type=dpdk\n",
        "_ovs-vsctl set Interface p0 mtu_request=9216\n",
        "_ovs-vsctl set Port p0 external_ids:dpf-type=physical\n",

        "_ovs-vsctl --may-exist add-br br-hbn\n",
        "_ovs-vsctl set bridge br-hbn datapath_type=netdev\n",
        "_ovs-vsctl set bridge br-hbn fail_mode=secure\n",
        "mst start\n",
    )
    .to_string()
}

/// OVS raw config script for the BF4 flavor.
fn get_bf4_astra_ovs_defaults() -> String {
    concat!(
        "#!/bin/bash\n",
        "# Shared helper used by the called scripts; exported so they inherit it\n",
        "\n",
        "# create an entry in /etc/hosts to allow self hostname resolution: (bug fix)\n",
        "grep -qw \"$HOSTNAME\" /etc/hosts || echo \"127.0.0.1 $HOSTNAME\" | sudo tee -a /etc/hosts > /dev/null\n",
        "\n",
        "_ovs-vsctl() {\n",
        "  ovs-vsctl --timeout 30 \"$@\"\n",
        "}\n",
        "export -f _ovs-vsctl\n",
        "\n",
        "# 1. Configure OVS bridges and xplane ports\n",
        "/etc/mellanox/ovs-script.sh\n",
        "\n",
        "# 2. Configure rail bridge addressing (netplan)\n",
        "/etc/mellanox/xplane-bridge.sh\n",
    )
    .to_string()
}

/// Rejects proxy strings containing characters that would break a systemd `Environment="..."` line:
/// double-quotes (break the quoting), newlines / carriage returns (break the unit-file line), and
/// any other ASCII control character (< 0x20 or DEL 0x7f).
fn validate_proxy_string(value: &str, field: &str) -> Result<(), crate::error::DpfError> {
    if value.chars().any(|c| c == '"' || c < '\x20' || c == '\x7f') {
        return Err(crate::error::DpfError::ConfigError(format!(
            "proxy {field} contains characters that are not allowed in a systemd \
             Environment= value (quotes, newlines, or control characters)"
        )));
    }
    Ok(())
}

/// Build the DPUFlavor spec for a specific deployment type. If `proxy` is set, a containerd
/// proxy drop-in config file is appended so the DPU can pull images through the proxy.
///
/// Returns `ConfigError` if any proxy string contains characters that would break the generated
/// systemd `Environment="..."` lines (quotes, newlines, or other control characters).
///
/// `metadata.name` is left unset; callers must set it (typically via [`DPUFlavor::unique_name`])
/// before creating the resource in the cluster.
pub fn default_flavor_for(
    namespace: &str,
    proxy: &Option<DpfProxyDetails>,
    // Selects the DPUFlavor variant to build for the given deployment type.
    deployment_type: DpuDeploymentType,
) -> Result<DPUFlavor, crate::error::DpfError> {
    match deployment_type {
        DpuDeploymentType::Bf4Generic => flavor_bf4(namespace, proxy),
        DpuDeploymentType::Bf4Astra => flavor_bf4_astra(namespace, proxy),
        DpuDeploymentType::Bf3 => default_flavor(namespace, proxy),
    }
}

/// Build the BF4 (generic) DPUFlavor spec, with BF4-specific grub and OVS configuration.
/// If `proxy` is set, a containerd proxy drop-in config file is appended so the DPU can pull
/// images through the proxy.
///
/// Returns `ConfigError` if any proxy string contains characters that would break the generated
/// systemd `Environment="..."` lines (quotes, newlines, or other control characters).
///
/// `metadata.name` is left unset; callers must set it (typically via [`DPUFlavor::unique_name`])
/// before creating the resource in the cluster.
pub fn flavor_bf4(
    namespace: &str,
    proxy: &Option<DpfProxyDetails>,
) -> Result<DPUFlavor, crate::error::DpfError> {
    let bfcfg_parameters = vec![
        "UPDATE_ATF_UEFI=yes".to_string(),
        "UPDATE_DPU_OS=yes".to_string(),
        "WITH_NIC_FW_UPDATE=yes".to_string(),
    ];
    Ok(DPUFlavor {
        metadata: ObjectMeta {
            name: None,
            namespace: Some(namespace.to_string()),
            ..Default::default()
        },
        spec: DpuFlavorSpec {
            dpu_mode: Some(DpuFlavorDpuMode::ZeroTrust),
            dpu_resources: None,
            bfcfg_parameters: Some(bfcfg_parameters),
            config_files: Some(get_config_files(proxy)?),
            containerd_config: None,
            grub: Some(bf4_grub_params()),
            host_network_interface_configs: None,
            nvconfig: Some(vec![get_bf4_default_nvconfig()]),
            ovs: Some(crate::crds::dpuflavors_generated::DpuFlavorOvs {
                raw_config_script: Some(get_bf4_ovs_defaults()),
            }),
            sysctl: None,
            system_reserved_resources: None,
            ew_nic_configurations: None,
            packages: None,
            systemd_services: None,
            host_os_init: None,
            scalable_functions: None,
        },
    })
}

/// Build the BF4 Astra DPUFlavor spec, with BF4-astra grub and OVS
/// configuration.
/// If `proxy` is set, a containerd proxy drop-in config file is appended so the DPU can pull
/// images through the proxy.
///
/// Returns `ConfigError` if any proxy string contains characters that would
/// break the generated systemd `Environment="..."` lines (quotes, newlines,
/// or other control characters).
///
/// `metadata.name` is left unset; callers must set it (typically via [`DPUFlavor::unique_name`])
/// before creating the resource in the cluster.
pub fn flavor_bf4_astra(
    namespace: &str,
    proxy: &Option<DpfProxyDetails>,
) -> Result<DPUFlavor, crate::error::DpfError> {
    Ok(DPUFlavor {
        metadata: ObjectMeta {
            name: None,
            namespace: Some(namespace.to_string()),
            ..Default::default()
        },
        spec: DpuFlavorSpec {
            bfcfg_parameters: None,
            config_files: Some(get_bf4_astra_config_files(proxy)?),
            containerd_config: Some(DpuFlavorContainerdConfig {
                registry_endpoint: None,
            }),
            dpu_mode: None,
            dpu_resources: None,
            ew_nic_configurations: Some(bf4_astra_ew_nic_configurations()),
            grub: Some(bf4_astra_grub_params()),
            host_network_interface_configs: None,
            nvconfig: Some(vec![get_bf4_astra_nvconfig()]),
            ovs: Some(DpuFlavorOvs {
                raw_config_script: Some(get_bf4_astra_ovs_defaults()),
            }),
            packages: Some(vec![]),
            sysctl: Some(DpuFlavorSysctl {
                parameters: Some(vec![]),
            }),
            system_reserved_resources: None,
            systemd_services: Some(vec![]),
            host_os_init: None,
            scalable_functions: None,
        },
    })
}

/// Default grub kernel parameters for the BF4 flavor.
pub fn bf4_grub_params() -> DpuFlavorGrub {
    DpuFlavorGrub {
        kernel_parameters: Some(
            vec![
                "console=hvc0",
                "console=ttyAMA0",
                "net.ifnames=0",
                "biosdevname=0",
                "iommu.passthrough=1",
                "cgroup_no_v1=net_prio,net_cls",
                "hugepagesz=2048kB",
                "hugepages=250",
            ]
            .into_iter()
            .map(|x| x.to_string())
            .collect(),
        ),
    }
}

/// Default grub kernel parameters for the BF4 astra flavor.
pub fn bf4_astra_grub_params() -> DpuFlavorGrub {
    DpuFlavorGrub {
        kernel_parameters: Some(
            vec![
                "console=hvc0",
                "console=ttyAMA0",
                "fixrttc",
                "net.ifnames=0",
                "biosdevname=0",
                "iommu.passthrough=1",
                "cgroup_no_v1=net_prio,net_cls",
                "hugepagesz=2048kB",
                "hugepages=8072",
            ]
            .into_iter()
            .map(|x| x.to_string())
            .collect(),
        ),
    }
}

fn bf4_astra_ew_nic_configurations() -> Vec<DpuFlavorEwNicConfigurations> {
    vec![DpuFlavorEwNicConfigurations {
        force: None,
        link_type: None,
        network_bay: Some(DpuFlavorEwNicConfigurationsNetworkBay {
            conf: "conf1".to_string(),
        }),
        num_vfs: 1,
        raw_nv_config: Some(vec![
            DpuFlavorEwNicConfigurationsRawNvConfig {
                name: "BOARD_CONFIGURATION_MODE".to_string(),
                value: "0".to_string(),
            },
            DpuFlavorEwNicConfigurationsRawNvConfig {
                name: "LOAD_BALANCE_MODE_P1".to_string(),
                value: "2".to_string(),
            },
            DpuFlavorEwNicConfigurationsRawNvConfig {
                name: "LAG_RESOURCE_ALLOCATION".to_string(),
                value: "1".to_string(),
            },
            DpuFlavorEwNicConfigurationsRawNvConfig {
                name: "FLEX_PARSER_PROFILE_ENABLE".to_string(),
                value: "10".to_string(),
            },
            DpuFlavorEwNicConfigurationsRawNvConfig {
                name: "RDE_DISABLE".to_string(),
                value: "1".to_string(),
            },
            DpuFlavorEwNicConfigurationsRawNvConfig {
                name: "VF_LOG_BAR_SIZE".to_string(),
                value: "5".to_string(),
            },
            DpuFlavorEwNicConfigurationsRawNvConfig {
                name: "SRIOV_EN".to_string(),
                value: "1".to_string(),
            },
            DpuFlavorEwNicConfigurationsRawNvConfig {
                name: "NUM_OF_VFS".to_string(),
                value: "1".to_string(),
            },
            DpuFlavorEwNicConfigurationsRawNvConfig {
                name: "KEEP_ETH_LINK_UP_P1".to_string(),
                value: "0".to_string(),
            },
            DpuFlavorEwNicConfigurationsRawNvConfig {
                name: "ROCE_ADAPTIVE_ROUTING_EN".to_string(),
                value: "1".to_string(),
            },
            DpuFlavorEwNicConfigurationsRawNvConfig {
                name: "USER_PROGRAMMABLE_CC".to_string(),
                value: "1".to_string(),
            },
            DpuFlavorEwNicConfigurationsRawNvConfig {
                name: "TX_SCHEDULER_LOCALITY_MODE".to_string(),
                value: "2".to_string(),
            },
            DpuFlavorEwNicConfigurationsRawNvConfig {
                name: "ROCE_RTT_RESP_DSCP_P1".to_string(),
                value: "48".to_string(),
            },
            DpuFlavorEwNicConfigurationsRawNvConfig {
                name: "ROCE_RTT_RESP_DSCP_MODE_P1".to_string(),
                value: "1".to_string(),
            },
            DpuFlavorEwNicConfigurationsRawNvConfig {
                name: "ROCE_CC_STEERING_EXT".to_string(),
                value: "2".to_string(),
            },
            DpuFlavorEwNicConfigurationsRawNvConfig {
                name: "NUM_OF_PLANES_P1".to_string(),
                value: "4".to_string(),
            },
            DpuFlavorEwNicConfigurationsRawNvConfig {
                name: "NUM_OF_PF".to_string(),
                value: "4".to_string(),
            },
            DpuFlavorEwNicConfigurationsRawNvConfig {
                name: "LINK_TYPE_P1".to_string(),
                value: "2".to_string(),
            },
            DpuFlavorEwNicConfigurationsRawNvConfig {
                name: "HIDE_PORT2_PF".to_string(),
                value: "1".to_string(),
            },
        ]),
        spectrum_x_optimized: Some(DpuFlavorEwNicConfigurationsSpectrumXOptimized {
            enabled: true,
            multiplane_mode: Some(
                DpuFlavorEwNicConfigurationsSpectrumXOptimizedMultiplaneMode::Hwplb,
            ),
            number_of_planes: Some(4),
            overlay: Some(DpuFlavorEwNicConfigurationsSpectrumXOptimizedOverlay::None),
            version: "RA2.2-runtime".to_string(),
        }),
    }]
}

/// Build the default DPUFlavor spec. If `proxy` is set, a containerd proxy drop-in config file
/// is appended so the DPU can pull images through the proxy.
///
/// Returns `ConfigError` if any proxy string contains characters that would break the generated
/// systemd `Environment="..."` lines (quotes, newlines, or other control characters).
///
/// `metadata.name` is left unset; callers must set it (typically via [`DPUFlavor::unique_name`])
/// before creating the resource in the cluster.
pub fn default_flavor(
    namespace: &str,
    proxy: &Option<DpfProxyDetails>,
) -> Result<DPUFlavor, crate::error::DpfError> {
    let bfcfg_parameters = vec![
        "UPDATE_ATF_UEFI=yes".to_string(),
        "UPDATE_DPU_OS=yes".to_string(),
        "WITH_NIC_FW_UPDATE=yes".to_string(),
    ];
    Ok(DPUFlavor {
        metadata: ObjectMeta {
            name: None,
            namespace: Some(namespace.to_string()),
            ..Default::default()
        },
        spec: DpuFlavorSpec {
            dpu_mode: Some(DpuFlavorDpuMode::ZeroTrust),
            dpu_resources: None,
            bfcfg_parameters: Some(bfcfg_parameters),
            config_files: Some(get_config_files(proxy)?),
            containerd_config: None,
            grub: Some(get_default_grub()),
            host_network_interface_configs: None,
            nvconfig: Some(vec![get_default_nvconfig()]),
            ovs: Some(crate::crds::dpuflavors_generated::DpuFlavorOvs {
                raw_config_script: Some(get_default_ovs_defaults()),
            }),
            sysctl: None,
            system_reserved_resources: None,
            ew_nic_configurations: None,
            packages: None,
            systemd_services: None,
            host_os_init: None,
            scalable_functions: None,
        },
    })
}

fn get_default_grub() -> DpuFlavorGrub {
    DpuFlavorGrub {
        kernel_parameters: Some(
            vec![
                "console=hvc0",
                "console=ttyAMA0",
                "earlycon=pl011,0x13010000",
                "fixrttc",
                "net.ifnames=0",
                "biosdevname=0",
                "iommu.passthrough=1",
                "cgroup_no_v1=net_prio,net_cls",
                "hugepagesz=2048kB",
                "hugepages=3072",
            ]
            .into_iter()
            .map(|x| x.to_string())
            .collect(),
        ),
    }
}

/// Returns the base set of config files, plus an optional containerd proxy drop-in if `proxy` is set.
fn get_config_files(
    proxy: &Option<DpfProxyDetails>,
) -> Result<Vec<DpuFlavorConfigFiles>, crate::error::DpfError> {
    let mut config_files = vec![
        DpuFlavorConfigFiles {
            path: "/var/lib/hbn/etc/supervisor/conf.d/acltool.conf".to_string(),
            operation: Some(DpuFlavorConfigFilesOperation::Override),
            permissions: Some("0644".to_string()),
            raw: Some(
                concat!(
                    "[program: cl-acltool]\n",
                    "command = bash -c \"sleep 5 && ",
                    "/usr/cumulus/bin/cl-acltool -i\"\n",
                    "startsecs = 0\n",
                    "autorestart = false\n",
                    "priority = 200\n",
                )
                .to_string(),
            ),
            content_from: None,
            r#type: None,
        },
        DpuFlavorConfigFiles {
            path: "/var/lib/hbn/etc/cumulus/acl/policy.d/10-dhcp.rules".to_string(),
            operation: Some(DpuFlavorConfigFilesOperation::Override),
            permissions: Some("0644".to_string()),
            raw: Some(dhcp_acl_rules()),
            content_from: None,
            r#type: None,
        },
        DpuFlavorConfigFiles {
            path: "/etc/lldpd.d/lldp-interfaces.conf".to_string(),
            operation: Some(DpuFlavorConfigFilesOperation::Override),
            permissions: Some("0644".to_string()),
            raw: Some("configure system interface pattern *\n".to_string()),
            content_from: None,
            r#type: None,
        },
        DpuFlavorConfigFiles {
            path: "/etc/default/lldpd".to_string(),
            operation: Some(DpuFlavorConfigFilesOperation::Override),
            permissions: Some("0644".to_string()),
            raw: Some("DAEMON_ARGS=\"-M 1\"\n".to_string()),
            content_from: None,
            r#type: None,
        },
        DpuFlavorConfigFiles {
            path: "/etc/mellanox/mlnx-bf.conf".to_string(),
            operation: Some(DpuFlavorConfigFilesOperation::Override),
            permissions: Some("0644".to_string()),
            raw: Some(
                concat!(
                    "ALLOW_SHARED_RQ=\"no\"\n",
                    "IPSEC_FULL_OFFLOAD=\"no\"\n",
                    "ENABLE_ESWITCH_MULTIPORT=\"yes\"\n"
                )
                .to_string(),
            ),
            content_from: None,
            r#type: None,
        },
        DpuFlavorConfigFiles {
            path: "/etc/mellanox/mlnx-ovs.conf".to_string(),
            operation: Some(DpuFlavorConfigFilesOperation::Override),
            permissions: Some("0644".to_string()),
            raw: Some(concat!("CREATE_OVS_BRIDGES=\"no\"\n", "OVS_DOCA=\"yes\"\n").to_string()),
            content_from: None,
            r#type: None,
        },
        DpuFlavorConfigFiles {
            path: "/etc/mellanox/mlnx-sf.conf".to_string(),
            operation: Some(DpuFlavorConfigFilesOperation::Override),
            permissions: Some("0644".to_string()),
            raw: Some("".to_string()),
            content_from: None,
            r#type: None,
        },
    ];

    if let Some(proxy) = proxy {
        validate_proxy_string(&proxy.https_proxy, "https_proxy")?;

        let mut raw = format!(
            "[Service]\nEnvironment=\"HTTPS_PROXY={0}\"\nEnvironment=\"https_proxy={0}\"\n",
            proxy.https_proxy
        );
        let mut entries: Vec<&str> = proxy
            .no_proxy
            .iter()
            .map(|e| e.trim())
            .filter(|e| !e.is_empty())
            .collect();
        if !entries.is_empty() {
            for entry in &entries {
                validate_proxy_string(entry, "no_proxy entry")?;
            }
            entries.sort_unstable();
            entries.dedup();
            let no_proxy = entries.join(",");
            raw.push_str(&format!(
                "Environment=\"NO_PROXY={0}\"\nEnvironment=\"no_proxy={0}\"\n",
                no_proxy
            ));
        }
        config_files.push(DpuFlavorConfigFiles {
            path: "/etc/systemd/system/containerd.service.d/socks-proxy.conf".to_string(),
            operation: Some(DpuFlavorConfigFilesOperation::Override),
            permissions: Some("0644".to_string()),
            raw: Some(raw),
            content_from: None,
            r#type: None,
        });
    }

    Ok(config_files)
}
fn get_bf4_default_nvconfig() -> DpuFlavorNvconfig {
    let parameters = vec![
        "PF_BAR2_ENABLE=0".to_string(),
        "PER_PF_NUM_SF=1".to_string(),
        "PF_TOTAL_SF=30".to_string(),
        "PF_SF_BAR_SIZE=14".to_string(),
        "NUM_PF_MSIX_VALID=0".to_string(),
        "PF_NUM_PF_MSIX_VALID=1".to_string(),
        "PF_NUM_PF_MSIX=228".to_string(),
        "INTERNAL_CPU_MODEL=1".to_string(),
        "INTERNAL_CPU_OFFLOAD_ENGINE=0".to_string(),
        "SRIOV_EN=1".to_string(),
        "LAG_RESOURCE_ALLOCATION=1".to_string(),
        "NUM_OF_VFS=16".to_string(),
        "LINK_TYPE_P1=ETH".to_string(),
        "LINK_TYPE_P2=ETH".to_string(),
    ];

    DpuFlavorNvconfig {
        // DPF does not allow anyother wild card. It takes only '*'
        device: Some(DpuFlavorNvconfigDevice::KopiumVariant0), //"*"
        parameters: Some(parameters),
    }
}

/// Returns the bf4 astra config files, plus an optional containerd proxy drop-in if `proxy` is set.
fn get_bf4_astra_config_files(
    proxy: &Option<DpfProxyDetails>,
) -> Result<Vec<DpuFlavorConfigFiles>, crate::error::DpfError> {
    let mut config_files = vec![
        DpuFlavorConfigFiles {
            content_from: None,
            operation: Some(DpuFlavorConfigFilesOperation::Override),
            path: "/etc/mellanox/mlnx-bf.conf".to_string(),
            permissions: Some("0644".to_string()),
            raw: Some(
                concat!(
                    "ALLOW_SHARED_RQ=\"no\"\n",
                    "IPSEC_FULL_OFFLOAD=\"no\"\n",
                    "ENABLE_ESWITCH_MULTIPORT=\"yes\"\n",
                )
                .to_string(),
            ),
            r#type: None,
        },
        DpuFlavorConfigFiles {
            content_from: None,
            operation: Some(DpuFlavorConfigFilesOperation::Override),
            path: "/etc/mellanox/mlnx-ovs.conf".to_string(),
            permissions: Some("0644".to_string()),
            raw: Some(
                concat!(
                    "CREATE_OVS_BRIDGES=\"no\"\n",
                    "OVS_DOCA=\"yes\"\n",
                )
                .to_string(),
            ),
            r#type: None,
        },
        DpuFlavorConfigFiles {
            content_from: None,
            operation: Some(DpuFlavorConfigFilesOperation::Override),
            path: "/etc/mellanox/mlnx-sf.conf".to_string(),
            permissions: Some("0644".to_string()),
            raw: Some(String::new()),
            r#type: None,
        },
        DpuFlavorConfigFiles {
            content_from: None,
            operation: Some(DpuFlavorConfigFilesOperation::Override),
            path: "/bindata/spectrum-x/RA2.2-runtime.yaml".to_string(),
            permissions: Some("0644".to_string()),
            raw: Some(
                concat!(
                    "# Copyright 2025 NVIDIA CORPORATION & AFFILIATES\n",
                    "#\n",
                    "# Licensed under the Apache License, Version 2.0 (the \"License\");\n",
                    "# you may not use this file except in compliance with the License.\n",
                    "# You may obtain a copy of the License at\n",
                    "#\n",
                    "#     http://www.apache.org/licenses/LICENSE-2.0\n",
                    "#\n",
                    "# Unless required by applicable law or agreed to in writing, software\n",
                    "# distributed under the License is distributed on an \"AS IS\" BASIS,\n",
                    "# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n",
                    "# See the License for the specific language governing permissions and\n",
                    "# limitations under the License.\n",
                    "#\n",
                    "# SPDX-License-Identifier: Apache-2.0\n",
                    "runtimeConfig:\n",
                    "  roce:\n",
                    "    - name: Trust\n",
                    "      value: dscp\n",
                    "      dmsPath: /interfaces/interface/nvidia/qos/config/trust-mode\n",
                    "      valueType: string\n",
                    "      alternativeValue: QOS_TRUST_MODE_DSCP\n",
                    "    - name: PFC\n",
                    "      value: \"00010000\"\n",
                    "      dmsPath: /interfaces/interface/nvidia/qos/config/pfc\n",
                    "      valueType: string\n",
                    "  adaptiveRouting:\n",
                    "    - name: Enable CC per plane\n",
                    "      value: \"0x00000001\"\n",
                    "      multiplane: hwplb\n",
                    "      mlxreg:\n",
                    "        register: ROCE_ACCL\n",
                    "        field: cc_per_plane_en\n",
                    "        setFields:\n",
                    "          - name: cc_per_plane_en\n",
                    "            value: \"0x1\"\n",
                    "          - name: cc_per_plane_en_field_select\n",
                    "            value: \"0x1\"\n",
                    "    - name: Adaptive Retransmission\n",
                    "      value: true\n",
                    "      dmsPath: /interfaces/interface/nvidia/roce/config/adaptive-retransmission\n",
                    "      valueType: bool\n",
                    "    - name: Tx Window\n",
                    "      value: true\n",
                    "      dmsPath: /interfaces/interface/nvidia/roce/config/tx-window\n",
                    "      valueType: bool\n",
                    "    - name: Slow Restart\n",
                    "      value: false\n",
                    "      dmsPath: /interfaces/interface/nvidia/roce/config/slow-restart\n",
                    "      valueType: bool\n",
                    "    - name: Slow Restart Idle\n",
                    "      value: false\n",
                    "      dmsPath: /interfaces/interface/nvidia/roce/config/slow-restart-idle\n",
                    "      valueType: bool\n",
                    "    - name: CC Probe MP mode\n",
                    "      value: \"0x00000001\"\n",
                    "      multiplane: hwplb\n",
                    "      mlxreg:\n",
                    "        register: ROCE_ACCL\n",
                    "        field: cc_probe_mp_mode\n",
                    "        setFields:\n",
                    "          - name: cc_probe_mp_mode\n",
                    "            value: \"0x1\"\n",
                    "          - name: cc_probe_mp_mode_field_select\n",
                    "            value: \"0x1\"\n",
                    "    - name: Adaptive Routing Force\n",
                    "      value: true\n",
                    "      dmsPath: /interfaces/interface/nvidia/roce/config/adaptive-routing-force\n",
                    "      valueType: bool\n",
                    "  congestionControl:\n",
                    "    - name: Congestion Control on RP points\n",
                    "      value: true\n",
                    "      dmsPath: /interfaces/interface/nvidia/cc/config/priority/rp_enabled\n",
                    "      valueType: bool\n",
                    "      alternativeValue: \"1\"\n",
                    "      hwplbFirstPortOnly: true\n",
                    "    - name: Congestion Control on NP points\n",
                    "      value: true\n",
                    "      dmsPath: /interfaces/interface/nvidia/cc/config/priority/np_enabled\n",
                    "      valueType: bool\n",
                    "      alternativeValue: \"1\"\n",
                    "      hwplbFirstPortOnly: true\n",
                    "    - name: Congestion Control\n",
                    "      value: true\n",
                    "      dmsPath: /interfaces/interface/nvidia/cc/slot[id=0]/config/enabled\n",
                    "      valueType: bool\n",
                    "    - name: Congestion Control with Counters\n",
                    "      value: true\n",
                    "      dmsPath: /interfaces/interface/nvidia/cc/slot[id=0]/config/counter_enable\n",
                    "      valueType: bool\n",
                    "    - name: DCQCN\n",
                    "      value: false\n",
                    "      dmsPath: /interfaces/interface/nvidia/cc/slot[id=15]/config/enabled\n",
                    "      valueType: bool\n",
                    "    - name: Bandwidth\n",
                    "      value: 400\n",
                    "      dmsPath: /interfaces/interface/nvidia/cc/slot[id=0]/param[id=0]/config/value\n",
                    "      valueType: int\n",
                    "      deviceId: \"1023\"\n",
                    "      breakout: 2\n",
                    "    - name: Bandwidth\n",
                    "      value: 200\n",
                    "      dmsPath: /interfaces/interface/nvidia/cc/slot[id=0]/param[id=0]/config/value\n",
                    "      valueType: int\n",
                    "      deviceId: \"1023\"\n",
                    "      breakout: 4\n",
                    "    - name: Bandwidth\n",
                    "      value: 400\n",
                    "      dmsPath: /interfaces/interface/nvidia/cc/slot[id=0]/param[id=0]/config/value\n",
                    "      valueType: int\n",
                    "      deviceId: \"1025\"\n",
                    "      breakout: 2\n",
                    "    - name: Bandwidth\n",
                    "      value: 200\n",
                    "      dmsPath: /interfaces/interface/nvidia/cc/slot[id=0]/param[id=0]/config/value\n",
                    "      valueType: int\n",
                    "      deviceId: \"1025\"\n",
                    "      breakout: 4\n",
                    "    - name: Bandwidth\n",
                    "      value: 200\n",
                    "      dmsPath: /interfaces/interface/nvidia/cc/slot[id=0]/param[id=0]/config/value\n",
                    "      valueType: int\n",
                    "      deviceId: \"a2dc\"\n",
                    "      breakout: 2\n",
                    "    - name: Bandwidth\n",
                    "      value: 100\n",
                    "      dmsPath: /interfaces/interface/nvidia/cc/slot[id=0]/param[id=0]/config/value\n",
                    "      valueType: int\n",
                    "      deviceId: \"a2dc\"\n",
                    "      breakout: 4\n",
                    "    - name: Responsiveness Alpha Factor\n",
                    "      value: 6553\n",
                    "      dmsPath: /interfaces/interface/nvidia/cc/slot[id=0]/param[id=1]/config/value\n",
                    "      valueType: int\n",
                    "    - name: Maximum Decrease Factor\n",
                    "      value: 63570\n",
                    "      dmsPath: /interfaces/interface/nvidia/cc/slot[id=0]/param[id=2]/config/value\n",
                    "      valueType: int\n",
                    "    - name: Maximum Increase Factor\n",
                    "      value: 69468\n",
                    "      dmsPath: /interfaces/interface/nvidia/cc/slot[id=0]/param[id=3]/config/value\n",
                    "      valueType: int\n",
                    "    - name: Additive Increase Step Size\n",
                    "      value: 96\n",
                    "      dmsPath: /interfaces/interface/nvidia/cc/slot[id=0]/param[id=4]/config/value\n",
                    "      valueType: int\n",
                    "    - name: High Additive Increase Step Size\n",
                    "      value: 1700\n",
                    "      dmsPath: /interfaces/interface/nvidia/cc/slot[id=0]/param[id=5]/config/value\n",
                    "      valueType: int\n",
                    "    - name: High Additive Increase Interval Period\n",
                    "      value: 200000\n",
                    "      dmsPath: /interfaces/interface/nvidia/cc/slot[id=0]/param[id=6]/config/value\n",
                    "      valueType: int\n",
                    "    - name: ZTR_CC_CONGESTION_DELAY_THRESHOLD\n",
                    "      value: 13000\n",
                    "      dmsPath: /interfaces/interface/nvidia/cc/slot[id=0]/param[id=7]/config/value\n",
                    "      valueType: int\n",
                    "    - name: Maximum Queuing Delay\n",
                    "      value: 250000\n",
                    "      dmsPath: /interfaces/interface/nvidia/cc/slot[id=0]/param[id=8]/config/value\n",
                    "      valueType: int\n",
                    "    - name: Rate on First Congestion\n",
                    "      value: 524288\n",
                    "      dmsPath: /interfaces/interface/nvidia/cc/slot[id=0]/param[id=9]/config/value\n",
                    "      valueType: int\n",
                    "    - name: Delay Only\n",
                    "      value: 0\n",
                    "      dmsPath: /interfaces/interface/nvidia/cc/slot[id=0]/param[id=10]/config/value\n",
                    "      valueType: int\n",
                    "    - name: CNP Validity\n",
                    "      value: 1\n",
                    "      dmsPath: /interfaces/interface/nvidia/cc/slot[id=0]/param[id=11]/config/value\n",
                    "      valueType: int\n",
                    "    - name: Transmit Rate Decrement Step\n",
                    "      value: 1\n",
                    "      dmsPath: /interfaces/interface/nvidia/cc/slot[id=0]/param[id=12]/config/value\n",
                    "      valueType: int\n",
                    "    - name: Fixed Transmission Rate\n",
                    "      value: 0\n",
                    "      dmsPath: /interfaces/interface/nvidia/cc/slot[id=0]/param[id=13]/config/value\n",
                    "      valueType: int\n",
                    "    - name: Fast Scheduling Factor\n",
                    "      value: 2097152\n",
                    "      dmsPath: /interfaces/interface/nvidia/cc/slot[id=0]/param[id=14]/config/value\n",
                    "      valueType: int\n",
                    "    - name: Topology Awareness\n",
                    "      value: 1\n",
                    "      dmsPath: /interfaces/interface/nvidia/cc/slot[id=0]/param[id=15]/config/value\n",
                    "      valueType: int\n",
                    "    - name: Advanced Features\n",
                    "      value: 1\n",
                    "      dmsPath: /interfaces/interface/nvidia/cc/slot[id=0]/param[id=16]/config/value\n",
                    "      valueType: int\n",
                    "    - name: Troubleshooting Capabilities\n",
                    "      value: 0\n",
                    "      dmsPath: /interfaces/interface/nvidia/cc/slot[id=0]/param[id=17]/config/value\n",
                    "      valueType: int\n",
                    "    - name: CC_FIXED_CWND\n",
                    "      value: 0\n",
                    "      dmsPath: /interfaces/interface/nvidia/cc/slot[id=0]/param[id=18]/config/value\n",
                    "      valueType: int\n",
                    "    - name: Enable CC Plane Failure Detection\n",
                    "      value: 1\n",
                    "      dmsPath: /interfaces/interface/nvidia/cc/slot[id=0]/param[id=22]/config/value\n",
                    "      valueType: int\n",
                    "      multiplane: hwplb\n",
                    "    - name: CC Plane Failure Threshold\n",
                    "      value: 3\n",
                    "      dmsPath: /interfaces/interface/nvidia/cc/slot[id=0]/param[id=23]/config/value\n",
                    "      valueType: int\n",
                    "      multiplane: hwplb\n",
                    "    - name: CC Plane Recovery Threshold\n",
                    "      value: 1\n",
                    "      dmsPath: /interfaces/interface/nvidia/cc/slot[id=0]/param[id=24]/config/value\n",
                    "      valueType: int\n",
                    "      multiplane: hwplb\n",
                    "  interPacketGap:\n",
                    "    pureL3:\n",
                    "      - name: Inter Packet Gap for no overlay\n",
                    "        value: 25\n",
                    "        dmsPath: /interfaces/interface/ethernet/nvidia/config/inter-packet-gap\n",
                    "        valueType: int\n",
                    "    l3EVPN:\n",
                    "      - name: Inter Packet Gap for L3 EVPN overlay\n",
                    "        value: 33\n",
                    "        dmsPath: /interfaces/interface/ethernet/nvidia/config/inter-packet-gap\n",
                    "        valueType: int\n",
                    "docaCCVersion: 3.4.0\n",
                    "useSoftwareCCAlgorithm: true\n",
                )
                .to_string(),
            ),
            r#type: None,
        },
        DpuFlavorConfigFiles {
            content_from: None,
            operation: Some(DpuFlavorConfigFilesOperation::Override),
            path: "/etc/mellanox/ovs-script.sh".to_string(),
            permissions: Some("0755".to_string()),
            raw: Some(
                concat!(
                    "#!/bin/bash\n",
                    "\n",
                    "# Remove default OVS configuration on the DPU and ensure no leftovers on the OVS kernel side\n",
                    "seq -f 'ovsbr%g' 1 99 | xargs -r -n1 ovs-vsctl --if-exists del-br\n",
                    "\n",
                    "ovs-appctl --timeout 15 dpctl/del-dp system@ovs-system || true\n",
                    "\n",
                    "# Run devlink commands to set eswitch multiport:\n",
                    "CX9_DEVS=(pci/0004:03:00 pci/0005:03:00 pci/0004:06:00 pci/0005:06:00 pci/0000:03:00 pci/0001:03:00 pci/0000:06:00 pci/0001:06:00)\n",
                    "for dev in \"${CX9_DEVS[@]}\"; do\n",
                    "  for i in 0 1 2 3; do devlink dev eswitch set ${dev}.$i mode switchdev; done\n",
                    "done\n",
                    "for dev in \"${CX9_DEVS[@]}\"; do\n",
                    "  for i in 0 1 2 3; do devlink dev param set ${dev}.$i name esw_multiport value true cmode runtime; done\n",
                    "done\n",
                    "\n",
                    "# 2. Configure OVS\n",
                    "_ovs-vsctl set Open_vSwitch . other_config:doca-init=true\n",
                    "_ovs-vsctl set Open_vSwitch . other_config:dpdk-max-memzones=50000\n",
                    "_ovs-vsctl set Open_vSwitch . other_config:hw-offload=true\n",
                    "_ovs-vsctl set Open_vSwitch . other_config:pmd-quiet-idle=true\n",
                    "_ovs-vsctl set Open_vSwitch . other_config:max-idle=20000\n",
                    "_ovs-vsctl set Open_vSwitch . other_config:max-revalidator=5000\n",
                    "_ovs-vsctl set Open_vSwitch . other_config:doca-congestion-threshold=60\n",
                    "_ovs-vsctl set Open_vSwitch . other_config:flow-limit=500000\n",
                    "_ovs-vsctl set Open_vSwitch . other_config:hw-offload-ct-unidir-udp-enabled=true\n",
                    "_ovs-vsctl remove Open_vSwitch . other_config default-datapath-type || true\n",
                    "\n",
                    "if systemctl list-unit-files openvswitch-switch.service &>/dev/null; then\n",
                    "  systemctl restart openvswitch-switch\n",
                    "elif systemctl list-unit-files openvswitch.service &>/dev/null; then\n",
                    "  systemctl restart openvswitch\n",
                    "fi\n",
                    "\n",
                    "\n",
                    "_ovs-vsctl --may-exist add-br br-sfc\n",
                    "_ovs-vsctl set bridge br-sfc datapath_type=netdev\n",
                    "_ovs-vsctl set bridge br-sfc fail_mode=secure\n",
                    "_ovs-vsctl --may-exist add-br br-hbn\n",
                    "_ovs-vsctl set bridge br-hbn datapath_type=netdev\n",
                    "_ovs-vsctl set bridge br-hbn fail_mode=secure\n",
                    "\n",
                    "# Pre plug p0 to br-sfc\n",
                    "_ovs-vsctl --may-exist add-port br-sfc p0\n",
                    "_ovs-vsctl set Interface p0 type=dpdk\n",
                    "_ovs-vsctl set Interface p0 mtu_request=9216\n",
                    "_ovs-vsctl set Port p0 external_ids:dpf-type=physical\n",
                    "\n",
                    "# Pre plug p1 to br-sfc\n",
                    "_ovs-vsctl --may-exist add-port br-sfc p1\n",
                    "_ovs-vsctl set Interface p1 type=dpdk\n",
                    "_ovs-vsctl set Interface p1 mtu_request=9216\n",
                    "_ovs-vsctl set Port p1 external_ids:dpf-type=physical\n",
                    "\n",
                    "# Configure ovs bridges for xplane:\n",
                    "RAILS=(0 1 2 3)\n",
                    "SW_PLANES=(0 1)\n",
                    "HW_PLANES=(0 1 2 3)\n",
                    "\n",
                    "for rail in \"${RAILS[@]}\"; do\n",
                    "    for sw_plane in \"${SW_PLANES[@]}\"; do\n",
                    "        bridge=\"brcx-r${rail}swpln${sw_plane}\"\n",
                    "        _ovs-vsctl --may-exist add-br \"$bridge\"\n",
                    "        _ovs-vsctl set bridge \"$bridge\" datapath_type=netdev\n",
                    "        _ovs-vsctl set bridge \"$bridge\" fail_mode=standalone\n",
                    "    done\n",
                    "done\n",
                    "\n",
                    "_ovs-vsctl --may-exist add-br br-xplane\n",
                    "_ovs-vsctl set bridge br-xplane datapath_type=netdev\n",
                    "_ovs-vsctl set bridge br-xplane fail_mode=secure\n",
                    "\n",
                    "# Map (rail, sw_plane) -> CX9 ID\n",
                    "# Rail 0: SW 0 -> CX1, SW 1 -> CX2\n",
                    "# Rail 1: SW 0 -> CX0, SW 1 -> CX3\n",
                    "# Rail 2: SW 0 -> CX5, SW 1 -> CX6\n",
                    "# Rail 3: SW 0 -> CX4, SW 1 -> CX7\n",
                    "declare -A CX9_MAP\n",
                    "CX9_MAP[\"0,0\"]=1\n",
                    "CX9_MAP[\"0,1\"]=2\n",
                    "CX9_MAP[\"1,0\"]=0\n",
                    "CX9_MAP[\"1,1\"]=3\n",
                    "CX9_MAP[\"2,0\"]=5\n",
                    "CX9_MAP[\"2,1\"]=6\n",
                    "CX9_MAP[\"3,0\"]=4\n",
                    "CX9_MAP[\"3,1\"]=7\n",
                    "\n",
                    "# Map CX9 ID -> interface name (Ax)\n",
                    "# A2 -> CX0, A3 -> CX1, A0 -> CX2, A1 -> CX3\n",
                    "# A4 -> CX4, A5 -> CX5, A6 -> CX6, A7 -> CX7\n",
                    "declare -A IFACE_MAP\n",
                    "IFACE_MAP[0]=\"A2\"\n",
                    "IFACE_MAP[1]=\"A3\"\n",
                    "IFACE_MAP[2]=\"A0\"\n",
                    "IFACE_MAP[3]=\"A1\"\n",
                    "IFACE_MAP[4]=\"A4\"\n",
                    "IFACE_MAP[5]=\"A5\"\n",
                    "IFACE_MAP[6]=\"A6\"\n",
                    "IFACE_MAP[7]=\"A7\"\n",
                    "\n",
                    "for rail in \"${RAILS[@]}\"; do\n",
                    "    for sw_plane in \"${SW_PLANES[@]}\"; do\n",
                    "        group_id=\"r${rail}swpln${sw_plane}\"\n",
                    "        cx9_id=\"${CX9_MAP[\"${rail},${sw_plane}\"]}\"\n",
                    "        iface_prefix=\"${IFACE_MAP[$cx9_id]}\"\n",
                    "\n",
                    "        for hw_plane in \"${HW_PLANES[@]}\"; do\n",
                    "            interface_val=\"${iface_prefix}p${hw_plane}\"\n",
                    "\n",
                    "            _ovs-vsctl --may-exist add-port br-xplane \"$interface_val\"\n",
                    "            _ovs-vsctl set Interface \"$interface_val\" type=dpdk\n",
                    "            _ovs-vsctl set Interface \"$interface_val\" mtu_request=9216\n",
                    "            _ovs-vsctl set Interface \"$interface_val\" external_ids:xplane=true\n",
                    "            _ovs-vsctl set Interface \"$interface_val\" external_ids:xplane-group-id=\"$group_id\"\n",
                    "            _ovs-vsctl set Interface \"$interface_val\" external_ids:xplane-uplink=true\n",
                    "            _ovs-vsctl set Interface \"$interface_val\" external_ids:xplane-plane-id=\"$hw_plane\"\n",
                    "        done\n",
                    "    done\n",
                    "done\n",
                )
                .to_string(),
            ),
            r#type: None,
        },
        DpuFlavorConfigFiles {
            content_from: None,
            operation: Some(DpuFlavorConfigFilesOperation::Override),
            path: "/etc/mellanox/xplane-bridge.sh".to_string(),
            permissions: Some("0755".to_string()),
            raw: Some(
                concat!(
                    "#!/bin/bash\n",
                    "\n",
                    "# Node list: \"Serial|NodeAddress|GWAddress\"\n",
                    "NODES=(\n",
                    "    \"MT26206064EV|212|213\"\n",
                    "    \"MT2619602QZU|214|215\"\n",
                    "    \"MT26206064DV|216|217\"\n",
                    "    \"MT26206064LM|218|219\"\n",
                    "    \"MT2620606MXD|220|221\"\n",
                    "    \"MT26206064EC|222|223\"\n",
                    "    \"MT26206064CC|224|225\"\n",
                    "    \"MT26206064NF|226|227\"\n",
                    "    \"MT26206064C6|228|229\"\n",
                    "    \"MT26206064LQ|230|231\"\n",
                    "    \"MT26206064HB|232|233\"\n",
                    "    \"MT26206064C5|234|235\"\n",
                    "    \"MT26206064HY|236|237\"\n",
                    "    \"MT26206064NE|238|239\"\n",
                    "    \"MT26206064GW|240|241\"\n",
                    "    \"MT26206064FY|242|243\"\n",
                    "    \"MT26206064MA|244|245\"\n",
                    "    \"MT26206064KK|246|247\"\n",
                    ")\n",
                    "\n",
                    "# Define Subnet Prefixes as an associative array indexed by \"rail,sw_plane\"\n",
                    "# sw_plane 0 = ports p01-p04, sw_plane 1 = ports p05-p08\n",
                    "declare -A SUB_PREFIXES\n",
                    "SUB_PREFIXES[\"0,0\"]=\"100.96.0\"\n",
                    "SUB_PREFIXES[\"1,0\"]=\"100.97.0\"\n",
                    "SUB_PREFIXES[\"2,0\"]=\"100.98.0\"\n",
                    "SUB_PREFIXES[\"3,0\"]=\"100.99.0\"\n",
                    "SUB_PREFIXES[\"0,1\"]=\"100.104.0\"\n",
                    "SUB_PREFIXES[\"1,1\"]=\"100.105.0\"\n",
                    "SUB_PREFIXES[\"2,1\"]=\"100.106.0\"\n",
                    "SUB_PREFIXES[\"3,1\"]=\"100.107.0\"\n",
                    "\n",
                    "# 1. Detect local node serial number\n",
                    "LOCAL_SERIAL=$(lspci -s 0002:01:00.0 -vvv 2>/dev/null | sed -n 's/.*Serial number: //p')\n",
                    "\n",
                    "# Fallback: Strip whitespaces if any exist\n",
                    "LOCAL_SERIAL=$(echo \"$LOCAL_SERIAL\" | tr -d '[:space:]')\n",
                    "\n",
                    "if [ -z \"$LOCAL_SERIAL\" ]; then\n",
                    "    echo \"failed to detect local DPU serial from PCI device 0002:01:00.0; cannot select rail addresses\" >&2\n",
                    "    exit 1\n",
                    "fi\n",
                    "\n",
                    "# 2. Find matching node variables from the list\n",
                    "NODE_ADDR=\"\"\n",
                    "GW_ADDR=\"\"\n",
                    "\n",
                    "for node in \"${NODES[@]}\"; do\n",
                    "    IFS=\"|\" read -r s_num n_addr g_addr <<< \"$node\"\n",
                    "    if [ \"$s_num\" == \"$LOCAL_SERIAL\" ]; then\n",
                    "        NODE_ADDR=\"$n_addr\"\n",
                    "        GW_ADDR=\"$g_addr\"\n",
                    "        break\n",
                    "    fi\n",
                    "done\n",
                    "\n",
                    "if [ -z \"$NODE_ADDR\" ] || [ -z \"$GW_ADDR\" ]; then\n",
                    "    echo \"no rail address mapping for DPU serial ${LOCAL_SERIAL}; NODE_ADDR=${NODE_ADDR:-unset} GW_ADDR=${GW_ADDR:-unset}\" >&2\n",
                    "    exit 1\n",
                    "fi\n",
                    "\n",
                    "# 3. Generate the Netplan Configuration File\n",
                    "NETPLAN_FILE=\"/etc/netplan/99-cx9-rails.yaml\"\n",
                    "\n",
                    "{\n",
                    "    echo \"network:\"\n",
                    "    echo \"  version: 2\"\n",
                    "    echo \"  ethernets:\"\n",
                    "\n",
                    "    for rail in 0 1 2 3; do\n",
                    "        for sw_plane in 0 1; do\n",
                    "            prefix=\"${SUB_PREFIXES[\"$rail,$sw_plane\"]}\"\n",
                    "\n",
                    "            echo \"    brcx-r${rail}swpln${sw_plane}:\"\n",
                    "            echo \"      addresses:\"\n",
                    "            echo \"        - ${prefix}.${NODE_ADDR}/31\"\n",
                    "            echo \"      routes:\"\n",
                    "            echo \"        - to: ${prefix}.0/16\"\n",
                    "            echo \"          via: ${prefix}.${GW_ADDR}\"\n",
                    "            echo \"        - to: ${SUB_PREFIXES[0,$sw_plane]}.0/13\"\n",
                    "            echo \"          via: ${prefix}.${GW_ADDR}\"\n",
                    "        done\n",
                    "    done\n",
                    "} > \"$NETPLAN_FILE\"\n",
                    "\n",
                    "netplan apply\n",
                )
                .to_string(),
            ),
            r#type: None,
        },
    ];

    if let Some(proxy) = proxy {
        validate_proxy_string(&proxy.https_proxy, "https_proxy")?;

        let mut raw = format!(
            "[Service]\nEnvironment=\"HTTPS_PROXY={0}\"\nEnvironment=\"https_proxy={0}\"\n",
            proxy.https_proxy
        );
        let mut entries: Vec<&str> = proxy
            .no_proxy
            .iter()
            .map(|e| e.trim())
            .filter(|e| !e.is_empty())
            .collect();
        if !entries.is_empty() {
            for entry in &entries {
                validate_proxy_string(entry, "no_proxy entry")?;
            }
            entries.sort_unstable();
            entries.dedup();
            let no_proxy = entries.join(",");
            raw.push_str(&format!(
                "Environment=\"NO_PROXY={0}\"\nEnvironment=\"no_proxy={0}\"\n",
                no_proxy
            ));
        }
        config_files.push(DpuFlavorConfigFiles {
            path: "/etc/systemd/system/containerd.service.d/socks-proxy.conf".to_string(),
            operation: Some(DpuFlavorConfigFilesOperation::Override),
            permissions: Some("0644".to_string()),
            raw: Some(raw),
            content_from: None,
            r#type: None,
        });
    }

    Ok(config_files)
}

fn get_default_nvconfig() -> DpuFlavorNvconfig {
    let parameters = vec![
        "PF_BAR2_ENABLE=0".to_string(),
        "PER_PF_NUM_SF=1".to_string(),
        "PF_TOTAL_SF=30".to_string(),
        "PF_SF_BAR_SIZE=10".to_string(),
        "NUM_PF_MSIX_VALID=0".to_string(),
        "PF_NUM_PF_MSIX_VALID=1".to_string(),
        "PF_NUM_PF_MSIX=228".to_string(),
        "INTERNAL_CPU_MODEL=1".to_string(),
        "INTERNAL_CPU_OFFLOAD_ENGINE=0".to_string(),
        "SRIOV_EN=1".to_string(),
        "LAG_RESOURCE_ALLOCATION=1".to_string(),
        "NUM_OF_VFS=16".to_string(),
        "HIDE_PORT2_PF=True".to_string(),
        "NUM_OF_PF=1".to_string(),
        "LINK_TYPE_P1=ETH".to_string(),
        "LINK_TYPE_P2=ETH".to_string(),
    ];

    DpuFlavorNvconfig {
        // DPF does not allow anyother wild card. It takes only '*'
        device: Some(DpuFlavorNvconfigDevice::KopiumVariant0), //"*"
        parameters: Some(parameters),
    }
}

fn get_bf4_astra_nvconfig() -> DpuFlavorNvconfig {
    let parameters = vec![
        "PF_BAR2_ENABLE=0".to_string(),
        "PER_PF_NUM_SF=1".to_string(),
        "PF_TOTAL_SF=30".to_string(),
        "PF_SF_BAR_SIZE=14".to_string(),
        "NUM_PF_MSIX_VALID=0".to_string(),
        "PF_NUM_PF_MSIX_VALID=1".to_string(),
        "PF_NUM_PF_MSIX=228".to_string(),
        "INTERNAL_CPU_MODEL=1".to_string(),
        "INTERNAL_CPU_OFFLOAD_ENGINE=0".to_string(),
        "SRIOV_EN=1".to_string(),
        "NUM_OF_VFS=46".to_string(),
        "LAG_RESOURCE_ALLOCATION=1".to_string(),
        "LINK_TYPE_P1=ETH".to_string(),
        "LINK_TYPE_P2=ETH".to_string(),
    ];

    DpuFlavorNvconfig {
        // DPF does not allow anyother wild card. It takes only '*'
        device: Some(DpuFlavorNvconfigDevice::KopiumVariant0), //"*"
        parameters: Some(parameters),
    }
}

/// DHCP ACL rules: drop DHCP broadcasts from host-facing interfaces.
fn dhcp_acl_rules() -> String {
    let mut rules = String::from("[iptables]\n");
    for iface in
        std::iter::once("pf0hpf_if".to_string()).chain((0..=15).map(|i| format!("pf0vf{i}_if")))
    {
        rules.push_str(&format!(
            "-t filter -A FORWARD -p udp -d 255.255.255.255 \
             --dport 67 -m physdev --physdev-in {iface} \
             -m comment --comment 'offload:0' -j DROP\n"
        ));
    }
    rules
}

#[cfg(test)]
mod tests {
    use carbide_test_support::Outcome::*;
    use carbide_test_support::{Case, check_cases, scenarios, value_scenarios};

    use super::*;
    use crate::types::DpfProxyDetails;

    fn proxy(https_proxy: &str, no_proxy: &[&str]) -> Option<DpfProxyDetails> {
        Some(DpfProxyDetails {
            https_proxy: https_proxy.to_string(),
            no_proxy: no_proxy.iter().map(|s| s.to_string()).collect(),
        })
    }

    /// The `raw` body of the trailing (proxy) config file built by `default_flavor`.
    fn proxy_file_raw(https_proxy: &str, no_proxy: &[&str]) -> String {
        let flavor = default_flavor("ns", &proxy(https_proxy, no_proxy)).unwrap();
        let files = flavor.spec.config_files.unwrap();
        files.last().unwrap().raw.clone().unwrap()
    }

    /// `unique_name` of the default flavor for the given proxy, with the standard prefix.
    fn name_for(proxy: &Option<DpfProxyDetails>) -> String {
        default_flavor("ns", proxy)
            .unwrap()
            .unique_name("dpu-flavor")
            .unwrap()
    }

    // ── validate_proxy_string ──────────────────────────────────────────────
    //
    // The pure validator at the heart of the proxy path. `DpfError` is not
    // `PartialEq`, so error rows use `Fails` (with `.map_err(drop)`).

    #[test]
    fn validate_proxy_string_accepts_and_rejects() {
        scenarios!(
            run = |value| validate_proxy_string(value, "field").map_err(drop);
            "typical proxy url" {
                "http://proxy.corp.example.com:3128" => Yields(()),
            }

            "empty string" {
                "" => Yields(()),
            }

            "cidr no_proxy entry" {
                "10.0.0.0/8" => Yields(()),
            }

            "hostname no_proxy entry" {
                "localhost" => Yields(()),
            }

            "dns suffix no_proxy entry" {
                ".svc.cluster.local" => Yields(()),
            }

            "high ascii printable is allowed" {
                "host~name" => Yields(()),
            }

            "space is allowed (>= 0x20, not quote/control)" {
                "has space" => Yields(()),
            }

            "tilde 0x7e is the last printable allowed" {
                "~" => Yields(()),
            }

            "double quote rejected" {
                "http://proxy:3128/\"evil" => Fails,
            }

            "newline rejected" {
                "http://proxy:3128\nEvil: injected" => Fails,
            }

            "carriage return rejected" {
                "http://proxy:3128\rinjected" => Fails,
            }

            "tab (control char) rejected" {
                "http://proxy:3128\tx" => Fails,
            }

            "null byte rejected" {
                "10.0.0.0/8\x00bad" => Fails,
            }

            "0x01 control char rejected" {
                "10.0.0.0/8\x01bad" => Fails,
            }

            "0x1f (last control below 0x20) rejected" {
                "x\x1fy" => Fails,
            }

            "DEL 0x7f rejected" {
                "x\x7fy" => Fails,
            }
        );
    }

    #[test]
    fn validate_proxy_string_error_names_the_field() {
        // The rejected-string error message mentions the field name passed in.
        scenarios!(
            run = |(value, field, tokens): (&str, &str, &[&str])| {
                let msg = match validate_proxy_string(value, field) {
                    Err(crate::error::DpfError::ConfigError(m)) => m,
                    other => return Err(format!("expected ConfigError, got {other:?}")),
                };
                Ok(tokens.iter().all(|t| msg.contains(t)))
            };
            "field name appears in the error" {
                ("\"", "https_proxy", &["https_proxy", "systemd"][..]) => Yields(true),
            }

            "no_proxy field name appears in the error" {
                ("\n", "no_proxy entry", &["no_proxy entry"][..]) => Yields(true),
            }
        );
    }

    // ── default_flavor: proxy validation flows through ─────────────────────

    #[test]
    fn default_flavor_accepts_or_rejects_proxy() {
        scenarios!(
            run = |p| default_flavor("ns", &p).map(drop).map_err(drop);
            "no proxy" {
                None => Yields(()),
            }

            "typical proxy with no_proxy list" {
                proxy(
                    "http://proxy.corp.example.com:3128",
                    &["10.0.0.0/8", "localhost", ".svc.cluster.local"],
                ) => Yields(()),
            }

            "proxy with empty no_proxy" {
                proxy("http://proxy:3128", &[]) => Yields(()),
            }

            "https_proxy with quote rejected" {
                proxy("http://proxy:3128/\"evil", &[]) => Fails,
            }

            "https_proxy with newline rejected" {
                proxy("http://proxy:3128\nEvil: injected", &[]) => Fails,
            }

            "https_proxy with carriage return rejected" {
                proxy("http://proxy:3128\rx", &[]) => Fails,
            }

            "no_proxy entry with control char rejected" {
                proxy("http://proxy:3128", &["10.0.0.0/8\x01bad"]) => Fails,
            }

            "no_proxy entry with DEL rejected" {
                proxy("http://proxy:3128", &["ok", "bad\x7f"]) => Fails,
            }

            "blank/whitespace-only no_proxy entries are skipped, not rejected" {
                proxy("http://proxy:3128", &["", "  ", "\t"]) => Yields(()),
            }
        );
    }

    // ── default_flavor: structural getters ─────────────────────────────────

    #[test]
    fn default_flavor_namespace_is_passed_through() {
        value_scenarios!(
            run = |ns| default_flavor(ns, &None).unwrap().metadata.namespace;
            "plain namespace" {
                "my-ns" => Some("my-ns".to_string()),
            }

            "empty namespace is still set verbatim" {
                "" => Some(String::new()),
            }

            "namespace with hyphens" {
                "dpf-system-test" => Some("dpf-system-test".to_string()),
            }
        );
    }

    #[test]
    fn default_flavor_metadata_name_is_always_none() {
        // The caller must set the name via unique_name(); the builder leaves it unset.
        value_scenarios!(
            run = |p| default_flavor("ns", &p).unwrap().metadata.name.is_none();
            "no proxy" {
                None => true,
            }

            "with proxy" {
                proxy("http://proxy:3128", &["localhost"]) => true,
            }
        );
    }

    #[test]
    fn default_flavor_spec_invariants() {
        // Structural shape of the default spec that callers depend on.
        let flavor = default_flavor("ns", &None).unwrap();
        value_scenarios!(
            run = |present| present;
            "dpu_mode is ZeroTrust" {
                matches!(flavor.spec.dpu_mode, Some(DpuFlavorDpuMode::ZeroTrust)) => true,
            }

            "bfcfg has three parameters" {
                flavor.spec.bfcfg_parameters.as_ref().map(|v| v.len()) == Some(3) => true,
            }

            "exactly one nvconfig entry" {
                flavor.spec.nvconfig.as_ref().map(|v| v.len()) == Some(1) => true,
            }

            "ovs raw config script is present" {
                flavor
                .spec
                .ovs
                .as_ref()
                .and_then(|o| o.raw_config_script.as_ref())
                .is_some() => true,
            }

            "dpu_resources unset" {
                flavor.spec.dpu_resources.is_none() => true,
            }

            "containerd_config unset" {
                flavor.spec.containerd_config.is_none() => true,
            }
        );
    }

    #[test]
    fn bf4_astra_flavor_spec_invariants() {
        let flavor = flavor_bf4_astra("astra-ns", &None).unwrap();
        let ew_nic = flavor
            .spec
            .ew_nic_configurations
            .as_ref()
            .and_then(|configs| configs.first())
            .unwrap();
        let spectrum_x = ew_nic.spectrum_x_optimized.as_ref().unwrap();
        let grub_parameters = flavor
            .spec
            .grub
            .as_ref()
            .and_then(|grub| grub.kernel_parameters.as_ref())
            .unwrap();
        let nvconfig_parameters = flavor
            .spec
            .nvconfig
            .as_ref()
            .and_then(|configs| configs.first())
            .and_then(|config| config.parameters.as_ref())
            .unwrap();
        let ovs_script = flavor
            .spec
            .ovs
            .as_ref()
            .and_then(|ovs| ovs.raw_config_script.as_ref())
            .unwrap();

        value_scenarios!(
            run = |valid| valid;
            "namespace is passed through and name is left unset" {
                (
                    flavor.metadata.namespace.as_deref() == Some("astra-ns")
                        && flavor.metadata.name.is_none()
                ) => true,
            }

            "deprecated generic fields are unset" {
                (
                    flavor.spec.bfcfg_parameters.is_none()
                        && flavor.spec.dpu_mode.is_none()
                ) => true,
            }

            "network bay configuration selects conf1 with one VF" {
                (
                    ew_nic.num_vfs == 1
                        && ew_nic.link_type.is_none()
                        && ew_nic
                            .network_bay
                            .as_ref()
                            .is_some_and(|network_bay| network_bay.conf == "conf1")
                ) => true,
            }

            "Spectrum-X configuration selects the Astra profile" {
                (
                    spectrum_x.enabled
                        && matches!(
                            spectrum_x.multiplane_mode.as_ref(),
                            Some(
                                DpuFlavorEwNicConfigurationsSpectrumXOptimizedMultiplaneMode::Hwplb
                            )
                        )
                        && spectrum_x.number_of_planes == Some(4)
                        && matches!(
                            spectrum_x.overlay.as_ref(),
                            Some(DpuFlavorEwNicConfigurationsSpectrumXOptimizedOverlay::None)
                        )
                        && spectrum_x.version == "RA2.2-runtime"
                ) => true,
            }

            "Astra grub parameters include fixrttc and 8072 huge pages" {
                (
                    grub_parameters.iter().any(|parameter| parameter == "fixrttc")
                        && grub_parameters
                            .iter()
                            .any(|parameter| parameter == "hugepages=8072")
                ) => true,
            }

            "Astra nvconfig requests 30 total SFs and 46 VFs" {
                (
                    nvconfig_parameters
                        .iter()
                        .any(|parameter| parameter == "PF_TOTAL_SF=30")
                        && nvconfig_parameters
                            .iter()
                            .any(|parameter| parameter == "NUM_OF_VFS=46")
                ) => true,
            }

            "OVS bootstrap invokes both Astra scripts" {
                (
                    ovs_script.contains("/etc/mellanox/ovs-script.sh")
                        && ovs_script.contains("/etc/mellanox/xplane-bridge.sh")
                ) => true,
            }

            "Spectrum-X config has the Adaptive Routing Force setting" {
                {
                    let spectrum = flavor
                        .spec
                        .config_files
                        .as_ref()
                        .unwrap()
                        .iter()
                        .find(|file| file.path == "/bindata/spectrum-x/RA2.2-runtime.yaml")
                        .and_then(|file| file.raw.as_ref())
                        .unwrap();
                    serde_yaml::from_str::<serde_yaml::Value>(spectrum)
                        .ok()
                        .is_some_and(|document| {
                            let runtime = &document["runtimeConfig"];
                            runtime["adaptiveRouting"]
                                .as_sequence()
                                .is_some_and(|settings| {
                                    settings.iter().any(|setting| {
                                        setting["name"].as_str() == Some("Adaptive Routing Force")
                                            && setting["value"].as_bool() == Some(true)
                                            && setting["valueType"].as_str() == Some("bool")
                                            && setting["dmsPath"].as_str()
                                                == Some(
                                                    "/interfaces/interface/nvidia/roce/config/adaptive-routing-force",
                                                )
                                    })
                                })
                                && runtime["congestionControl"].is_sequence()
                        })
                } => true,
            }

            "xplane bridge setup diagnoses missing serial and address mappings" {
                {
                    let xplane_script = flavor
                        .spec
                        .config_files
                        .as_ref()
                        .unwrap()
                        .iter()
                        .find(|file| file.path == "/etc/mellanox/xplane-bridge.sh")
                        .and_then(|file| file.raw.as_ref())
                        .unwrap();
                    xplane_script.contains(
                        "failed to detect local DPU serial from PCI device 0002:01:00.0; cannot select rail addresses"
                    ) && xplane_script.contains(
                        "no rail address mapping for DPU serial ${LOCAL_SERIAL}; NODE_ADDR=${NODE_ADDR:-unset} GW_ADDR=${GW_ADDR:-unset}"
                    )
                } => true,
            }

            "empty containerd/sysctl/packages/systemdServices placeholders are set" {
                (
                    flavor.spec.containerd_config.is_some()
                        && flavor
                            .spec
                            .sysctl
                            .as_ref()
                            .is_some_and(|sysctl| {
                                sysctl.parameters.as_ref().is_some_and(Vec::is_empty)
                            })
                        && flavor
                            .spec
                            .packages
                            .as_ref()
                            .is_some_and(Vec::is_empty)
                        && flavor
                            .spec
                            .systemd_services
                            .as_ref()
                            .is_some_and(Vec::is_empty)
                ) => true,
            }

            "ewNic rawNvConfig has correct programmable CC and locality mode" {
                {
                    let raw = ew_nic.raw_nv_config.as_ref().unwrap();
                    let programmable_cc = raw.iter().find(|entry| {
                        entry.name == "USER_PROGRAMMABLE_CC"
                    });
                    let locality = raw.iter().find(|entry| {
                        entry.name == "TX_SCHEDULER_LOCALITY_MODE"
                    });
                    raw.iter()
                        .filter(|entry| entry.name == "ROCE_ADAPTIVE_ROUTING_EN")
                        .count()
                        == 1
                        && programmable_cc.is_some_and(|entry| entry.value == "1")
                        && locality.is_some_and(|entry| entry.value == "2")
                } => true,
            }
        );
    }

    #[test]
    fn bf4_astra_proxy_config_file_count() {
        value_scenarios!(
            run = |p| {
                let files = flavor_bf4_astra("astra-ns", &p)
                    .unwrap()
                    .spec
                    .config_files
                    .unwrap();
                let proxy_file_count = files
                    .iter()
                    .filter(|file| {
                        file.path
                            == "/etc/systemd/system/containerd.service.d/socks-proxy.conf"
                    })
                    .count();
                (files.len(), proxy_file_count)
            };
            "no proxy keeps only the six Astra base files" {
                None => (6, 0),
            }

            "configured proxy appends exactly one proxy file" {
                proxy("http://proxy:3128", &["10.0.0.0/8", "localhost"]) => (7, 1),
            }
        );
    }

    // ── get_config_files: count and trailing-file fields ───────────────────

    #[test]
    fn config_file_count_depends_on_proxy() {
        value_scenarios!(
            run = |p| {
                default_flavor("ns", &p)
                    .unwrap()
                    .spec
                    .config_files
                    .unwrap()
                    .len()
            };
            "no proxy yields seven base files" {
                None => 7,
            }

            "proxy with empty no_proxy appends an eighth" {
                proxy("http://proxy:3128", &[]) => 8,
            }

            "proxy with no_proxy list still appends exactly one" {
                proxy("http://proxy:3128", &["10.0.0.0/8", "localhost"]) => 8,
            }
        );
    }

    #[test]
    fn proxy_file_fields_are_fixed() {
        // path, permissions, operation of the trailing proxy drop-in.
        let flavor = default_flavor("ns", &proxy("http://proxy:3128", &[])).unwrap();
        let files = flavor.spec.config_files.unwrap();
        let f = files.last().unwrap();
        value_scenarios!(
            run = |ok| ok;
            "path" {
                f.path == "/etc/systemd/system/containerd.service.d/socks-proxy.conf" => true,
            }

            "permissions 0644" {
                f.permissions.as_deref() == Some("0644") => true,
            }

            "override operation" {
                matches!(f.operation, Some(DpuFlavorConfigFilesOperation::Override)) => true,
            }
        );
    }

    #[test]
    fn base_config_file_paths_are_present() {
        // The seven base files always exist regardless of proxy, with these paths.
        let files = default_flavor("ns", &None)
            .unwrap()
            .spec
            .config_files
            .unwrap();
        let paths: Vec<String> = files.iter().map(|f| f.path.clone()).collect();
        value_scenarios!(
            run = |path| paths.contains(&path.to_string());
            "acltool.conf" {
                "/var/lib/hbn/etc/supervisor/conf.d/acltool.conf" => true,
            }

            "10-dhcp.rules" {
                "/var/lib/hbn/etc/cumulus/acl/policy.d/10-dhcp.rules" => true,
            }

            "lldp-interfaces.conf" {
                "/etc/lldpd.d/lldp-interfaces.conf" => true,
            }

            "lldpd defaults" {
                "/etc/default/lldpd" => true,
            }

            "mlnx-bf.conf" {
                "/etc/mellanox/mlnx-bf.conf" => true,
            }

            "mlnx-ovs.conf" {
                "/etc/mellanox/mlnx-ovs.conf" => true,
            }

            "mlnx-sf.conf" {
                "/etc/mellanox/mlnx-sf.conf" => true,
            }
        );
    }

    #[test]
    fn lldp_config_file_contents_are_fixed() {
        let files = default_flavor("ns", &None)
            .unwrap()
            .spec
            .config_files
            .unwrap();
        value_scenarios!(
            run = |(path, expected_raw): (&str, &str)| {
                files.iter().find(|file| file.path == path).is_some_and(|file| {
                    matches!(file.operation, Some(DpuFlavorConfigFilesOperation::Override))
                        && file.permissions.as_deref() == Some("0644")
                        && file.raw.as_deref() == Some(expected_raw)
                        && file.content_from.is_none()
                        && file.r#type.is_none()
                })
            };
            "LLDP interface pattern permits every interface" {
                (
                    "/etc/lldpd.d/lldp-interfaces.conf",
                    "configure system interface pattern *\n",
                ) => true,
            }

            "lldpd enables LLDP-MED inventory" {
                ("/etc/default/lldpd", "DAEMON_ARGS=\"-M 1\"\n") => true,
            }
        );
    }

    // ── proxy drop-in raw body content ─────────────────────────────────────
    //
    // `.contains(...)` substring checks folded into (value, &[tokens]) rows.

    #[test]
    fn proxy_raw_contains_expected_tokens() {
        check_cases(
            [Case {
                scenario: "uppercase and lowercase HTTPS_PROXY env set under [Service]",
                input: (
                    proxy_file_raw("http://proxy.example.com:3128", &[]),
                    &[
                        "[Service]",
                        "HTTPS_PROXY=http://proxy.example.com:3128",
                        "https_proxy=http://proxy.example.com:3128",
                    ][..],
                ),
                expect: Yields(true),
            }],
            |(raw, tokens): (String, &[&str])| Ok::<_, ()>(tokens.iter().all(|t| raw.contains(t))),
        );
    }

    #[test]
    fn proxy_raw_no_proxy_handling() {
        // When no_proxy is empty the NO_PROXY env lines are omitted; when set they
        // appear sorted+deduped. Each row: (raw body, tokens that must all appear).
        check_cases(
            [
                Case {
                    scenario: "no_proxy lines present, sorted and deduped",
                    input: (
                        proxy_file_raw(
                            "http://proxy:3128",
                            &["localhost", "10.0.0.0/8", "10.0.0.0/8"],
                        ),
                        &[
                            "NO_PROXY=10.0.0.0/8,localhost",
                            "no_proxy=10.0.0.0/8,localhost",
                        ][..],
                    ),
                    expect: Yields(true),
                },
                Case {
                    scenario: "single no_proxy entry",
                    input: (
                        proxy_file_raw("http://proxy:3128", &["10.0.0.0/8"]),
                        &["NO_PROXY=10.0.0.0/8", "no_proxy=10.0.0.0/8"][..],
                    ),
                    expect: Yields(true),
                },
                Case {
                    scenario: "whitespace around entries is trimmed",
                    input: (
                        proxy_file_raw("http://proxy:3128", &["  localhost  ", " 10.0.0.0/8 "]),
                        &["NO_PROXY=10.0.0.0/8,localhost"][..],
                    ),
                    expect: Yields(true),
                },
            ],
            |(raw, tokens): (String, &[&str])| Ok::<_, ()>(tokens.iter().all(|t| raw.contains(t))),
        );
    }

    #[test]
    fn proxy_raw_omits_no_proxy_when_effectively_empty() {
        // Empty or blank-only no_proxy lists produce no NO_PROXY env lines at all.
        value_scenarios!(
            run = |raw| raw.contains("NO_PROXY") || raw.contains("no_proxy");
            "empty list" {
                proxy_file_raw("http://proxy:3128", &[]) => false,
            }

            "blank and whitespace-only entries are filtered out" {
                proxy_file_raw("http://proxy:3128", &["", "   ", "\t"]) => false,
            }
        );
    }

    // ── unique_name ────────────────────────────────────────────────────────

    #[test]
    fn unique_name_has_expected_format() {
        // "<prefix>-<16 lowercase hex chars>" for several prefixes.
        scenarios!(
            run = |prefix: &str| {
                let flavor = default_flavor("ns", &None).map_err(drop)?;
                let name = flavor.unique_name(prefix).map_err(drop)?;
                let (got_prefix, hash) = name.rsplit_once('-').ok_or(())?;
                Ok::<bool, ()>(
                    got_prefix == prefix
                        && hash.len() == 16
                        && hash
                            .chars()
                            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()),
                )
            };
            "standard prefix" {
                "dpu-flavor" => Yields(true),
            }

            "empty prefix still yields prefix-<hash>" {
                "" => Yields(true),
            }

            "prefix containing hyphens" {
                "a-b-c" => Yields(true),
            }
        );
    }

    #[test]
    fn unique_name_equality_across_specs() {
        // true  => the two specs hash to the same name (stable / order- & dup-insensitive)
        // false => the specs differ, so the names must differ
        value_scenarios!(
            run = |(a, b)| a == b;
            "deterministic for identical specs" {
                (name_for(&None), name_for(&None)) => true,
            }

            "no_proxy order does not affect the name" {
                (
                    name_for(&proxy("http://proxy:3128", &["localhost", "10.0.0.0/8"])),
                    name_for(&proxy("http://proxy:3128", &["10.0.0.0/8", "localhost"])),
                ) => true,
            }

            "duplicate no_proxy entries do not affect the name" {
                (
                    name_for(&proxy("http://proxy:3128", &["10.0.0.0/8"])),
                    name_for(&proxy("http://proxy:3128", &["10.0.0.0/8", "10.0.0.0/8"])),
                ) => true,
            }

            "adding a proxy changes the name" {
                (name_for(&None), name_for(&proxy("http://proxy:3128", &[]))) => false,
            }

            "extending the no_proxy list changes the name" {
                (
                    name_for(&proxy("http://proxy:3128", &["10.0.0.0/8"])),
                    name_for(&proxy("http://proxy:3128", &["10.0.0.0/8", "localhost"])),
                ) => false,
            }

            "changing the https_proxy url changes the name" {
                (
                    name_for(&proxy("http://a:3128", &[])),
                    name_for(&proxy("http://b:3128", &[])),
                ) => false,
            }
        );
    }

    #[test]
    fn unique_name_prefix_changes_the_output() {
        // The same spec under different prefixes yields different names.
        let flavor = default_flavor("ns", &None).unwrap();
        value_scenarios!(
            run = |(a, b)| a == b;
            "different prefixes differ" {
                (
                    flavor.unique_name("a").unwrap(),
                    flavor.unique_name("b").unwrap(),
                ) => false,
            }

            "same prefix matches" {
                (
                    flavor.unique_name("x").unwrap(),
                    flavor.unique_name("x").unwrap(),
                ) => true,
            }
        );
    }

    // ── dhcp_acl_rules (pure formatter) ────────────────────────────────────

    #[test]
    fn dhcp_acl_rules_shape() {
        let rules = dhcp_acl_rules();
        value_scenarios!(
            run = |v| v;
            "starts with the iptables header" {
                rules.starts_with("[iptables]\n") => true,
            }

            "covers the host-facing pf0hpf interface" {
                rules.contains("--physdev-in pf0hpf_if ") => true,
            }

            "covers vf0" {
                rules.contains("--physdev-in pf0vf0_if ") => true,
            }

            "covers vf15 (last in range)" {
                rules.contains("--physdev-in pf0vf15_if ") => true,
            }

            "does not over-run to vf16" {
                rules.contains("pf0vf16_if") => false,
            }

            "header line plus 17 rule lines (hpf + vf0..15)" {
                rules.lines().count() == 18 => true,
            }

            "every rule drops DHCP broadcast to .255" {
                rules.matches("-d 255.255.255.255").count() == 17 => true,
            }
        );
    }

    // ── get_default_ovs_defaults (pure formatter) ──────────────────────────

    #[test]
    fn ovs_defaults_contains_key_lines() {
        check_cases(
            [Case {
                scenario: "doca/offload/br-sfc setup lines present",
                input: (
                    get_default_ovs_defaults(),
                    &[
                        "other_config:doca-init=true",
                        "other_config:hw-offload=true",
                        "add-br br-sfc",
                        "datapath_type=netdev",
                        "type=dpdk",
                        "mtu_request=9216",
                    ][..],
                ),
                expect: Yields(true),
            }],
            |(raw, tokens): (String, &[&str])| Ok::<_, ()>(tokens.iter().all(|t| raw.contains(t))),
        );
    }

    // ── get_default_nvconfig (pure constructor) ────────────────────────────

    #[test]
    fn default_nvconfig_shape() {
        let nv = get_default_nvconfig();
        value_scenarios!(
            run = |v| v;
            "device is the only allowed wildcard variant" {
                matches!(nv.device, Some(DpuFlavorNvconfigDevice::KopiumVariant0)) => true,
            }

            "parameter count" {
                nv.parameters.as_ref().map(|p| p.len()) == Some(16) => true,
            }

            "carries the SRIOV enable flag" {
                nv
                .parameters
                .as_ref()
                .map(|p| p.iter().any(|s| s == "SRIOV_EN=1"))
                == Some(true) => true,
            }

            "carries NUM_OF_VFS=16" {
                nv
                .parameters
                .as_ref()
                .map(|p| p.iter().any(|s| s == "NUM_OF_VFS=16"))
                == Some(true) => true,
            }
        );
    }
}
