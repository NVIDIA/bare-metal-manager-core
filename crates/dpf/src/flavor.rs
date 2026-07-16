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
    DPUFlavor, DpuFlavorConfigFiles, DpuFlavorConfigFilesOperation, DpuFlavorDpuMode,
    DpuFlavorGrub, DpuFlavorNvconfig, DpuFlavorNvconfigDevice, DpuFlavorSpec,
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
        "   ovs-vsctl --no-wait --timeout 15 \"$@\"\n",
        " }\n",
        "_ovs-vsctl set Open_vSwitch . other_config:doca-init=true\n",
        "_ovs-vsctl set Open_vSwitch . other_config:dpdk-max-memzones=50000\n",
        "_ovs-vsctl set Open_vSwitch . other_config:hw-offload=true\n",
        "_ovs-vsctl set Open_vSwitch . other_config:pmd-quiet-idle=true\n",
        "_ovs-vsctl set Open_vSwitch . other_config:max-idle=20000\n",
        "_ovs-vsctl set Open_vSwitch . other_config:max-revalidator=5000\n",
        "_ovs-vsctl set Open_vSwitch . other_config:ctl-pipe-size=1024\n",
        "_ovs-vsctl --if-exists del-br ovsbr1\n",
        "_ovs-vsctl --if-exists del-br ovsbr2\n",
        "_ovs-vsctl --may-exist add-br br-sfc\n",
        "_ovs-vsctl set bridge br-sfc datapath_type=netdev\n",
        "_ovs-vsctl set bridge br-sfc fail_mode=secure\n",
        "_ovs-vsctl --may-exist add-port br-sfc p0\n",
        "_ovs-vsctl set Interface p0 type=dpdk\n",
        "_ovs-vsctl set Interface p0 mtu_request=9216\n",
        "_ovs-vsctl set Port p0 external_ids:dpf-type=physical\n",
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
            grub: None,
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
        },
    })
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
    // TODO: HIDE_PORT2_PF is not supported, so reoving it for now.
    // We need to find the equivalent field in Bf4 and configure it again.
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
        "LINK_TYPE_P1=2".to_string(),
        "LINK_TYPE_P2=2".to_string(),
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
            "no proxy yields five base files" {
                None => 5,
            }

            "proxy with empty no_proxy appends a sixth" {
                proxy("http://proxy:3128", &[]) => 6,
            }

            "proxy with no_proxy list still appends exactly one" {
                proxy("http://proxy:3128", &["10.0.0.0/8", "localhost"]) => 6,
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
        // The five base files always exist regardless of proxy, with these paths.
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
