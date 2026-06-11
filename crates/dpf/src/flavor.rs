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
    DpuFlavorNvconfig, DpuFlavorNvconfigDevice, DpuFlavorSpec,
};
use crate::types::DpfProxyDetails;

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
        },
    })
}

/// Returns the base set of config files, plus an optional containerd proxy drop-in if `proxy` is set.
fn get_config_files(
    proxy: &Option<DpfProxyDetails>,
) -> Result<Vec<DpuFlavorConfigFiles>, crate::error::DpfError> {
    let mut config_files = vec![
        DpuFlavorConfigFiles {
            path: Some("/var/lib/hbn/etc/supervisor/conf.d/acltool.conf".to_string()),
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
        },
        DpuFlavorConfigFiles {
            path: Some("/var/lib/hbn/etc/cumulus/acl/policy.d/10-dhcp.rules".to_string()),
            operation: Some(DpuFlavorConfigFilesOperation::Override),
            permissions: Some("0644".to_string()),
            raw: Some(dhcp_acl_rules()),
        },
        DpuFlavorConfigFiles {
            path: Some("/etc/mellanox/mlnx-bf.conf".to_string()),
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
        },
        DpuFlavorConfigFiles {
            path: Some("/etc/mellanox/mlnx-ovs.conf".to_string()),
            operation: Some(DpuFlavorConfigFilesOperation::Override),
            permissions: Some("0644".to_string()),
            raw: Some(concat!("CREATE_OVS_BRIDGES=\"no\"\n", "OVS_DOCA=\"yes\"\n").to_string()),
        },
        DpuFlavorConfigFiles {
            path: Some("/etc/mellanox/mlnx-sf.conf".to_string()),
            operation: Some(DpuFlavorConfigFilesOperation::Override),
            permissions: Some("0644".to_string()),
            raw: Some("".to_string()),
        },
    ];

    if let Some(proxy) = proxy {
        validate_proxy_string(&proxy.https_proxy, "https_proxy")?;

        let mut raw = format!(
            "[Service]\nEnvironment=\"HTTPS_PROXY={0}\"\nEnvironment=\"https_proxy={0}\"\n",
            proxy.https_proxy
        );
        if !proxy.no_proxy.is_empty() {
            let mut entries: Vec<&str> = proxy
                .no_proxy
                .iter()
                .map(|e| e.trim())
                .filter(|e| !e.is_empty())
                .collect();
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
            path: Some("/etc/systemd/system/containerd.service.d/socks-proxy.conf".to_string()),
            operation: Some(DpuFlavorConfigFilesOperation::Override),
            permissions: Some("0644".to_string()),
            raw: Some(raw),
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
    use super::*;
    use crate::types::DpfProxyDetails;

    fn proxy(https_proxy: &str, no_proxy: &[&str]) -> Option<DpfProxyDetails> {
        Some(DpfProxyDetails {
            https_proxy: https_proxy.to_string(),
            no_proxy: no_proxy.iter().map(|s| s.to_string()).collect(),
        })
    }

    // ── unique_name ────────────────────────────────────────────────────────

    #[test]
    fn unique_name_has_expected_format() {
        let flavor = default_flavor("ns", &None).unwrap();
        let name = flavor.unique_name("dpu-flavor").unwrap();
        // "<prefix>-<16 lowercase hex chars>"
        let (prefix, hash) = name.rsplit_once('-').expect("name contains '-'");
        assert_eq!(prefix, "dpu-flavor");
        assert_eq!(hash.len(), 16);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn unique_name_is_deterministic() {
        let f1 = default_flavor("ns", &None).unwrap();
        let f2 = default_flavor("ns", &None).unwrap();
        assert_eq!(
            f1.unique_name("dpu-flavor").unwrap(),
            f2.unique_name("dpu-flavor").unwrap()
        );
    }

    #[test]
    fn unique_name_changes_when_proxy_added() {
        let no_proxy = default_flavor("ns", &None).unwrap();
        let with_proxy = default_flavor("ns", &proxy("http://proxy:3128", &[])).unwrap();
        assert_ne!(
            no_proxy.unique_name("dpu-flavor").unwrap(),
            with_proxy.unique_name("dpu-flavor").unwrap()
        );
    }

    #[test]
    fn unique_name_changes_when_no_proxy_list_changes() {
        let p1 = default_flavor("ns", &proxy("http://proxy:3128", &["10.0.0.0/8"])).unwrap();
        let p2 = default_flavor(
            "ns",
            &proxy("http://proxy:3128", &["10.0.0.0/8", "localhost"]),
        )
        .unwrap();
        assert_ne!(
            p1.unique_name("dpu-flavor").unwrap(),
            p2.unique_name("dpu-flavor").unwrap()
        );
    }

    #[test]
    fn unique_name_stable_regardless_of_no_proxy_order() {
        let p1 = default_flavor(
            "ns",
            &proxy("http://proxy:3128", &["localhost", "10.0.0.0/8"]),
        )
        .unwrap();
        let p2 = default_flavor(
            "ns",
            &proxy("http://proxy:3128", &["10.0.0.0/8", "localhost"]),
        )
        .unwrap();
        assert_eq!(
            p1.unique_name("dpu-flavor").unwrap(),
            p2.unique_name("dpu-flavor").unwrap(),
            "no_proxy order must not affect the flavor name"
        );
    }

    #[test]
    fn unique_name_stable_with_duplicate_no_proxy_entries() {
        let p1 = default_flavor("ns", &proxy("http://proxy:3128", &["10.0.0.0/8"])).unwrap();
        let p2 = default_flavor(
            "ns",
            &proxy("http://proxy:3128", &["10.0.0.0/8", "10.0.0.0/8"]),
        )
        .unwrap();
        assert_eq!(
            p1.unique_name("dpu-flavor").unwrap(),
            p2.unique_name("dpu-flavor").unwrap(),
            "duplicate no_proxy entries must not affect the flavor name"
        );
    }

    #[test]
    fn proxy_config_file_no_proxy_entries_are_sorted_and_deduped() {
        let flavor = default_flavor(
            "ns",
            &proxy(
                "http://proxy:3128",
                &["localhost", "10.0.0.0/8", "10.0.0.0/8"],
            ),
        )
        .unwrap();
        let files = flavor.spec.config_files.unwrap();
        let raw = files.last().unwrap().raw.as_deref().unwrap();
        assert!(
            raw.contains("NO_PROXY=10.0.0.0/8,localhost"),
            "no_proxy must be sorted and deduped; got: {raw}"
        );
    }

    // ── default_flavor ─────────────────────────────────────────────────────

    #[test]
    fn default_flavor_metadata_name_is_none() {
        let flavor = default_flavor("test-ns", &None).unwrap();
        assert!(
            flavor.metadata.name.is_none(),
            "name must be set by the caller via unique_name()"
        );
    }

    #[test]
    fn default_flavor_namespace_is_set() {
        let flavor = default_flavor("my-ns", &None).unwrap();
        assert_eq!(flavor.metadata.namespace.as_deref(), Some("my-ns"));
    }

    // ── get_config_files ───────────────────────────────────────────────────

    #[test]
    fn no_proxy_yields_five_config_files() {
        let flavor = default_flavor("ns", &None).unwrap();
        let files = flavor.spec.config_files.unwrap();
        assert_eq!(files.len(), 5);
    }

    #[test]
    fn proxy_appends_sixth_config_file() {
        let flavor = default_flavor("ns", &proxy("http://proxy:3128", &[])).unwrap();
        let files = flavor.spec.config_files.unwrap();
        assert_eq!(files.len(), 6);
    }

    #[test]
    fn proxy_config_file_has_correct_path() {
        let flavor = default_flavor("ns", &proxy("http://proxy:3128", &[])).unwrap();
        let files = flavor.spec.config_files.unwrap();
        let proxy_file = files.last().unwrap();
        assert_eq!(
            proxy_file.path.as_deref(),
            Some("/etc/systemd/system/containerd.service.d/socks-proxy.conf")
        );
    }

    #[test]
    fn proxy_config_file_contains_https_proxy_env() {
        let flavor = default_flavor("ns", &proxy("http://proxy.example.com:3128", &[])).unwrap();
        let files = flavor.spec.config_files.unwrap();
        let raw = files.last().unwrap().raw.as_deref().unwrap();
        assert!(raw.contains("HTTPS_PROXY=http://proxy.example.com:3128"));
        assert!(raw.contains("https_proxy=http://proxy.example.com:3128"));
    }

    #[test]
    fn proxy_config_file_omits_no_proxy_when_empty() {
        let flavor = default_flavor("ns", &proxy("http://proxy:3128", &[])).unwrap();
        let files = flavor.spec.config_files.unwrap();
        let raw = files.last().unwrap().raw.as_deref().unwrap();
        assert!(!raw.contains("NO_PROXY"));
        assert!(!raw.contains("no_proxy"));
    }

    #[test]
    fn proxy_config_file_includes_no_proxy_when_set() {
        let flavor = default_flavor(
            "ns",
            &proxy("http://proxy:3128", &["10.0.0.0/8", "localhost"]),
        )
        .unwrap();
        let files = flavor.spec.config_files.unwrap();
        let raw = files.last().unwrap().raw.as_deref().unwrap();
        assert!(raw.contains("NO_PROXY=10.0.0.0/8,localhost"));
        assert!(raw.contains("no_proxy=10.0.0.0/8,localhost"));
    }

    #[test]
    fn proxy_config_file_has_override_operation() {
        let flavor = default_flavor("ns", &proxy("http://proxy:3128", &[])).unwrap();
        let files = flavor.spec.config_files.unwrap();
        let proxy_file = files.last().unwrap();
        assert!(matches!(
            proxy_file.operation,
            Some(DpuFlavorConfigFilesOperation::Override)
        ));
        assert_eq!(proxy_file.permissions.as_deref(), Some("0644"));
    }

    // ── validate_proxy_string ──────────────────────────────────────────────

    #[test]
    fn proxy_rejected_when_https_proxy_contains_quote() {
        let err = default_flavor("ns", &proxy("http://proxy:3128/\"evil", &[])).unwrap_err();
        assert!(
            matches!(err, crate::error::DpfError::ConfigError(_)),
            "expected ConfigError, got: {err:?}"
        );
    }

    #[test]
    fn proxy_rejected_when_https_proxy_contains_newline() {
        let err =
            default_flavor("ns", &proxy("http://proxy:3128\nEvil: injected", &[])).unwrap_err();
        assert!(matches!(err, crate::error::DpfError::ConfigError(_)));
    }

    #[test]
    fn proxy_rejected_when_no_proxy_entry_contains_control_char() {
        let err =
            default_flavor("ns", &proxy("http://proxy:3128", &["10.0.0.0/8\x01bad"])).unwrap_err();
        assert!(matches!(err, crate::error::DpfError::ConfigError(_)));
    }

    #[test]
    fn proxy_accepted_with_typical_values() {
        default_flavor(
            "ns",
            &proxy(
                "http://proxy.corp.example.com:3128",
                &["10.0.0.0/8", "localhost", ".svc.cluster.local"],
            ),
        )
        .unwrap();
    }
}
