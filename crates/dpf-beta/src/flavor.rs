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

//! DPUFlavor configuration for HBN.

use kube::core::ObjectMeta;

use crate::crds::dpuflavors_generated::{
    DPUFlavor, DpuFlavorConfigFiles, DpuFlavorConfigFilesOperation, DpuFlavorDpuMode, DpuFlavorSpec,
};

pub const DPUFLAVOR_NAME: &str = "carbide-dpu-flavor";

/// Build the default DPUFlavor CR for Carbide.
pub fn default_flavor(namespace: &str) -> DPUFlavor {
    DPUFlavor {
        metadata: ObjectMeta {
            name: Some(DPUFLAVOR_NAME.to_string()),
            namespace: Some(namespace.to_string()),
            ..Default::default()
        },
        spec: DpuFlavorSpec {
            dpu_mode: Some(DpuFlavorDpuMode::ZeroTrust),
            dpu_resources: None,
            bfcfg_parameters: None,
            config_files: Some(vec![
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
                    path: Some("/etc/sysctl.d/98-hbn.conf".to_string()),
                    operation: Some(DpuFlavorConfigFilesOperation::Override),
                    permissions: Some("0644".to_string()),
                    raw: Some(
                        concat!(
                            "net.ipv6.conf.all.forwarding = 1\n",
                            "kernel.shmmax = 4294967296\n",
                            "vm.nr_hugepages=2048\n",
                            "vm.min_free_kbytes=67584\n",
                        )
                        .to_string(),
                    ),
                },
            ]),
            containerd_config: None,
            grub: None,
            host_network_interface_configs: None,
            nvconfig: None,
            ovs: None,
            sysctl: None,
            system_reserved_resources: None,
        },
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
