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

use crate::crds::dpuflavors_generated::{
    DPUFlavor, DpuFlavorConfigFiles, DpuFlavorConfigFilesOperation, DpuFlavorDpuMode,
    DpuFlavorNvconfig, DpuFlavorSpec,
};

pub const DEFAULT_FLAVOR_NAME: &str = "dpu-flavor";

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

/// Build the default DPUFlavor CR.
pub fn default_flavor(namespace: &str, name: &str) -> DPUFlavor {
    let bfcfg_parameters = vec![
        "ENABLE_BR_HBN=yes".to_string(),
        "ENABLE_BR_SFC=yes".to_string(),
        "UPDATE_ATF_UEFI=yes".to_string(),
        "UPDATE_DPU_OS=yes".to_string(),
        "WITH_NIC_FW_UPDATE=yes".to_string(),
    ];
    DPUFlavor {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            ..Default::default()
        },
        spec: DpuFlavorSpec {
            dpu_mode: Some(DpuFlavorDpuMode::ZeroTrust),
            dpu_resources: None,
            bfcfg_parameters: Some(bfcfg_parameters),
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
                    raw: Some(
                        concat!("CREATE_OVS_BRIDGES=\"no\"\n", "OVS_DOCA=\"yes\"\n").to_string(),
                    ),
                },
                DpuFlavorConfigFiles {
                    path: Some("/etc/mellanox/mlnx-sf.conf".to_string()),
                    operation: Some(DpuFlavorConfigFilesOperation::Override),
                    permissions: Some("0644".to_string()),
                    raw: Some("".to_string()),
                },
            ]),
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
    }
}

fn get_default_nvconfig() -> DpuFlavorNvconfig {
    let parameters = vec![
        "PF_BAR2_ENABLE=0".to_string(),
        "PER_PF_NUM_SF=1".to_string(),
        "PF_TOTAL_SF=20".to_string(),
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
        device: Some("*".to_string()),
        host_power_cycle_required: None,
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
