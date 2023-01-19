/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use rpc::{BlockDevice, Cpu, DiscoveryData, DiscoveryInfo, NetworkInterface, PciDeviceProperties};

pub fn create_dpu_discovery_data() -> DiscoveryData {
    let cpus: Vec<Cpu> = (0..8)
        .into_iter()
        .map(|number| Cpu {
            core: 0,
            node: 2,
            model: "0x1".to_string(),
            number,
            socket: 0,
            vendor: "0x41".to_string(),
            frequency: "400.00".to_string(),
        })
        .collect();

    let network_interfaces = vec![
        NetworkInterface {
            mac_address: "02:52:e9:bc:01:91".to_string(),
            pci_properties: Some(PciDeviceProperties {
                path: "/devices/pci0000:00/0000:00:00.0/0000:01:00.0/0000:02:00.0/0000:03:00.0/mlx5_core.sf.2/net/enp3s0f0s0".to_string(),
                device: "0xa2d6".to_string(),
                vendor: "0x15b3".to_string(),
                numa_node: 2147483647,
                description: Some("MT42822 BlueField-2 integrated ConnectX-6 Dx network controller".to_string())
            })
        },
        NetworkInterface {
            mac_address: "ch: 64".to_string(),
            pci_properties: Some(PciDeviceProperties {
                path: "/devices/pci0000:00/0000:00:00.0/0000:01:00.0/0000:02:00.0/0000:03:00.0/net/en3f0pf0sf0".to_string(),
                device: "0xa2d6".to_string(),
                vendor: "0x15b3".to_string(),
                numa_node: -1,
                description: Some("MT42822 BlueField-2 integrated ConnectX-6 Dx network controller".to_string())
            })
        },
        NetworkInterface {
            mac_address: "08:c0:eb:cb:0e:ac".to_string(),
            pci_properties: Some(PciDeviceProperties {
                path: "/devices/pci0000:00/0000:00:00.0/0000:01:00.0/0000:02:00.0/0000:03:00.0/net/p0".to_string(),
                device: "0xa2d6".to_string(),
                vendor: "0x15b3".to_string(),
                numa_node: -1,
                description: Some("MT42822 BlueField-2 integrated ConnectX-6 Dx network controller".to_string())
            })
        },
        NetworkInterface {
            mac_address: "00:11:22:33:44:55".to_string(),
            pci_properties: Some(PciDeviceProperties {
                path: "/devices/pci0000:00/0000:00:00.0/0000:01:00.0/0000:02:00.0/0000:03:00.0/net/pf0hpf".to_string(),
                device: "0xa2d6".to_string(),
                vendor: "0x15b3".to_string(),
                numa_node: -1,
                description: Some("MT42822 BlueField-2 integrated ConnectX-6 Dx network controller".to_string())
            })
        },
        NetworkInterface {
            mac_address: "02:13:e7:bf:35:9e".to_string(),
            pci_properties: Some(PciDeviceProperties {
                path: "/devices/pci0000:00/0000:00:00.0/0000:01:00.0/0000:02:00.0/0000:03:00.1/mlx5_core.sf.3/net/enp3s0f1s0".to_string(),
                device: "0xa2d6".to_string(),
                vendor: "0x15b3".to_string(),
                numa_node: 2147483647,
                description: Some("MT42822 BlueField-2 integrated ConnectX-6 Dx network controller".to_string())
            })
        },
        NetworkInterface {
            mac_address: "ch: 64".to_string(),
            pci_properties: Some(PciDeviceProperties {
                path: "/devices/pci0000:00/0000:00:00.0/0000:01:00.0/0000:02:00.0/0000:03:00.1/net/en3f1pf1sf0".to_string(),
                device: "0xa2d6".to_string(),
                vendor: "0x15b3".to_string(),
                numa_node: -1,
                description: Some("MT42822 BlueField-2 integrated ConnectX-6 Dx network controller".to_string())
            })
        },
        NetworkInterface {
            mac_address: "08:c0:eb:cb:0e:ad".to_string(),
            pci_properties: Some(PciDeviceProperties {
                path: "/devices/pci0000:00/0000:00:00.0/0000:01:00.0/0000:02:00.0/0000:03:00.1/net/p1".to_string(),
                device: "0xa2d6".to_string(),
                vendor: "0x15b3".to_string(),
                numa_node: -1,
                description: Some("MT42822 BlueField-2 integrated ConnectX-6 Dx network controller".to_string())
            })
        },
        NetworkInterface {
            mac_address: "ch: 64".to_string(),
            pci_properties: Some(PciDeviceProperties {
                path: "/devices/pci0000:00/0000:00:00.0/0000:01:00.0/0000:02:00.0/0000:03:00.1/net/pf1hpf".to_string(),
                device: "0xa2d6".to_string(),
                vendor: "0x15b3".to_string(),
                numa_node: -1,
                description: Some("MT42822 BlueField-2 integrated ConnectX-6 Dx network controller".to_string())
            })
        }
    ];

    DiscoveryData::Info(DiscoveryInfo {
        network_interfaces,
        cpus,
        block_devices: vec![
            BlockDevice {
                model: "NO_MODEL".to_string(),
                serial: "NO_SERIAL".to_string(),
                revision: "NO_REVISION".to_string(),
            },
            BlockDevice {
                model: "NO_MODEL".to_string(),
                serial: "NO_SERIAL".to_string(),
                revision: "NO_REVISION".to_string(),
            },
        ],
        machine_type: "aarch64".to_string(),
        nvme_devices: Vec::new(),
        dmi_data: None,
        tpm_ek_certificate: None,
    })
}
