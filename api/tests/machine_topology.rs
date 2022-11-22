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
use log::LevelFilter;

use carbide::{
    db::{
        machine::Machine, machine_interface::MachineInterface, machine_topology::MachineTopology,
        network_segment::NetworkSegment,
    },
    model::hardware_info::{
        BlockDevice, Cpu, DmiDevice, HardwareInfo, NetworkInterface, NvmeDevice,
        PciDeviceProperties, TpmEkCertificate,
    },
};
use mac_address::MacAddress;

pub mod common;
use common::api_fixtures::network_segment::FIXTURE_NETWORK_SEGMENT_ID;

#[ctor::ctor]
fn setup() {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(LevelFilter::Warn)
        .init();
}

const FIXTURE_CREATED_DOMAIN_ID: uuid::Uuid = uuid::uuid!("1ebec7c1-114f-4793-a9e4-63f3d22b5b5e");

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_crud_machine_topology(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    // We can't use the fixture created Machine here, since it already has a topology attached
    // therefore we create a new one

    let mut txn = pool.begin().await?;

    let segment = NetworkSegment::find(
        &mut txn,
        carbide::db::UuidKeyedObjectFilter::One(FIXTURE_NETWORK_SEGMENT_ID),
    )
    .await
    .unwrap()
    .remove(0);

    let iface = MachineInterface::create(
        &mut txn,
        &segment,
        &MacAddress::new([0xa, 0xb, 0xc, 0xd, 0xe, 0xf]),
        Some(FIXTURE_CREATED_DOMAIN_ID),
        "myhost".to_string(),
        true,
        carbide::db::address_selection_strategy::AddressSelectionStrategy::Automatic,
    )
    .await
    .unwrap();
    let machine = Machine::create(&mut txn, iface).await.unwrap();

    txn.commit().await?;

    let mut txn = pool.begin().await?;

    let hardware_info = HardwareInfo {
        block_devices: vec![
            BlockDevice {
                model: "QEMU_DVD-ROM".to_string(),
                serial: "QM00003".to_string(),
                revision: "2.5+".to_string(),
            },
            BlockDevice {
                model: "QEMU_DVD-ROM2".to_string(),
                serial: "QM00004".to_string(),
                revision: "2.5+".to_string(),
            },
            BlockDevice {
                model: "NO_MODEL".to_string(),
                serial: "NO_SERIAL".to_string(),
                revision: "NO_REVISION".to_string(),
            },
        ],
        cpus: vec![Cpu {
            core: 0,
            node: 0,
            number: 0,
            socket: 0,
            vendor: "GenuineIntel".to_string(),
            model: "Intel(R) Xeon(R) Gold 6248 CPU @ 2.50GHz".to_string(),
            frequency: "3503.998".to_string(),
        }],
        machine_type: "x86_64".to_string(),
        network_interfaces: vec![NetworkInterface {
            mac_address: "52:54:00:12:34:56".to_string(),
            pci_properties: Some(PciDeviceProperties {
                path: "/devices/pci0000:00/0000:00:04.0/virtio1/net/ens4".to_string(),
                description: Some("Virtio network device".to_string()),
                device: "0x1000".to_string(),
                numa_node: 2147483647,
                vendor: "0x1af4".to_string(),
            }),
        }],
        nvme_devices: vec![NvmeDevice {
            model: "test_nvme_model".to_string(),
            firmware_rev: "test_nvme_firmware_rev.1.0".to_string(),
        }],
        dmi_devices: vec![DmiDevice {
            board_name: "test_dmi_model".to_string(),
            board_version: "test_board_version.1.0".to_string(),
            bios_version: "test_bios_version.1.0".to_string(),
        }],
        tpm_ek_certificate: Some(TpmEkCertificate::from(b"Some certificate".to_vec())),
    };

    MachineTopology::create(&mut txn, machine.id(), &hardware_info).await?;

    txn.commit().await?;

    let mut txn = pool.begin().await?;

    let topos = MachineTopology::find_by_machine_ids(&mut txn, &[*machine.id()])
        .await
        .unwrap();
    assert_eq!(topos.len(), 1);
    let topo = topos.get(machine.id()).unwrap();
    assert_eq!(topo.len(), 1);

    let returned_hw_info = topo[0].topology().discovery_data.info.clone();
    assert_eq!(returned_hw_info, hardware_info);

    // Hardware info is available on the machine
    let machine2 = Machine::find_one(&mut txn, *machine.id())
        .await
        .unwrap()
        .unwrap();

    let rpc_machine = rpc::Machine::try_from(machine2).unwrap();
    let discovery_info = rpc_machine.discovery_info.unwrap();
    let retrieved_hw_info = HardwareInfo::try_from(discovery_info).unwrap();

    assert_eq!(retrieved_hw_info, hardware_info);

    txn.commit().await?;

    // Updating a machine topology won't have any impact
    let mut txn = pool.begin().await?;

    let mut new_info = hardware_info.clone();
    new_info.cpus[0].model = "SnailSpeedCpu".to_string();

    assert!(
        MachineTopology::create(&mut txn, machine.id(), &hardware_info)
            .await?
            .is_none()
    );

    let machine2 = Machine::find_one(&mut txn, *machine.id())
        .await
        .unwrap()
        .unwrap();

    let rpc_machine = rpc::Machine::try_from(machine2).unwrap();
    let discovery_info = rpc_machine.discovery_info.unwrap();
    let retrieved_hw_info = HardwareInfo::try_from(discovery_info).unwrap();

    assert_eq!(retrieved_hw_info, hardware_info);

    txn.commit().await?;

    Ok(())
}
