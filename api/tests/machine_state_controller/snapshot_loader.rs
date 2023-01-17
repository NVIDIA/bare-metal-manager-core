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

use carbide::{
    db::{
        machine::Machine, machine_interface::MachineInterface, machine_topology::MachineTopology,
        network_segment::NetworkSegment,
    },
    model::hardware_info::{
        BlockDevice, Cpu, DmiDevice, HardwareInfo, NetworkInterface, NvmeDevice,
        PciDeviceProperties,
    },
    state_controller::snapshot_loader::{DbSnapshotLoader, MachineStateSnapshotLoader},
    CarbideResult,
};
use mac_address::MacAddress;
use sqlx::Executor;

use crate::common::api_fixtures::network_segment::FIXTURE_NETWORK_SEGMENT_ID;

const FIXTURE_CREATED_DOMAIN_ID: uuid::Uuid = uuid::uuid!("1ebec7c1-114f-4793-a9e4-63f3d22b5b5e");

const FIXTURE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

#[sqlx::test]
async fn test_snapshot_loader(pool: sqlx::PgPool) -> CarbideResult<()> {
    let mut txn = pool.begin().await?;

    // Workaround to make the fixtures work from a different directory
    for fixture in &["create_domain", "create_vpc", "create_network_segment"] {
        let content = std::fs::read(format!("{}/{}.sql", FIXTURE_DIR, fixture)).unwrap();
        let content = String::from_utf8(content).unwrap();
        txn.execute(content.as_str())
            .await
            .unwrap_or_else(|e| panic!("failed to apply test fixture {:?}: {:?}", fixture, e));
    }

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
            product_serial: "p12345".to_string(),
            board_serial: "b23456".to_string(),
            chassis_serial: "c34567".to_string(),
        }],
        tpm_ek_certificate: None,
    };

    MachineTopology::create(&mut txn, machine.id(), &hardware_info).await?;
    txn.commit().await?;

    let mut txn = pool.begin().await?;

    let snapshot_loader = DbSnapshotLoader::default();
    let snapshot = snapshot_loader
        .load_machine_snapshot(&mut txn, *machine.id())
        .await
        .unwrap();

    assert_eq!(snapshot.machine_id, *machine.id());
    assert_eq!(snapshot.hardware_info, hardware_info);

    Ok(())
}
