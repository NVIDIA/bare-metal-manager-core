use log::LevelFilter;

use carbide::db::{
    machine::Machine, machine_interface::MachineInterface, machine_topology::MachineTopology,
};

#[ctor::ctor]
fn setup() {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(LevelFilter::Warn)
        .init();
}

const FIXTURE_CREATED_MACHINE_INTERFACE_ID: uuid::Uuid =
    uuid::uuid!("ad871735-efaa-406e-a83e-9ff63b1bc145");

#[sqlx::test(fixtures(
    "create_domain",
    "create_vpc",
    "create_network_segment",
    "create_machine"
))]
async fn test_crud_machine_topology(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    let machine_interface =
        MachineInterface::find_one(&mut txn, FIXTURE_CREATED_MACHINE_INTERFACE_ID).await?;

    let machine = Machine::create(&mut txn, machine_interface).await?;

    txn.commit().await?;

    let mut txn = pool.begin().await?;

    let discovery_data = rpc::DiscoveryInfo {
        block_devices: vec![
            rpc::BlockDevice {
                model: "QEMU_DVD-ROM".to_string(),
                serial: "QM00003".to_string(),
                revision: "2.5+".to_string(),
            },
            rpc::BlockDevice {
                model: "NO_MODEL".to_string(),
                serial: "NO_SERIAL".to_string(),
                revision: "NO_REVISION".to_string(),
            },
        ],
        cpus: vec![rpc::Cpu {
            core: 0,
            node: 0,
            number: 0,
            socket: 0,
            vendor: "GenuineIntel".to_string(),
            model: "Intel(R) Core(TM) i9-10920X CPU @ 3.50GHz".to_string(),
            frequency: "3503.998".to_string(),
        }],
        machine_type: "x86_64".to_string(),
        network_interfaces: vec![rpc::NetworkInterface {
            mac_address: "52:54:00:12:34:56".to_string(),
            pci_properties: Some(rpc::PciDeviceProperties {
                path: "/devices/pci0000:00/0000:00:04.0/virtio1/net/ens4".to_string(),
                description: Some("Virtio network device".to_string()),
                device: "0x1000".to_string(),
                numa_node: 2147483647,
                vendor: "0x1af4".to_string(),
            }),
        }],
    };

    let machine_info = rpc::forge::MachineDiscoveryInfo {
        machine_id: Some(rpc::forge::Uuid {
            value: "1685191a-50f2-49da-a75e-81b8d8dfbc2c".to_string(),
        }),
        discovery_data: Some(rpc::forge::machine_discovery_info::DiscoveryData::Info(
            discovery_data,
        )),
    };

    MachineTopology::create(&mut txn, machine.id(), &machine_info).await?;

    txn.commit().await?;

    Ok(())
}
