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

    let json = r#"{"machine_id": {"value": "1685191a-50f2-49da-a75e-81b8d8dfbc2c"}, "discovery_data": {"InfoV0": {"cpus": [{"core": 0, "node": 0, "model": "Intel(R) Core(TM) i9-10920X CPU @ 3.50GHz", "number": 0, "socket": 0, "vendor": "GenuineIntel", "frequency": "3503.998"}], "machine_type": "x86_64", "block_devices": [{"model": "QEMU_DVD-ROM", "serial": "QM00003", "revision": "2.5+"}, {"model": "NO_MODEL", "serial": "NO_SERIAL", "revision": "NO_REVISION"}], "network_interfaces": [{"mac_address": "52:54:00:12:34:56", "pci_properties": {"path": "/devices/pci0000:00/0000:00:04.0/virtio1/net/ens4", "device": "0x1000", "vendor": "0x1af4", "numa_node": 2147483647, "description": "Virtio network device"}}]}}}"#;

    MachineTopology::create(&mut txn, machine.id(), json.to_string()).await?;

    txn.commit().await?;

    Ok(())
}
