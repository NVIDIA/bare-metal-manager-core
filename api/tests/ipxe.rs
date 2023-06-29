use carbide::{
    db::{machine::Machine, machine_interface::MachineInterface},
    model::machine::{machine_id::MachineId, MachineState, ManagedHostState},
};
use common::api_fixtures::create_test_env;
use mac_address::MacAddress;
use rpc::forge::{forge_server::Forge, DhcpDiscovery};

pub mod common;

use common::api_fixtures::{
    instance::create_instance, network_segment::FIXTURE_NETWORK_SEGMENT_ID, TestEnv,
};

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

async fn move_machine_to_needed_state(
    machine_id: MachineId,
    state: ManagedHostState,
    pool: &sqlx::PgPool,
) {
    let mut txn = pool
        .clone()
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    let machine = Machine::find_one(
        &mut txn,
        &machine_id,
        carbide::db::machine::MachineSearchConfig::default(),
    )
    .await
    .unwrap()
    .unwrap();

    machine.advance(&mut txn, state, None).await.unwrap();
    txn.commit().await.unwrap();
}

async fn get_pxe_instructions(
    env: &TestEnv,
    interface_id: String,
    arch: rpc::forge::MachineArchitecture,
) -> rpc::forge::PxeInstructions {
    env.api
        .get_pxe_instructions(tonic::Request::new(rpc::forge::PxeInstructionRequest {
            arch: arch as i32,
            interface_id: Some(rpc::Uuid {
                value: interface_id,
            }),
        }))
        .await
        .unwrap()
        .into_inner()
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_pxe_dpu_ready(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;
    let (_host_id, dpu_id) = common::api_fixtures::create_managed_host(&env).await;
    move_machine_to_needed_state(dpu_id.clone(), ManagedHostState::Ready, &pool).await;

    let mut txn = pool
        .clone()
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    let dpu_interface_id = MachineInterface::find_by_machine_ids(&mut txn, &[dpu_id.clone()])
        .await
        .unwrap()[&dpu_id][0]
        .id;
    txn.commit().await.unwrap();

    let instructions = get_pxe_instructions(
        &env,
        dpu_interface_id.to_string(),
        rpc::forge::MachineArchitecture::Arm,
    )
    .await;
    assert_eq!(instructions.pxe_script, "exit".to_string());
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_pxe_when_machine_is_not_created(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;
    let api = common::api_fixtures::create_test_env(pool.clone())
        .await
        .api;

    let mac_address = "FF:FF:FF:FF:FF:FF".to_string();
    let _ = api
        .discover_dhcp(tonic::Request::new(DhcpDiscovery {
            mac_address: mac_address.clone(),
            relay_address: "192.0.2.1".to_string(),
            link_address: None,
            vendor_string: None,
            circuit_id: None,
        }))
        .await
        .unwrap()
        .into_inner();

    // Interface is created. Let's fetch interface id.
    let mut txn = pool.begin().await.unwrap();
    let interfaces =
        MachineInterface::find_by_mac_address(&mut txn, mac_address.parse::<MacAddress>().unwrap())
            .await
            .unwrap();

    assert_eq!(interfaces.len(), 1);
    let interface_id = interfaces[0].id();

    let instructions = get_pxe_instructions(
        &env,
        interface_id.to_string(),
        rpc::forge::MachineArchitecture::Arm,
    )
    .await;
    assert_ne!(instructions.pxe_script, "exit".to_string());
    assert!(instructions.pxe_script.contains("aarch64/carbide.efi"));

    // API doesn't know about MachineArchitecture yet. Let's check instructions for X86.
    let instructions = get_pxe_instructions(
        &env,
        interface_id.to_string(),
        rpc::forge::MachineArchitecture::X86,
    )
    .await;
    assert_ne!(instructions.pxe_script, "exit".to_string());
    assert!(instructions.pxe_script.contains("x86_64/carbide.root"));
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_pxe_host(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;
    let (host_id, _dpu_id) = common::api_fixtures::create_managed_host(&env).await;
    let mut txn = pool
        .clone()
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    let host_interface_id = MachineInterface::find_by_machine_ids(&mut txn, &[host_id.clone()])
        .await
        .unwrap()[&host_id][0]
        .id;
    txn.commit().await.unwrap();
    move_machine_to_needed_state(
        host_id.clone(),
        ManagedHostState::HostNotReady {
            machine_state: MachineState::WaitingForDiscovery,
        },
        &pool,
    )
    .await;

    let instructions = get_pxe_instructions(
        &env,
        host_interface_id.to_string(),
        rpc::forge::MachineArchitecture::X86,
    )
    .await;
    assert!(instructions.pxe_script.contains("x86_64/carbide.root"));

    move_machine_to_needed_state(
        host_id.clone(),
        ManagedHostState::HostNotReady {
            machine_state: MachineState::Discovered,
        },
        &pool,
    )
    .await;

    let instructions = get_pxe_instructions(
        &env,
        host_interface_id.to_string(),
        rpc::forge::MachineArchitecture::X86,
    )
    .await;
    assert!(instructions.pxe_script.contains("x86_64/carbide.root"));

    move_machine_to_needed_state(
        host_id.clone(),
        ManagedHostState::WaitingForCleanup {
            cleanup_state: carbide::model::machine::CleanupState::HostCleanup,
        },
        &pool,
    )
    .await;

    let instructions = get_pxe_instructions(
        &env,
        host_interface_id.to_string(),
        rpc::forge::MachineArchitecture::X86,
    )
    .await;
    assert!(instructions.pxe_script.contains("x86_64/carbide.root"));
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_pxe_instance(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;
    let (host_machine_id, dpu_machine_id) = common::api_fixtures::create_managed_host(&env).await;
    let mut txn = pool
        .clone()
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    let host_interface_id =
        MachineInterface::find_by_machine_ids(&mut txn, &[host_machine_id.clone()])
            .await
            .unwrap()[&host_machine_id][0]
            .id;
    txn.commit().await.unwrap();

    let network = Some(rpc::InstanceNetworkConfig {
        ib_interfaces: vec![],
        interfaces: vec![rpc::InstanceInterfaceConfig {
            function_type: rpc::InterfaceFunctionType::Physical as i32,
            network_segment_id: Some(FIXTURE_NETWORK_SEGMENT_ID.into()),
        }],
    });

    let (_instance_id, _instance) =
        create_instance(&env, &dpu_machine_id, &host_machine_id, network).await;

    let instructions = get_pxe_instructions(
        &env,
        host_interface_id.to_string(),
        rpc::forge::MachineArchitecture::X86,
    )
    .await;

    assert_eq!(instructions.pxe_script, "SomeRandomiPxe".to_string());
}
