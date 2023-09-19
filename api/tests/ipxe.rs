use carbide::{
    db::{machine::Machine, machine_interface::MachineInterface},
    model::machine::{machine_id::MachineId, MachineState, ManagedHostState},
};
use common::api_fixtures::create_test_env;
use mac_address::MacAddress;
use rpc::forge::{forge_server::Forge, CloudInitInstructionsRequest, DhcpDiscovery};

pub mod common;

use common::api_fixtures::{
    instance::create_instance, network_segment::FIXTURE_NETWORK_SEGMENT_ID, TestEnv,
};

use crate::common::mac_address_pool::DPU_OOB_MAC_ADDRESS_POOL;

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
async fn test_pxe_dpu_waiting_for_network_install(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;
    let host_sim = env.start_managed_host_sim();
    let (dpu_machine_id, _) =
        common::api_fixtures::dpu::create_dpu_machine_in_waiting_for_network_install(
            &env,
            &host_sim.config,
        )
        .await;

    let mut txn = pool.begin().await.unwrap();

    let machine = Machine::find_one(
        &mut txn,
        &dpu_machine_id,
        carbide::db::machine::MachineSearchConfig::default(),
    )
    .await
    .unwrap()
    .unwrap();

    assert_eq!(
        machine.current_state(),
        ManagedHostState::DPUNotReady {
            machine_state: MachineState::WaitingForNetworkInstall
        }
    );

    let instructions = get_pxe_instructions(
        &env,
        machine.interfaces().first().unwrap().id().to_string(),
        rpc::forge::MachineArchitecture::Arm,
    )
    .await;
    assert_ne!(instructions.pxe_script, "exit".to_string());
    assert!(instructions.pxe_script.contains("aarch64/carbide.root"));
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_pxe_when_machine_is_not_created(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;

    let dpu_interface_id = common::api_fixtures::dpu::dpu_discover_dhcp(
        &env,
        &DPU_OOB_MAC_ADDRESS_POOL.allocate().to_string(),
    )
    .await;

    let instructions = get_pxe_instructions(
        &env,
        dpu_interface_id.to_string(),
        rpc::forge::MachineArchitecture::Arm,
    )
    .await;

    assert_ne!(instructions.pxe_script, "exit".to_string());
    assert!(instructions.pxe_script.contains("aarch64/carbide.efi"));

    // API doesn't know about MachineArchitecture yet. Let's check instructions for X86.
    let instructions = get_pxe_instructions(
        &env,
        dpu_interface_id.to_string(),
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
        interfaces: vec![rpc::InstanceInterfaceConfig {
            function_type: rpc::InterfaceFunctionType::Physical as i32,
            network_segment_id: Some(FIXTURE_NETWORK_SEGMENT_ID.into()),
        }],
    });

    let (_instance_id, _instance) = create_instance(
        &env,
        &dpu_machine_id,
        &host_machine_id,
        network,
        None,
        vec![],
    )
    .await;

    let instructions = get_pxe_instructions(
        &env,
        host_interface_id.to_string(),
        rpc::forge::MachineArchitecture::X86,
    )
    .await;

    assert_eq!(instructions.pxe_script, "SomeRandomiPxe".to_string());
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_cloud_init_when_machine_is_not_created(pool: sqlx::PgPool) {
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
            remote_id: None,
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

    let cloud_init_cfg = api
        .get_cloud_init_instructions(tonic::Request::new(CloudInitInstructionsRequest {
            ip: interfaces[0].addresses()[0].address.to_string(),
        }))
        .await
        .expect("get_cloud_init_instructions returned an error")
        .into_inner();

    assert!(cloud_init_cfg
        .discovery_instructions
        .is_some_and(|di| di.update_firmware));
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_cloud_init_after_dpu_update(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;

    let (_host_id, dpu_id) = common::api_fixtures::create_managed_host(&env).await;
    move_machine_to_needed_state(
        dpu_id.clone(),
        ManagedHostState::DPUNotReady {
            machine_state: MachineState::Init,
        },
        &pool,
    )
    .await;

    // Interface is created. Let's fetch interface id.
    let machine = env
        .find_machines(Some(dpu_id.to_string().into()), None, true)
        .await
        .machines
        .remove(0);
    assert_eq!(machine.interfaces.len(), 1);

    let cloud_init_cfg = env
        .api
        .get_cloud_init_instructions(tonic::Request::new(CloudInitInstructionsRequest {
            ip: machine.interfaces[0].address[0].clone(),
        }))
        .await
        .expect("get_cloud_init_instructions returned an error")
        .into_inner();

    assert!(cloud_init_cfg
        .discovery_instructions
        .is_some_and(|di| !di.update_firmware));
}
