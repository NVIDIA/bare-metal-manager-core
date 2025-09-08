pub mod tests {
    use std::time::Duration;

    use ::rpc::uuid::machine::MachineId;
    use sqlx::PgConnection;

    use crate::{
        db::{
            self, DatabaseError, ObjectFilter,
            expected_machine::{ExpectedMachine, ExpectedMachineData},
            machine::MachineSearchConfig,
        },
        model::{
            machine::{
                BomValidating, BomValidatingContext, MachineState, MachineValidatingState,
                ManagedHostState, ValidationState,
            },
            metadata::Metadata,
            sku::Sku,
        },
        tests::common::api_fixtures::{
            TestEnv, TestEnvOverrides, TestManagedHost, create_managed_host,
            create_managed_host_with_config, create_test_env, create_test_env_with_overrides,
            get_config, managed_host::ManagedHostConfig,
        },
    };

    pub const FULL_SKU_DATA: &str = r#"
    {
        "id": "sku id",
        "description": "PowerEdge R760; 2xCPU; 8xGPU; 256 GiB",
        "created": "2025-01-22T04:33:27.950438037Z",
        "machines_associated_count": 0,
        "components": {
          "chassis": {
            "vendor": "Dell Inc.",
            "model": "PowerEdge R760",
            "architecture": "x86_64"
          },
          "cpus": [
            {
              "vendor": "GenuineIntel",
              "model": "Intel(R) Xeon(R) Gold 6442Y",
              "thread_count": 48,
              "count": 2
            }
          ],
          "gpus": [
            {
              "vendor": "NVIDIA",
              "model": "NVIDIA L40",
              "count": 8,
              "total_memory": "46068 MiB"
            }
          ],
          "ethernet_devices": [],
          "infiniband_devices": [],
          "memory": [
            {
              "memory_type": "DDR5",
              "capacity_mb": 32768,
              "count": 8
            }
          ],
          "storage": [
            {
              "model": "DELLBOSS_VD",
              "count": 1
            },
            {
              "model": "Dell Ent NVMe CM6 RI 1.92TB",
              "count": 1
            }
          ],
          "tpm": []
        },
        "schema_version": 2
    }"#;

    const SKU_DATA: &str = r#"
{
  "id": "sku id",
  "description": "PowerEdge R750; 1xCPU; 1xGPU; 2 GiB; 6xIB",
  "created": "2025-01-24T21:51:12.465131195Z",
  "machines_associated_count": 0,
  "components": {
    "chassis": {
      "vendor": "Dell Inc.",
      "model": "PowerEdge R750",
      "architecture": "x86_64"
    },
    "cpus": [
      {
        "vendor": "GenuineIntel",
        "model": "Intel(R) Xeon(R) Gold 6354 CPU @ 3.00GHz",
        "thread_count": 72,
        "count": 1
      }
    ],
    "gpus": [
      {
        "vendor": "NVIDIA",
        "model": "NVIDIA H100 PCIe",
        "total_memory": "81559 MiB",
        "count": 1
      }
    ],
    "ethernet_devices": [],
    "infiniband_devices": [
      {
        "vendor": "0x15b3",
        "model": "MT27800 Family [ConnectX-5]",
        "count": 2,
        "inactive_devices": [0,1]
      },
      {
        "vendor": "0x15b3",
        "model": "MT2910 Family [ConnectX-7]",
        "count": 4,
        "inactive_devices": [0,1,2,3]
      }
    ],
    "storage": [
      {
        "model": "DELLBOSS_VD",
        "count": 1
      },
      {
        "model": "Dell Ent NVMe CM6 RI 1.92TB",
        "count": 1
      }

    ],
    "memory": [
      {
        "memory_type": "DDR4",
        "capacity_mb": 1024,
        "count": 2
      }
    ],
    "tpm": []
  },
  "schema_version": 2
}"#;

    pub async fn handle_inventory_update(pool: &sqlx::PgPool, env: &TestEnv, mh: &TestManagedHost) {
        env.run_machine_state_controller_iteration_until_state_condition(
            &mh.host().id,
            3,
            |machine| {
                tracing::info!("waiting for inventory update: {}", machine.current_state());
                matches!(
                    machine.current_state(),
                    ManagedHostState::BomValidating {
                        bom_validating_state: BomValidating::UpdatingInventory { .. }
                    }
                )
            },
        )
        .await;

        let mut txn = pool.begin().await.unwrap();
        crate::db::machine::update_discovery_time(&mh.host().id, &mut txn)
            .await
            .unwrap();
        txn.commit().await.unwrap();
    }

    #[crate::sqlx_test]
    pub async fn test_sku_create(pool: sqlx::PgPool) -> Result<(), eyre::Error> {
        let mut txn = pool.begin().await?;
        let rpc_sku: rpc::forge::Sku = serde_json::de::from_str(FULL_SKU_DATA)?;
        let expected_sku: Sku = rpc_sku.into();
        let expected_sku_json = serde_json::ser::to_string_pretty(&expected_sku)?;

        crate::db::sku::create(&mut txn, &expected_sku).await?;

        let mut actual_sku = crate::db::sku::find(&mut txn, &[expected_sku.id.clone()])
            .await?
            .remove(0);
        // cheat the created timestamp
        actual_sku.created = expected_sku.created;

        let actual_sku_json = serde_json::ser::to_string_pretty(&actual_sku)?;

        assert_eq!(actual_sku_json, expected_sku_json);

        let error = crate::db::sku::create(&mut txn, &expected_sku)
            .await
            .expect_err("Duplicate SKU create should have failed");

        assert_eq!(
            error.to_string(),
            format!(
                "Argument is invalid: Specified SKU matches SKU with ID: {}",
                expected_sku.id
            )
        );
        Ok(())
    }

    #[crate::sqlx_test]
    pub async fn test_sku_delete(pool: sqlx::PgPool) -> Result<(), eyre::Error> {
        let mut txn = pool.begin().await?;
        let rpc_sku: rpc::forge::Sku = serde_json::de::from_str(FULL_SKU_DATA)?;
        let expected_sku: Sku = rpc_sku.into();

        crate::db::sku::create(&mut txn, &expected_sku).await?;
        let actual_sku = crate::db::sku::find(&mut txn, &[expected_sku.id.clone()])
            .await?
            .remove(0);

        crate::db::sku::delete(&mut txn, &actual_sku.id).await?;

        match crate::db::sku::find(&mut txn, &[expected_sku.id]).await {
            Ok(sku) => {
                if !sku.is_empty() {
                    let sku_name = sku[0].id.clone();
                    panic!("Found a SKU when querying for deleted SKU: {sku_name}")
                }
            }
            Err(carbide_error_type) => panic!("Unexpected error: {carbide_error_type}"),
        }

        Ok(())
    }

    #[crate::sqlx_test]
    async fn test_generate_sku_from_machine(pool: sqlx::PgPool) -> Result<(), eyre::Error> {
        let env = create_test_env(pool.clone()).await;
        let (machine_id, _dpu_id) = create_managed_host(&env).await.into();
        let mut txn = pool.begin().await?;

        let expected_sku: Sku = serde_json::de::from_str::<rpc::forge::Sku>(SKU_DATA)?.into();

        let mut actual_sku =
            crate::db::sku::generate_sku_from_machine(&mut txn, &machine_id).await?;
        // cheat the created timestamp and id
        actual_sku.id = "sku id".to_string();
        actual_sku.created = expected_sku.created;

        let actual_sku_json: String = serde_json::ser::to_string_pretty(&actual_sku)?;
        tracing::info!("actual_sku_json: {}", actual_sku_json);
        let expected_sku_json = serde_json::ser::to_string_pretty(&expected_sku)?;
        tracing::info!("expected_sku_json: {}", expected_sku_json);

        assert_eq!(actual_sku_json, expected_sku_json);

        Ok(())
    }

    #[crate::sqlx_test]
    async fn test_api_happy_path(pool: sqlx::PgPool) -> Result<(), eyre::Error> {
        let env = create_test_env(pool.clone()).await;
        let (machine_id, _dpu_id) = create_managed_host(&env).await.into();
        let mut txn = pool.begin().await?;

        let actual_sku = crate::db::sku::generate_sku_from_machine(&mut txn, &machine_id).await?;
        crate::db::sku::create(&mut txn, &actual_sku).await?;
        let actual_sku = crate::db::sku::find(&mut txn, &[actual_sku.id])
            .await?
            .remove(0);

        crate::db::machine::assign_sku(&mut txn, &machine_id, &actual_sku.id).await?;

        let machine = db::machine::find(
            &mut txn,
            ObjectFilter::One(machine_id),
            MachineSearchConfig::default(),
        )
        .await?
        .pop()
        .unwrap();
        assert_eq!(machine.hw_sku.unwrap(), actual_sku.id);

        crate::db::machine::unassign_sku(&mut txn, &machine_id).await?;

        let machine = db::machine::find(
            &mut txn,
            ObjectFilter::One(machine_id),
            MachineSearchConfig::default(),
        )
        .await?
        .pop()
        .unwrap();

        assert!(machine.hw_sku.is_none());

        let sku_id = actual_sku.id.clone();
        crate::db::sku::delete(&mut txn, &actual_sku.id).await?;

        match crate::db::sku::find(&mut txn, &[sku_id]).await {
            // We expect an okay result, but that it should be an empty list.
            Ok(sku) => {
                if !sku.is_empty() {
                    let sku_name = sku[0].id.clone();
                    panic!("Found a SKU when querying for deleted SKU: {sku_name}")
                }
            }
            Err(carbide_error_type) => panic!("Unexpected error: {carbide_error_type}"),
        }

        Ok(())
    }

    async fn create_test_env_for_sku(
        db_pool: sqlx::PgPool,
        ignore_unassigned_machines: bool,
        find_match_interval: Option<Duration>,
        auto_gen_sku_enabled: bool,
    ) -> TestEnv {
        let mut overrides = TestEnvOverrides::default();
        let mut config = get_config();
        config.bom_validation.enabled = true;
        config.bom_validation.ignore_unassigned_machines = ignore_unassigned_machines;
        config.bom_validation.auto_generate_missing_sku = auto_gen_sku_enabled;
        config.bom_validation.auto_generate_missing_sku_interval = Duration::from_secs(2);

        if let Some(find_match_interval) = find_match_interval {
            config.bom_validation.find_match_interval = find_match_interval;
        }
        overrides.config = Some(config);

        let test_env = create_test_env_with_overrides(db_pool, overrides).await;

        assert!(test_env.config.bom_validation.enabled);

        test_env
    }

    #[crate::sqlx_test]
    async fn test_machine_is_ignored_when_not_assigned(
        pool: sqlx::PgPool,
    ) -> Result<(), eyre::Error> {
        let env = create_test_env_for_sku(pool.clone(), true, None, false).await;

        let (_machine_id, _dpu_id) = create_managed_host(&env).await.into();

        Ok(())
    }

    #[crate::sqlx_test]
    async fn test_stays_in_waiting_state_when_not_assigned(
        pool: sqlx::PgPool,
    ) -> Result<(), eyre::Error> {
        let env = create_test_env_for_sku(pool.clone(), false, None, false).await;
        let managed_host_config =
            ManagedHostConfig::with_expected_state(ManagedHostState::BomValidating {
                bom_validating_state: BomValidating::WaitingForSkuAssignment(
                    BomValidatingContext {
                        machine_validation_context: Some("Discovery".to_string()),
                    },
                ),
            });

        let mh = create_managed_host_with_config(&env, managed_host_config).await;

        // the create call above stops at WaitingForSkuAssignment.  make sure it doesn't move if the state machine runs again
        env.run_machine_state_controller_iteration().await;
        env.run_machine_state_controller_iteration().await;

        let mut txn = pool.begin().await?;
        let machine = mh.host().db_machine(&mut txn).await;

        assert!(matches!(
            machine.current_state(),
            ManagedHostState::BomValidating {
                bom_validating_state: BomValidating::WaitingForSkuAssignment(_)
            }
        ));

        Ok(())
    }

    #[crate::sqlx_test]
    async fn test_leave_waiting_when_assigned(pool: sqlx::PgPool) -> Result<(), eyre::Error> {
        let env = create_test_env_for_sku(pool.clone(), false, None, false).await;
        let managed_host_config =
            ManagedHostConfig::with_expected_state(ManagedHostState::BomValidating {
                bom_validating_state: BomValidating::WaitingForSkuAssignment(
                    BomValidatingContext {
                        machine_validation_context: Some("Discovery".to_string()),
                    },
                ),
            });

        let mh = create_managed_host_with_config(&env, managed_host_config).await;
        let machine_id = mh.host().id;

        let mut txn = pool.begin().await?;

        let actual_sku = crate::db::sku::generate_sku_from_machine(&mut txn, &machine_id).await?;
        crate::db::sku::create(&mut txn, &actual_sku).await?;

        crate::db::machine::assign_sku(&mut txn, &machine_id, &actual_sku.id).await?;

        txn.commit().await?;

        // once the sku is assigned, the state machine should move to update inventory before it verifies it.
        env.run_machine_state_controller_iteration().await;

        let mut txn = pool.begin().await?;
        let machine = mh.host().db_machine(&mut txn).await;
        assert!(matches!(
            machine.current_state(),
            ManagedHostState::BomValidating {
                bom_validating_state: BomValidating::UpdatingInventory(_)
            }
        ));

        Ok(())
    }

    async fn get_machine_state(pool: &sqlx::PgPool, mh: &TestManagedHost) -> ManagedHostState {
        let mut txn = pool.begin().await.unwrap();
        let machine = mh.host().db_machine(&mut txn).await;
        machine.current_state().clone()
    }

    #[crate::sqlx_test]
    async fn test_discovery_moves_to_machine_validation_state(
        pool: sqlx::PgPool,
    ) -> Result<(), eyre::Error> {
        let env = create_test_env_for_sku(pool.clone(), false, None, false).await;
        let managed_host_config =
            ManagedHostConfig::with_expected_state(ManagedHostState::BomValidating {
                bom_validating_state: BomValidating::WaitingForSkuAssignment(
                    BomValidatingContext {
                        machine_validation_context: Some("Discovery".to_string()),
                    },
                ),
            });

        let mh = create_managed_host_with_config(&env, managed_host_config).await;
        let machine_id = mh.host().id;

        let mut txn = pool.begin().await?;

        let actual_sku = crate::db::sku::generate_sku_from_machine(&mut txn, &machine_id).await?;
        crate::db::sku::create(&mut txn, &actual_sku).await?;

        crate::db::machine::assign_sku(&mut txn, &machine_id, &actual_sku.id).await?;

        txn.commit().await?;

        handle_inventory_update(&pool, &env, &mh).await;

        env.run_machine_state_controller_iteration().await;

        let state = get_machine_state(&pool, &mh).await;
        assert!(matches!(
            state,
            ManagedHostState::BomValidating {
                bom_validating_state: BomValidating::VerifyingSku(_)
            }
        ));

        env.run_machine_state_controller_iteration().await;
        let state = get_machine_state(&pool, &mh).await;
        assert!(matches!(
            state,
            ManagedHostState::Validation {
                validation_state: ValidationState::MachineValidation {
                    machine_validation: MachineValidatingState::RebootHost { .. }
                }
            }
        ));
        env.run_machine_state_controller_iteration().await;
        let state = get_machine_state(&pool, &mh).await;
        assert!(matches!(
            state,
            ManagedHostState::Validation {
                validation_state: ValidationState::MachineValidation {
                    machine_validation: MachineValidatingState::MachineValidating { .. }
                }
            }
        ));

        Ok(())
    }

    #[crate::sqlx_test]
    async fn test_manual_verify_skips_machine_validation(
        pool: sqlx::PgPool,
    ) -> Result<(), eyre::Error> {
        let env = create_test_env_for_sku(pool.clone(), false, None, false).await;

        let mh = create_managed_host(&env).await;

        let state = get_machine_state(&pool, &mh).await;

        assert!(matches!(state, ManagedHostState::Ready));

        let mut txn = pool.begin().await?;

        let machine = mh.host().db_machine(&mut txn).await;
        let machine_id = mh.host().id;

        crate::db::machine::update_sku_status_verify_request_time(&mut txn, &machine_id).await?;

        txn.commit().await?;

        let mut state = machine.current_state().clone();

        for _ in 0..20 {
            env.run_machine_state_controller_iteration().await;
            state = get_machine_state(&pool, &mh).await;
            assert!(!matches!(
                state,
                ManagedHostState::Validation {
                    validation_state: ValidationState::MachineValidation {
                        machine_validation: MachineValidatingState::MachineValidating { .. }
                    }
                }
            ));
            if state == ManagedHostState::Ready {
                break;
            }
            if matches!(
                state,
                ManagedHostState::BomValidating {
                    bom_validating_state: BomValidating::UpdatingInventory(..)
                }
            ) {
                let mut txn = pool.begin().await?;

                crate::db::machine::update_discovery_time(&machine.id, &mut txn)
                    .await
                    .unwrap();
                txn.commit().await.unwrap();
            }
        }

        assert_eq!(state, ManagedHostState::Ready);

        Ok(())
    }

    #[crate::sqlx_test]
    async fn test_manual_verify_to_failed_to_passed_skips_machine_validation(
        pool: sqlx::PgPool,
    ) -> Result<(), eyre::Error> {
        let env = create_test_env_for_sku(pool.clone(), false, None, false).await;

        let mh = create_managed_host(&env).await;

        let state = get_machine_state(&pool, &mh).await;

        assert!(matches!(state, ManagedHostState::Ready));

        let mut txn = pool.begin().await?;

        let machine = mh.host().db_machine(&mut txn).await;
        let machine_id = mh.host().id;

        let original_sku = crate::db::sku::find(&mut txn, &[machine.hw_sku.clone().unwrap()])
            .await?
            .pop()
            .unwrap();

        tracing::info!("SKU1: {:?}", original_sku);

        let mut broken_sku = original_sku.clone();
        broken_sku.id = "Broken SKU".to_string();
        broken_sku.components.cpus[0].count += 1;

        crate::db::sku::create(&mut txn, &broken_sku).await?;

        tracing::info!("SKU2: {:?}", broken_sku);

        db::machine::unassign_sku(&mut txn, &machine_id).await?;
        db::machine::assign_sku(&mut txn, &machine_id, &broken_sku.id).await?;

        crate::db::machine::update_sku_status_verify_request_time(&mut txn, &machine_id).await?;

        txn.commit().await?;

        handle_inventory_update(&pool, &env, &mh).await;

        env.run_machine_state_controller_iteration_until_state_condition(
            &machine_id,
            3,
            |machine| {
                assert!(!matches!(
                    machine.current_state(),
                    ManagedHostState::Validation {
                        validation_state: ValidationState::MachineValidation {
                            machine_validation: MachineValidatingState::MachineValidating { .. }
                        },
                    }
                ));
                matches!(
                    machine.current_state(),
                    ManagedHostState::BomValidating {
                        bom_validating_state: BomValidating::SkuVerificationFailed(
                            BomValidatingContext { .. },
                        ),
                    }
                )
            },
        )
        .await;

        let mut txn = pool.begin().await?;

        db::machine::unassign_sku(&mut txn, &machine_id).await?;
        db::machine::assign_sku(&mut txn, &machine_id, &original_sku.id).await?;

        crate::db::machine::update_sku_status_verify_request_time(&mut txn, &machine_id).await?;
        txn.commit().await?;

        handle_inventory_update(&pool, &env, &mh).await;

        env.run_machine_state_controller_iteration_until_state_condition(
            &machine_id,
            3,
            |machine| {
                assert!(!matches!(
                    machine.current_state(),
                    ManagedHostState::Validation {
                        validation_state: ValidationState::MachineValidation {
                            machine_validation: MachineValidatingState::MachineValidating { .. }
                        }
                    }
                ));
                matches!(
                    machine.current_state(),
                    ManagedHostState::HostInit {
                        machine_state: MachineState::Discovered { .. },
                    },
                )
            },
        )
        .await;
        mh.host().forge_agent_control().await;

        let mut state = get_machine_state(&pool, &mh).await;
        for _ in 0..3 {
            env.run_machine_state_controller_iteration().await;

            state = get_machine_state(&pool, &mh).await;
            assert!(!matches!(
                state,
                ManagedHostState::Validation {
                    validation_state: ValidationState::MachineValidation {
                        machine_validation: MachineValidatingState::MachineValidating { .. }
                    }
                }
            ));
            if state == ManagedHostState::Ready {
                break;
            }
        }

        assert_eq!(state, ManagedHostState::Ready);
        Ok(())
    }

    #[crate::sqlx_test]
    async fn test_auto_match_sku(pool: sqlx::PgPool) -> Result<(), eyre::Error> {
        let env = create_test_env_for_sku(pool.clone(), false, None, false).await;
        let managed_host_config =
            ManagedHostConfig::with_expected_state(ManagedHostState::BomValidating {
                bom_validating_state: BomValidating::WaitingForSkuAssignment(
                    BomValidatingContext {
                        machine_validation_context: Some("Discovery".to_string()),
                    },
                ),
            });

        let mh = create_managed_host_with_config(&env, managed_host_config).await;
        let machine_id = mh.host().id;

        let mut txn = pool.begin().await?;

        let actual_sku = crate::db::sku::generate_sku_from_machine(&mut txn, &machine_id).await?;
        crate::db::sku::create(&mut txn, &actual_sku).await?;

        crate::db::machine::assign_sku(&mut txn, &machine_id, &actual_sku.id).await?;

        txn.commit().await?;

        // once the sku is assigned, the state machine should move to update inventory before it verifies it.
        env.run_machine_state_controller_iteration().await;

        let mut txn = pool.begin().await?;
        let machine = mh.host().db_machine(&mut txn).await;
        assert!(matches!(
            machine.current_state(),
            ManagedHostState::BomValidating {
                bom_validating_state: BomValidating::UpdatingInventory(_)
            }
        ));

        let expected_sku_id = machine.hw_sku.unwrap();

        // A new machine with the same hardware is automatically assigned the above
        // sku and moves on.

        let mh2 = create_managed_host(&env).await;

        let machine2 = mh2.host().db_machine(&mut txn).await;

        assert_eq!(machine2.hw_sku, Some(expected_sku_id));

        Ok(())
    }

    pub async fn clear_sku_status(
        txn: &mut PgConnection,
        machine_id: &MachineId,
    ) -> Result<(), DatabaseError> {
        let query = "UPDATE machines SET hw_sku_status=null WHERE id=$1 RETURNING id";

        let _: () = sqlx::query_as(query)
            .bind(machine_id)
            .fetch_one(txn)
            .await
            .map_err(|e| DatabaseError::new("clear sku last match attempt", e))?;

        Ok(())
    }

    #[crate::sqlx_test]
    async fn test_auto_match_sku_with_ignore(pool: sqlx::PgPool) -> Result<(), eyre::Error> {
        let env =
            create_test_env_for_sku(pool.clone(), true, Some(Duration::from_secs(10)), false).await;

        let (machine_id, _dpu_id) = create_managed_host(&env).await.into();

        let mut txn = pool.begin().await?;
        let machine = db::machine::find(
            &mut txn,
            ObjectFilter::One(machine_id),
            MachineSearchConfig::default(),
        )
        .await?
        .pop()
        .unwrap();

        assert_eq!(machine.current_state(), &ManagedHostState::Ready);

        let expected_sku = crate::db::sku::generate_sku_from_machine(&mut txn, &machine_id).await?;
        crate::db::sku::create(&mut txn, &expected_sku).await?;

        txn.commit().await?;

        // A new machine with the same hardware is automatically assigned the above
        // sku and moves on.

        let (machine_id, _dpu_id) = create_managed_host(&env).await.into();

        let mut txn = pool.begin().await?;

        let machine = db::machine::find(
            &mut txn,
            ObjectFilter::One(machine_id),
            MachineSearchConfig::default(),
        )
        .await?
        .pop()
        .unwrap();

        assert_eq!(machine.hw_sku, Some(expected_sku.id.clone()));
        assert_eq!(machine.current_state(), &ManagedHostState::Ready);

        clear_sku_status(&mut txn, &machine_id).await?;
        // test that an unassigned can find and assign a machine.
        crate::db::machine::unassign_sku(&mut txn, &machine_id).await?;
        txn.commit().await?;

        env.run_machine_state_controller_iteration_until_state_condition(
            &machine_id,
            10,
            |machine| machine.current_state() != &ManagedHostState::Ready,
        )
        .await;

        let mut txn = pool.begin().await.unwrap();
        crate::db::machine::update_discovery_time(&machine_id, &mut txn)
            .await
            .unwrap();
        txn.commit().await.unwrap();

        env.run_machine_state_controller_iteration_until_state_condition(
            &machine_id,
            10,
            |machine| machine.current_state() == &ManagedHostState::Ready,
        )
        .await;

        let mut txn = pool.begin().await?;
        let machine = db::machine::find(
            &mut txn,
            ObjectFilter::One(machine_id),
            MachineSearchConfig::default(),
        )
        .await?
        .pop()
        .unwrap();

        assert_eq!(machine.hw_sku, Some(expected_sku.id));
        assert_eq!(machine.current_state(), &ManagedHostState::Ready);

        Ok(())
    }

    #[crate::sqlx_test]
    async fn test_match_sku_versions(pool: sqlx::PgPool) -> Result<(), eyre::Error> {
        let env = create_test_env_for_sku(pool.clone(), false, None, false).await;

        let (machine_id, _dpu_id) = create_managed_host(&env).await.into();

        let mut txn = pool.begin().await?;
        let machine = db::machine::find(
            &mut txn,
            ObjectFilter::One(machine_id),
            MachineSearchConfig::default(),
        )
        .await?
        .pop()
        .unwrap();

        assert_eq!(machine.current_state(), &ManagedHostState::Ready);
        assert!(machine.hw_sku.is_some());

        let mut old_sku = crate::db::sku::generate_sku_from_machine(&mut txn, &machine_id).await?;
        //fake an old sku
        old_sku.schema_version = 0;
        old_sku.components.storage = Vec::default();

        let new_sku = crate::db::sku::find(&mut txn, &[machine.hw_sku.unwrap()])
            .await?
            .pop()
            .unwrap();
        assert_eq!(new_sku.schema_version, db::sku::CURRENT_SKU_VERSION);
        assert_ne!(new_sku.components.storage.len(), 0);

        // diff does not check version.  comparing SKUs of different versions will fail
        let diffs = crate::model::sku::diff_skus(&old_sku, &new_sku);
        assert!(!diffs.is_empty());

        // create an older version sku from new topology data will create a backwards compatible sku
        let old_new_sku =
            crate::db::sku::generate_sku_from_machine_at_version(&mut txn, &machine_id, 0).await?;
        assert_eq!(old_new_sku.schema_version, 0);
        assert!(old_new_sku.components.storage.is_empty());

        let diffs = crate::model::sku::diff_skus(&old_sku, &old_new_sku);
        assert!(diffs.is_empty());

        let diffs = crate::model::sku::diff_skus(&old_new_sku, &new_sku);
        assert!(!diffs.is_empty());

        txn.commit().await?;

        Ok(())
    }

    #[test]
    fn test_thread_differences() -> Result<(), eyre::Error> {
        let rpc_sku1: rpc::forge::Sku = serde_json::de::from_str(FULL_SKU_DATA)?;
        let mut rpc_sku2: rpc::forge::Sku = serde_json::de::from_str(FULL_SKU_DATA)?;

        let sku1 = rpc_sku1.into();
        let sku2 = rpc_sku2.clone().into();

        let diffs = crate::model::sku::diff_skus(&sku1, &sku2);
        assert!(diffs.is_empty());

        rpc_sku2.components.as_mut().unwrap().cpus[0].thread_count *= 2;
        let sku2 = rpc_sku2.into();

        let diffs = crate::model::sku::diff_skus(&sku1, &sku2);
        assert!(!diffs.is_empty());

        Ok(())
    }

    #[crate::sqlx_test]
    async fn test_stays_in_missing_state_when_assigned_sku_is_missing(
        pool: sqlx::PgPool,
    ) -> Result<(), eyre::Error> {
        let env = create_test_env_for_sku(pool.clone(), false, None, false).await;

        let managed_host_config =
            ManagedHostConfig::with_expected_state(ManagedHostState::BomValidating {
                bom_validating_state: BomValidating::SkuMissing(BomValidatingContext {
                    machine_validation_context: Some("Discovery".to_string()),
                }),
            });

        let mut txn = pool.begin().await?;
        ExpectedMachine::create(
            &mut txn,
            managed_host_config.bmc_mac_address,
            ExpectedMachineData {
                bmc_username: "admin".to_string(),
                bmc_password: "password".to_string(),
                serial_number: "1234567890".to_string(),
                fallback_dpu_serial_numbers: vec![],
                metadata: Metadata::new_with_default_name(),
                sku_id: Some("no-sku".to_string()),
            },
        )
        .await?;
        txn.commit().await?;

        let mh = create_managed_host_with_config(&env, managed_host_config).await;

        env.run_machine_state_controller_iteration().await;
        env.run_machine_state_controller_iteration().await;
        env.run_machine_state_controller_iteration().await;

        let mut txn = pool.begin().await?;
        let machine = mh.host().db_machine(&mut txn).await;
        let machine_id = mh.host().id;

        assert!(matches!(
            machine.current_state(),
            ManagedHostState::BomValidating {
                bom_validating_state: BomValidating::SkuMissing(_)
            }
        ));

        let mut sku = db::sku::generate_sku_from_machine(&mut txn, &machine_id).await?;
        sku.id = "no-sku".to_string();

        db::sku::create(&mut txn, &sku).await?;

        txn.commit().await?;

        handle_inventory_update(&pool, &env, &mh).await;

        env.run_machine_state_controller_iteration_until_state_condition(&machine_id, 10, |m| {
            matches!(m.current_state(), ManagedHostState::Validation { .. })
        })
        .await;

        mh.host().reboot_completed().await;
        env.run_machine_state_controller_iteration().await;
        mh.machine_validation_completed().await;
        env.run_machine_state_controller_iteration().await;
        mh.host().reboot_completed().await;

        // run until ready
        env.run_machine_state_controller_iteration_until_state_matches(
            &machine_id,
            20,
            ManagedHostState::Ready,
        )
        .await;

        Ok(())
    }

    #[crate::sqlx_test]
    async fn test_generate_sku_when_assigned_sku_is_missing(
        pool: sqlx::PgPool,
    ) -> Result<(), eyre::Error> {
        let env = create_test_env_for_sku(pool.clone(), false, None, true).await;

        let managed_host_config =
            ManagedHostConfig::with_expected_state(ManagedHostState::BomValidating {
                bom_validating_state: BomValidating::SkuMissing(BomValidatingContext {
                    machine_validation_context: Some("Discovery".to_string()),
                }),
            });

        let mut txn = pool.begin().await?;
        ExpectedMachine::create(
            &mut txn,
            managed_host_config.bmc_mac_address,
            ExpectedMachineData {
                bmc_username: "admin".to_string(),
                bmc_password: "password".to_string(),
                serial_number: "1234567890".to_string(),
                fallback_dpu_serial_numbers: vec![],
                metadata: Metadata::new_with_default_name(),
                sku_id: Some("no-sku".to_string()),
            },
        )
        .await?;
        txn.commit().await?;

        let mh = create_managed_host_with_config(&env, managed_host_config).await;
        let machine_id = mh.host().id;

        let mut txn = pool.begin().await?;
        let machine = mh.host().db_machine(&mut txn).await;

        assert!(matches!(
            machine.current_state(),
            ManagedHostState::BomValidating {
                bom_validating_state: BomValidating::SkuMissing(_)
            }
        ));
        txn.commit().await?;

        // when auto-gen-sku is enabled, the state machine will create the sku and
        // re-verify the machine (requiring an inventory update)
        handle_inventory_update(&pool, &env, &mh).await;

        env.run_machine_state_controller_iteration_until_state_condition(&machine_id, 10, |m| {
            matches!(m.current_state(), ManagedHostState::Validation { .. })
        })
        .await;

        mh.host().reboot_completed().await;
        env.run_machine_state_controller_iteration().await;
        mh.machine_validation_completed().await;
        env.run_machine_state_controller_iteration().await;
        mh.host().reboot_completed().await;

        // run until ready
        env.run_machine_state_controller_iteration_until_state_matches(
            &machine_id,
            20,
            ManagedHostState::Ready,
        )
        .await;

        Ok(())
    }

    #[crate::sqlx_test(fixtures("create_sku"))]
    pub fn test_sku_metadata_update(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
        let mut txn = pool.begin().await?;

        crate::db::sku::update_metadata(
            &mut txn,
            "sku1".to_string(),
            Some("new description".to_string()),
            Some("fancy device".to_string()),
        )
        .await?;

        let sku = crate::db::sku::find(&mut txn, &["sku1".to_string()])
            .await?
            .pop()
            .unwrap();

        assert_eq!(&sku.description, "new description");
        assert_eq!(&sku.device_type.unwrap(), "fancy device");

        Ok(())
    }

    #[crate::sqlx_test(fixtures("create_sku"))]
    pub fn test_sku_metadata_update_description(
        pool: sqlx::PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut txn = pool.begin().await?;

        crate::db::sku::update_metadata(
            &mut txn,
            "sku1".to_string(),
            Some("new description".to_string()),
            None,
        )
        .await?;

        let sku = crate::db::sku::find(&mut txn, &["sku1".to_string()])
            .await?
            .pop()
            .unwrap();

        assert_eq!(&sku.description, "new description");
        assert!(&sku.device_type.is_none());

        crate::db::sku::update_metadata(
            &mut txn,
            "sku1".to_string(),
            Some("old description".to_string()),
            Some("old device".to_string()),
        )
        .await?;

        crate::db::sku::update_metadata(
            &mut txn,
            "sku1".to_string(),
            Some("really new description".to_string()),
            None,
        )
        .await?;

        let sku = crate::db::sku::find(&mut txn, &["sku1".to_string()])
            .await?
            .pop()
            .unwrap();

        assert_eq!(&sku.description, "really new description");
        assert_eq!(&sku.device_type.unwrap(), "old device");

        Ok(())
    }

    #[crate::sqlx_test(fixtures("create_sku"))]
    pub fn test_sku_metadata_update_device_type(
        pool: sqlx::PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut txn = pool.begin().await?;

        crate::db::sku::update_metadata(
            &mut txn,
            "sku1".to_string(),
            None,
            Some("new device type".to_string()),
        )
        .await?;

        let sku = crate::db::sku::find(&mut txn, &["sku1".to_string()])
            .await?
            .pop()
            .unwrap();

        assert_eq!(&sku.description, "test description");
        assert_eq!(&sku.device_type.unwrap(), "new device type");

        Ok(())
    }

    #[crate::sqlx_test(fixtures("create_sku"))]
    pub fn test_sku_metadata_update_invalid(
        pool: sqlx::PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut txn = pool.begin().await?;

        let result =
            crate::db::sku::update_metadata(&mut txn, "sku1".to_string(), None, None).await;

        assert!(result.is_err());
        Ok(())
    }

    #[crate::sqlx_test(fixtures("create_sku"))]
    pub fn test_sku_replace_componenets(
        pool: sqlx::PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut txn = pool.begin().await?;
        let sku_id = "sku1".to_string();
        let original_sku = crate::db::sku::find(&mut txn, &[sku_id.clone()])
            .await?
            .remove(0);
        let original_sku_json = serde_json::ser::to_string_pretty(&original_sku)?;
        tracing::info!(original_sku_json, "original");

        let rpc_sku: rpc::forge::Sku = serde_json::de::from_str(FULL_SKU_DATA)?;
        let replacement_sku: Sku = rpc_sku.into();
        let replacement_sku_json = serde_json::ser::to_string_pretty(&replacement_sku)?;
        tracing::info!(replacement_sku_json, "replacment");

        let expected_sku = Sku {
            components: replacement_sku.components,
            ..original_sku
        };
        let expected_sku_json = serde_json::ser::to_string_pretty(&expected_sku)?;

        let returned_sku =
            crate::db::sku::replace_components(&mut txn, &sku_id, expected_sku.components).await?;

        let returned_sku_json = serde_json::ser::to_string_pretty(&returned_sku)?;

        let mut actual_sku = crate::db::sku::find(&mut txn, &[sku_id]).await?.remove(0);

        // cheat the created timestamp
        actual_sku.created = expected_sku.created;

        let actual_sku_json = serde_json::ser::to_string_pretty(&actual_sku)?;

        assert_eq!(actual_sku_json, returned_sku_json);
        assert_eq!(actual_sku_json, expected_sku_json);

        Ok(())
    }

    #[crate::sqlx_test]
    async fn test_replace_components_triggers_verify(
        pool: sqlx::PgPool,
    ) -> Result<(), eyre::Error> {
        let env = create_test_env_for_sku(pool.clone(), true, None, false).await;
        let (machine_id, _dpu_id) = create_managed_host(&env).await.into();
        let mut txn = pool.begin().await?;

        let actual_sku = crate::db::sku::generate_sku_from_machine(&mut txn, &machine_id).await?;
        crate::db::sku::create(&mut txn, &actual_sku).await?;
        let actual_sku = crate::db::sku::find(&mut txn, &[actual_sku.id])
            .await?
            .remove(0);

        crate::db::machine::assign_sku(&mut txn, &machine_id, &actual_sku.id).await?;

        let machine = db::machine::find(
            &mut txn,
            ObjectFilter::One(machine_id),
            MachineSearchConfig::default(),
        )
        .await?
        .pop()
        .unwrap();

        let original_verify_time = machine.hw_sku_status.map(|s| s.verify_request_time);
        assert_eq!(machine.hw_sku.unwrap(), actual_sku.id);

        txn.commit().await?;
        let mut txn = pool.begin().await?;

        crate::db::sku::replace_components(&mut txn, &actual_sku.id, actual_sku.components.clone())
            .await?;

        txn.commit().await?;
        let mut txn = pool.begin().await?;

        let machine = db::machine::find(
            &mut txn,
            ObjectFilter::One(machine_id),
            MachineSearchConfig::default(),
        )
        .await?
        .pop()
        .unwrap();

        let replace_verify_time = machine.hw_sku_status.map(|s| s.verify_request_time);

        assert_ne!(original_verify_time, replace_verify_time);

        env.run_machine_state_controller_iteration().await;

        let mut txn = pool.begin().await?;
        let machine = db::machine::find(
            &mut txn,
            ObjectFilter::One(machine_id),
            MachineSearchConfig::default(),
        )
        .await?
        .pop()
        .unwrap();

        assert!(matches!(
            machine.current_state(),
            ManagedHostState::BomValidating { .. }
        ));

        Ok(())
    }
}
