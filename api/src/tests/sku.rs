pub mod tests {
    use forge_uuid::machine::MachineId;

    use crate::{
        db::{self, DatabaseError, ObjectFilter, machine::MachineSearchConfig},
        model::{
            machine::{
                BomValidating, BomValidatingContext, MachineState, MachineValidatingState,
                ManagedHostState, ValidationState,
            },
            sku::Sku,
        },
        tests::common::api_fixtures::{
            TestEnv, TestEnvOverrides, create_managed_host, create_managed_host_with_config,
            create_test_env, create_test_env_with_overrides, get_config,
            managed_host::ManagedHostConfig,
        },
    };

    const FULL_SKU_DATA: &str = r#"
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
            "model": "Dell Ent NVMe CM6 RI 1.92TB",
            "count": 9
          },
          {
            "model": "DELLBOSS_VD",
            "count": 3
          }
          ],
          "tpm": []
        },
        "schema_version": 1
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
        "count": 3
      },
      {
        "model": "Dell Ent NVMe CM6 RI 1.92TB",
        "count": 9
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
  "schema_version": 1
}"#;

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
            Ok(sku) => panic!("Found deleted SKU: {sku:?}"),
            Err(DatabaseError { source, .. }) => match source {
                sqlx::Error::RowNotFound => {}
                _ => panic!("Unexpected error: {source}"),
            },
        }

        Ok(())
    }

    #[crate::sqlx_test]
    async fn test_from_topology(pool: sqlx::PgPool) -> Result<(), eyre::Error> {
        let env = create_test_env(pool.clone()).await;
        let (machine_id, _dpu_id) = create_managed_host(&env).await;
        let mut txn = pool.begin().await?;

        let expected_sku: Sku = serde_json::de::from_str::<rpc::forge::Sku>(SKU_DATA)?.into();

        let mut actual_sku = crate::db::sku::from_topology(&mut txn, &machine_id).await?;
        // cheat the created timestamp and id
        actual_sku.id = "sku id".to_string();
        actual_sku.created = expected_sku.created;
        // Sort the IB devices by Model. Due to the hashmap, the actual order might be different
        actual_sku
            .components
            .infiniband_devices
            .sort_by(|dev1, dev2| dev1.model.cmp(&dev2.model));

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
        let (machine_id, _dpu_id) = create_managed_host(&env).await;
        let mut txn = pool.begin().await?;

        let actual_sku = crate::db::sku::from_topology(&mut txn, &machine_id).await?;
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
            Ok(sku) => panic!("Found deleted SKU: {sku:?}"),
            Err(DatabaseError { source, .. }) => match source {
                sqlx::Error::RowNotFound => {}
                _ => panic!("Unexpected error: {source}"),
            },
        }

        Ok(())
    }

    async fn create_test_env_for_sku(
        db_pool: sqlx::PgPool,
        ignore_unassigned_machines: bool,
    ) -> TestEnv {
        let mut overrides = TestEnvOverrides::default();
        let mut config = get_config();
        config.bom_validation.enabled = true;
        config.bom_validation.ignore_unassigned_machines = ignore_unassigned_machines;
        overrides.config = Some(config);

        let test_env = create_test_env_with_overrides(db_pool, overrides).await;

        assert!(test_env.config.bom_validation.enabled);

        test_env
    }

    #[crate::sqlx_test]
    async fn test_machine_is_ignored_when_not_assigned(
        pool: sqlx::PgPool,
    ) -> Result<(), eyre::Error> {
        let env = create_test_env_for_sku(pool.clone(), true).await;

        let (_machine_id, _dpu_id) = create_managed_host(&env).await;

        Ok(())
    }

    #[crate::sqlx_test]
    async fn test_stays_in_waiting_state_when_not_assigned(
        pool: sqlx::PgPool,
    ) -> Result<(), eyre::Error> {
        let env = create_test_env_for_sku(pool.clone(), false).await;
        let managed_host_config =
            ManagedHostConfig::with_expected_state(ManagedHostState::BomValidating {
                bom_validating_state: BomValidating::WaitingForSkuAssignment(
                    BomValidatingContext {
                        machine_validation_context: Some("Discovery".to_string()),
                    },
                ),
            });

        let (machine_id, _dpu_id) =
            create_managed_host_with_config(&env, managed_host_config).await;

        // the create call above stops at WaitingForSkuAssignment.  make sure it doesn't move if the state machine runs again
        env.run_machine_state_controller_iteration().await;
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
            ManagedHostState::BomValidating {
                bom_validating_state: BomValidating::WaitingForSkuAssignment(_)
            }
        ));

        Ok(())
    }

    #[crate::sqlx_test]
    async fn test_leave_waiting_when_assigned(pool: sqlx::PgPool) -> Result<(), eyre::Error> {
        let env = create_test_env_for_sku(pool.clone(), false).await;
        let managed_host_config =
            ManagedHostConfig::with_expected_state(ManagedHostState::BomValidating {
                bom_validating_state: BomValidating::WaitingForSkuAssignment(
                    BomValidatingContext {
                        machine_validation_context: Some("Discovery".to_string()),
                    },
                ),
            });

        let (machine_id, _dpu_id) =
            create_managed_host_with_config(&env, managed_host_config).await;

        let mut txn = pool.begin().await?;

        let actual_sku = crate::db::sku::from_topology(&mut txn, &machine_id).await?;
        crate::db::sku::create(&mut txn, &actual_sku).await?;

        crate::db::machine::assign_sku(&mut txn, &machine_id, &actual_sku.id).await?;

        txn.commit().await?;

        // once the sku is assigned, the state machine should move to update inventory before it verifies it.
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
            ManagedHostState::BomValidating {
                bom_validating_state: BomValidating::UpdatingInventory(_)
            }
        ));

        Ok(())
    }

    async fn get_machine_state(
        pool: &sqlx::PgPool,
        machine_id: &MachineId,
    ) -> Result<ManagedHostState, eyre::Error> {
        let mut txn = pool.begin().await?;
        let machine = db::machine::find(
            &mut txn,
            ObjectFilter::One(*machine_id),
            MachineSearchConfig::default(),
        )
        .await?
        .pop()
        .unwrap();

        Ok(machine.current_state().clone())
    }

    pub async fn handle_inventory_update(
        pool: &sqlx::PgPool,
        env: &TestEnv,
        machine_id: &MachineId,
    ) {
        let mut txn = pool.begin().await.unwrap();
        env.run_machine_state_controller_iteration_until_state_condition(
            machine_id,
            3,
            &mut txn,
            |machine| {
                matches!(
                    machine.current_state(),
                    ManagedHostState::BomValidating {
                        bom_validating_state: BomValidating::UpdatingInventory { .. }
                    }
                )
            },
        )
        .await;

        txn.commit().await.unwrap();
        let mut txn = pool.begin().await.unwrap();
        crate::db::machine::update_discovery_time(machine_id, &mut txn)
            .await
            .unwrap();
        txn.commit().await.unwrap();
    }

    #[crate::sqlx_test]
    async fn test_discovery_moves_to_machine_validation_state(
        pool: sqlx::PgPool,
    ) -> Result<(), eyre::Error> {
        let env = create_test_env_for_sku(pool.clone(), false).await;
        let managed_host_config =
            ManagedHostConfig::with_expected_state(ManagedHostState::BomValidating {
                bom_validating_state: BomValidating::WaitingForSkuAssignment(
                    BomValidatingContext {
                        machine_validation_context: Some("Discovery".to_string()),
                    },
                ),
            });

        let (machine_id, _dpu_id) =
            create_managed_host_with_config(&env, managed_host_config).await;

        let mut txn = pool.begin().await?;

        let actual_sku = crate::db::sku::from_topology(&mut txn, &machine_id).await?;
        crate::db::sku::create(&mut txn, &actual_sku).await?;

        crate::db::machine::assign_sku(&mut txn, &machine_id, &actual_sku.id).await?;

        txn.commit().await?;

        handle_inventory_update(&pool, &env, &machine_id).await;

        env.run_machine_state_controller_iteration().await;

        let state = get_machine_state(&pool, &machine_id).await?;
        assert!(matches!(
            state,
            ManagedHostState::BomValidating {
                bom_validating_state: BomValidating::VerifyingSku(_)
            }
        ));

        env.run_machine_state_controller_iteration().await;
        let state = get_machine_state(&pool, &machine_id).await?;
        assert!(matches!(
            state,
            ManagedHostState::Validation {
                validation_state: ValidationState::MachineValidation {
                    machine_validation: MachineValidatingState::RebootHost { .. }
                }
            }
        ));
        env.run_machine_state_controller_iteration().await;
        let state = get_machine_state(&pool, &machine_id).await?;
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
        let env = create_test_env_for_sku(pool.clone(), false).await;

        let (machine_id, _dpu_id) = create_managed_host(&env).await;

        let state = get_machine_state(&pool, &machine_id).await?;

        assert!(matches!(state, ManagedHostState::Ready,));

        let mut txn = pool.begin().await?;

        let machine = db::machine::find(
            &mut txn,
            ObjectFilter::One(machine_id),
            MachineSearchConfig::default(),
        )
        .await?
        .pop()
        .unwrap();

        crate::db::machine::update_sku_status_verify_request_time(&mut txn, &machine_id).await?;

        txn.commit().await?;

        let mut state = machine.current_state().clone();

        for _ in 0..20 {
            env.run_machine_state_controller_iteration().await;
            state = get_machine_state(&pool, &machine_id).await?;
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
        let env = create_test_env_for_sku(pool.clone(), false).await;

        let (machine_id, _dpu_id) = create_managed_host(&env).await;

        let state = get_machine_state(&pool, &machine_id).await?;

        assert!(matches!(state, ManagedHostState::Ready,));

        let mut txn = pool.begin().await?;

        let machine = db::machine::find(
            &mut txn,
            ObjectFilter::One(machine_id),
            MachineSearchConfig::default(),
        )
        .await?
        .pop()
        .unwrap();

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

        handle_inventory_update(&pool, &env, &machine_id).await;

        let mut txn = pool.begin().await?;
        env.run_machine_state_controller_iteration_until_state_condition(
            &machine_id,
            3,
            &mut txn,
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

        txn.commit().await?;
        let mut txn = pool.begin().await?;

        db::machine::unassign_sku(&mut txn, &machine_id).await?;
        db::machine::assign_sku(&mut txn, &machine_id, &original_sku.id).await?;

        crate::db::machine::update_sku_status_verify_request_time(&mut txn, &machine_id).await?;
        txn.commit().await?;

        handle_inventory_update(&pool, &env, &machine_id).await;

        let mut txn = pool.begin().await?;
        env.run_machine_state_controller_iteration_until_state_condition(
            &machine_id,
            3,
            &mut txn,
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
        txn.commit().await?;
        let _response =
            crate::tests::common::api_fixtures::forge_agent_control(&env, machine_id.into()).await;

        let mut state = get_machine_state(&pool, &machine_id).await?;
        for _ in 0..3 {
            env.run_machine_state_controller_iteration().await;

            state = get_machine_state(&pool, &machine_id).await?;
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
        let env = create_test_env_for_sku(pool.clone(), false).await;
        let managed_host_config =
            ManagedHostConfig::with_expected_state(ManagedHostState::BomValidating {
                bom_validating_state: BomValidating::WaitingForSkuAssignment(
                    BomValidatingContext {
                        machine_validation_context: Some("Discovery".to_string()),
                    },
                ),
            });

        let (machine_id, _dpu_id) =
            create_managed_host_with_config(&env, managed_host_config).await;

        let mut txn = pool.begin().await?;

        let actual_sku = crate::db::sku::from_topology(&mut txn, &machine_id).await?;
        crate::db::sku::create(&mut txn, &actual_sku).await?;

        crate::db::machine::assign_sku(&mut txn, &machine_id, &actual_sku.id).await?;

        txn.commit().await?;

        // once the sku is assigned, the state machine should move to update inventory before it verifies it.
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
            ManagedHostState::BomValidating {
                bom_validating_state: BomValidating::UpdatingInventory(_)
            }
        ));

        let expected_sku_id = machine.hw_sku.unwrap();

        // A new machine with the same hardware is automatically assigned the above
        // sku and moves on.

        let (machine_id, _dpu_id) = create_managed_host(&env).await;

        let machine2 = db::machine::find(
            &mut txn,
            ObjectFilter::One(machine_id),
            MachineSearchConfig::default(),
        )
        .await?
        .pop()
        .unwrap();

        assert_eq!(machine2.hw_sku, Some(expected_sku_id));

        Ok(())
    }

    #[crate::sqlx_test]
    async fn test_auto_match_sku_with_ignore(pool: sqlx::PgPool) -> Result<(), eyre::Error> {
        let env = create_test_env_for_sku(pool.clone(), true).await;

        let (machine_id, _dpu_id) = create_managed_host(&env).await;

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

        let expected_sku = crate::db::sku::from_topology(&mut txn, &machine_id).await?;
        crate::db::sku::create(&mut txn, &expected_sku).await?;

        txn.commit().await?;

        // A new machine with the same hardware is automatically assigned the above
        // sku and moves on.

        let (machine_id, _dpu_id) = create_managed_host(&env).await;

        let mut txn = pool.begin().await?;

        let machine2 = db::machine::find(
            &mut txn,
            ObjectFilter::One(machine_id),
            MachineSearchConfig::default(),
        )
        .await?
        .pop()
        .unwrap();

        assert_eq!(machine2.hw_sku, Some(expected_sku.id));

        Ok(())
    }

    #[crate::sqlx_test]
    async fn test_match_sku_versions(pool: sqlx::PgPool) -> Result<(), eyre::Error> {
        let env = create_test_env_for_sku(pool.clone(), false).await;

        let (machine_id, _dpu_id) = create_managed_host(&env).await;

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

        let mut old_sku = crate::db::sku::from_topology(&mut txn, &machine_id).await?;
        //fake an old sku
        old_sku.schema_version = 0;
        old_sku.components.storage = Vec::default();

        let new_sku = crate::db::sku::find(&mut txn, &[machine.hw_sku.unwrap()])
            .await?
            .pop()
            .unwrap();
        assert_eq!(new_sku.schema_version, 1);
        assert_ne!(new_sku.components.storage.len(), 0);

        // diff does not check version.  comparing SKUs of different versions will fail
        let diffs = crate::model::sku::diff_skus(&old_sku, &new_sku);
        assert!(!diffs.is_empty());

        // create an older version sku from new topology data will create a backwards compatible sku
        let old_new_sku =
            crate::db::sku::from_topology_with_version(&mut txn, &machine_id, 0).await?;
        assert_eq!(old_new_sku.schema_version, 0);
        assert!(old_new_sku.components.storage.is_empty());

        let diffs = crate::model::sku::diff_skus(&old_sku, &old_new_sku);
        assert!(diffs.is_empty());

        let diffs = crate::model::sku::diff_skus(&old_new_sku, &new_sku);
        assert!(!diffs.is_empty());

        txn.commit().await?;

        Ok(())
    }
}
