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

//! State Controller IO implementation for network segments

use crate::{
    db::{
        ib_subnet::{IBSubnet, IBSubnetSearchConfig},
        UuidKeyedObjectFilter,
    },
    model::config_version::{ConfigVersion, Versioned},
    model::ib_subnet::IBSubnetControllerState,
    state_controller::{
        io::StateControllerIO, metrics::NoopMetricsEmitter, snapshot_loader::SnapshotLoaderError,
    },
};

/// State Controller IO implementation for network segments
#[derive(Default, Debug)]
pub struct IBSubnetStateControllerIO {}

#[async_trait::async_trait]
impl StateControllerIO for IBSubnetStateControllerIO {
    type ObjectId = uuid::Uuid;
    type State = IBSubnet;
    type ControllerState = IBSubnetControllerState;
    type MetricsEmitter = NoopMetricsEmitter;

    const DB_LOCK_NAME: &'static str = "ibsubnet_controller_lock";

    const LOG_SPAN_CONTROLLER_NAME: &'static str = "ib_subnet_controller";

    async fn list_objects(
        &self,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
    ) -> Result<Vec<Self::ObjectId>, SnapshotLoaderError> {
        IBSubnet::list_segment_ids(txn)
            .await
            .map_err(SnapshotLoaderError::from)
    }

    /// Loads a state snapshot from the database
    async fn load_object_state(
        &self,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        segment_id: &Self::ObjectId,
    ) -> Result<Self::State, SnapshotLoaderError> {
        let mut segments = IBSubnet::find(
            txn,
            UuidKeyedObjectFilter::One(*segment_id),
            IBSubnetSearchConfig::default(),
        )
        .await?;
        if segments.len() != 1 {
            return Err(SnapshotLoaderError::InvalidResult(format!(
                "Searching for IBSubnet {} returned zero or multiple results",
                segment_id
            )));
        }
        let segment = segments.swap_remove(0);
        Ok(segment)
    }

    async fn load_controller_state(
        &self,
        _txn: &mut sqlx::Transaction<sqlx::Postgres>,
        _object_id: &Self::ObjectId,
        state: &Self::State,
    ) -> Result<Versioned<Self::ControllerState>, SnapshotLoaderError> {
        Ok(state.controller_state.clone())
    }

    async fn persist_controller_state(
        &self,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        object_id: &Self::ObjectId,
        old_version: ConfigVersion,
        new_state: Self::ControllerState,
    ) -> Result<(), SnapshotLoaderError> {
        let _updated =
            IBSubnet::try_update_controller_state(txn, *object_id, old_version, &new_state).await?;
        Ok(())
    }

    fn metric_state_names(state: &IBSubnetControllerState) -> (&'static str, &'static str) {
        match state {
            IBSubnetControllerState::Provisioning => ("provisioning", ""),
            IBSubnetControllerState::Ready => ("ready", ""),
            IBSubnetControllerState::Error => ("error", ""),
            IBSubnetControllerState::Deleting => ("deleting", ""),
        }
    }
}
