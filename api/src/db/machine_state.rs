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
use std::fmt::{Display, Formatter};
use std::str::FromStr;

use sqlx::{postgres::PgRow, Row};

use ::rpc::forge as rpc;
use ::rpc::MachineStateMachineState;

use crate::CarbideError;

#[derive(sqlx::Type)]
#[sqlx(rename_all = "lowercase")]
#[sqlx(type_name = "machine_state")]
#[derive(Debug, PartialEq, Eq)]
pub enum MachineState {
    Init,
    New,
    Adopted,
    Tested,
    Ready,
    Reset,
    Assigned,
    Broken,
    Decommissioned,
    Unknown,
}

impl Display for MachineState {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Init => "init",
                Self::New => "new",
                Self::Adopted => "adopted",
                Self::Tested => "tested",
                Self::Ready => "ready",
                Self::Reset => "reset",
                Self::Assigned => "assigned",
                Self::Broken => "broken",
                Self::Decommissioned => "decommissioned",
                Self::Unknown => "unknown",
            }
        )
    }
}

impl<'r> sqlx::FromRow<'r, PgRow> for MachineState {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        row.try_get("machine_state_machine")
    }
}

impl FromStr for MachineState {
    type Err = CarbideError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "init" => Ok(Self::Init),
            "new" => Ok(Self::New),
            "adopted" => Ok(Self::Adopted),
            "tested" => Ok(Self::Tested),
            "ready" => Ok(Self::Ready),
            "reset" => Ok(Self::Reset),
            "assigned" => Ok(Self::Assigned),
            "broken" => Ok(Self::Broken),
            "decommissioned" => Ok(Self::Decommissioned),
            x => Err(CarbideError::DatabaseTypeConversionError(format!(
                "Unknown source field state: {}",
                x
            ))),
        }
    }
}

impl From<&MachineStateMachineState> for MachineState {
    fn from(state: &MachineStateMachineState) -> Self {
        match state {
            MachineStateMachineState::Init => MachineState::Init,
            MachineStateMachineState::New => MachineState::New,
            MachineStateMachineState::Adopted => MachineState::Adopted,
            MachineStateMachineState::Tested => MachineState::Tested,
            MachineStateMachineState::Ready => MachineState::Ready,
            MachineStateMachineState::Reset => MachineState::Reset,
            MachineStateMachineState::Assigned => MachineState::Assigned,
            MachineStateMachineState::Broken => MachineState::Broken,
            MachineStateMachineState::Decommissioned => MachineState::Decommissioned,
        }
    }
}

impl From<MachineState> for rpc::MachineState {
    fn from(machine_state: MachineState) -> rpc::MachineState {
        rpc::MachineState {
            state: machine_state.to_string(),
        }
    }
}
