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

use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgRow, Row};

use ::rpc::forge as rpc;
use ::rpc::VpcResourceStateMachineState;

use crate::CarbideError;

#[derive(sqlx::Type)]
#[sqlx(rename_all = "lowercase")]
#[sqlx(type_name = "vpc_resource_state")]
#[derive(Debug, PartialEq, Eq, Deserialize, Serialize, Clone)]
pub enum VpcResourceState {
    Init,
    New,
    Submitting,
    Accepted,
    Ready,
    Broken,
    WaitingForVpc,
}

impl Display for VpcResourceState {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Init => "initialized",
                Self::New => "new",
                Self::Submitting => "submitting",
                Self::Accepted => "accepted",
                Self::Ready => "ready",
                Self::Broken => "error",
                Self::WaitingForVpc => "waiting_for_vpc",
            }
        )
    }
}

impl<'r> sqlx::FromRow<'r, PgRow> for VpcResourceState {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        row.try_get("vpc_resource_state_machine")
    }
}

impl FromStr for VpcResourceState {
    type Err = CarbideError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "initialize" => Ok(Self::Init),
            "new" => Ok(Self::New),
            "submitting" => Ok(Self::Submitting),
            "accepted" => Ok(Self::Accepted),
            "ready" => Ok(Self::Ready),
            "error" => Ok(Self::Broken),
            "Waiting_for_vpc" => Ok(Self::WaitingForVpc),
            x => Err(CarbideError::DatabaseTypeConversionError(format!(
                "Unknown source field state: {}",
                x
            ))),
        }
    }
}

impl From<&VpcResourceStateMachineState> for VpcResourceState {
    fn from(state: &VpcResourceStateMachineState) -> Self {
        match state {
            VpcResourceStateMachineState::Init => VpcResourceState::Init,
            VpcResourceStateMachineState::New => VpcResourceState::New,
            VpcResourceStateMachineState::Submitting => VpcResourceState::Submitting,
            VpcResourceStateMachineState::Accepted => VpcResourceState::Accepted,
            VpcResourceStateMachineState::Ready => VpcResourceState::Ready,
            VpcResourceStateMachineState::Broken => VpcResourceState::Broken,
            VpcResourceStateMachineState::WaitingForVpc => VpcResourceState::WaitingForVpc,
        }
    }
}

impl From<VpcResourceState> for rpc::VpcResourceState {
    fn from(vpc_resource_state: VpcResourceState) -> rpc::VpcResourceState {
        rpc::VpcResourceState {
            state: vpc_resource_state.to_string(),
        }
    }
}
