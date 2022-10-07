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
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use ::rpc::forge as rpc;
use ::rpc::VpcResourceStateMachineInput;

use crate::CarbideError;

#[derive(Debug, PartialEq, Eq, sqlx::Type, Copy, Clone, Deserialize, Serialize)]
#[sqlx(type_name = "vpc_resource_action")]
#[sqlx(rename_all = "lowercase")]
pub enum VpcResourceAction {
    Initialize,
    Submit,
    Accept,
    Wait,
    VpcSuccess,
    Recommission,
    Fail,
}

impl FromStr for VpcResourceAction {
    type Err = CarbideError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "initialize" => Ok(Self::Initialize),
            "vpcsuccess" => Ok(Self::VpcSuccess),
            "submit" => Ok(Self::Submit),
            "accept" => Ok(Self::Accept),
            "wait" => Ok(Self::Wait),
            "fail" => Ok(Self::Fail),
            "recommission" => Ok(Self::Recommission),
            x => Err(CarbideError::DatabaseTypeConversionError(format!(
                "Unknown source field action: {}",
                x
            ))),
        }
    }
}

impl From<&VpcResourceStateMachineInput> for VpcResourceAction {
    fn from(action: &VpcResourceStateMachineInput) -> Self {
        match action {
            VpcResourceStateMachineInput::Initialize => VpcResourceAction::Initialize,
            VpcResourceStateMachineInput::VpcSuccess => VpcResourceAction::VpcSuccess,
            VpcResourceStateMachineInput::Submit => VpcResourceAction::Submit,
            VpcResourceStateMachineInput::Wait => VpcResourceAction::Wait,
            VpcResourceStateMachineInput::Accept => VpcResourceAction::Accept,
            VpcResourceStateMachineInput::Fail => VpcResourceAction::Fail,
            VpcResourceStateMachineInput::Recommission => VpcResourceAction::Recommission,
        }
    }
}

impl From<&VpcResourceAction> for VpcResourceStateMachineInput {
    fn from(event: &VpcResourceAction) -> Self {
        match event {
            VpcResourceAction::Initialize => VpcResourceStateMachineInput::Initialize,
            VpcResourceAction::VpcSuccess => VpcResourceStateMachineInput::VpcSuccess,
            VpcResourceAction::Submit => VpcResourceStateMachineInput::Submit,
            VpcResourceAction::Accept => VpcResourceStateMachineInput::Accept,
            VpcResourceAction::Wait => VpcResourceStateMachineInput::Wait,
            VpcResourceAction::Fail => VpcResourceStateMachineInput::Fail,
            VpcResourceAction::Recommission => VpcResourceStateMachineInput::Recommission,
        }
    }
}

/// Conversion from a VpcResourceAction instance into a protobuf representation for the same type.
impl From<VpcResourceAction> for rpc::VpcResourceAction {
    fn from(action: VpcResourceAction) -> rpc::VpcResourceAction {
        match action {
            VpcResourceAction::Initialize => rpc::VpcResourceAction::VpcInitialize,
            VpcResourceAction::VpcSuccess => rpc::VpcResourceAction::VpcSuccess,
            VpcResourceAction::Submit => rpc::VpcResourceAction::VpcSubmit,
            VpcResourceAction::Accept => rpc::VpcResourceAction::VpcAccept,
            VpcResourceAction::Wait => rpc::VpcResourceAction::VpcWait,
            VpcResourceAction::Recommission => rpc::VpcResourceAction::VpcRecommission,
            VpcResourceAction::Fail => rpc::VpcResourceAction::VpcFail,
        }
    }
}
