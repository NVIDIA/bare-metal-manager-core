/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

pub mod dhcp;
pub mod machine_discovery;
pub mod managed_host_display;

pub use managed_host_display::{ManagedHostMetadata, ManagedHostOutput, get_managed_host_output};

/// A string to display to the user. Either the 'reason' or 'err' field, or None.
pub fn reason_to_user_string(p: &rpc::forge::ControllerStateReason) -> Option<String> {
    use rpc::forge::ControllerStateOutcome::*;
    let Ok(outcome) = rpc::forge::ControllerStateOutcome::try_from(p.outcome) else {
        tracing::error!("Invalid rpc::forge::ControllerStateOutcome i32, should be impossible.");
        return None;
    };
    match outcome {
        Transition | DoNothing | Todo => None,
        Wait | Error => p.outcome_msg.clone(),
    }
}
