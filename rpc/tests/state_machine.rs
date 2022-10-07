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
use ::rpc::{MachineStateMachine, MachineStateMachineInput, MachineStateMachineState};
use rust_fsm::*;

#[test]
fn test_state_machine() {
    let mut machine: StateMachine<MachineStateMachine> = StateMachine::new();
    let _ = machine
        .consume(&MachineStateMachineInput::Discover)
        .unwrap();
    assert!(matches!(machine.state(), &MachineStateMachineState::New));
    machine.consume(&MachineStateMachineInput::Adopt).unwrap();

    let machine: StateMachine<MachineStateMachine> =
        StateMachine::from_state(MachineStateMachineState::Ready);
    assert!(matches!(
        machine.state(),
        &rpc::MachineStateMachineState::Ready
    ));
}
