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

use bmc_mock::{BmcEvent, MockPowerState};

use crate::machine_state_machine::OsImage;

pub type FsmReturn<Fsm> = (Fsm, Vec<Action>);

#[derive(Clone, Copy, Debug)]
pub enum MachineFsm {
    BmcInit { power_on: bool, bmc_only: bool },
    Init,
    MachineDown,
    DhcpComplete,
    MachineUp { os_fsm: OsFsm },
    BmcOnlyMachineUp,
    BmcOnlyMachineDown,
}

impl MachineFsm {
    pub fn init(power_on: bool, bmc_only: bool) -> FsmReturn<Self> {
        (
            Self::BmcInit { power_on, bmc_only },
            vec![Action::Dhcp(DhcpType::Bmc)],
        )
    }

    pub fn event(self, event: Event) -> (Self, Vec<Action>) {
        match self {
            Self::BmcInit { power_on, bmc_only } => self.fsm_bmc_init(event, power_on, bmc_only),
            Self::Init => self.fsm_init(event),
            Self::MachineDown => self.fsm_machine_down(event),
            Self::DhcpComplete => self.fsm_dhcp_complete(event),
            Self::MachineUp { os_fsm } => self.fsm_machine_up(event, os_fsm),

            Self::BmcOnlyMachineUp => self.fsm_bmc_only_machine_up(event),
            Self::BmcOnlyMachineDown => self.fsm_bmc_only_machine_down(event),
        }
    }

    pub fn is_up(&self) -> bool {
        matches!(self, Self::MachineUp { .. } | Self::BmcOnlyMachineUp)
    }

    pub fn power_state(&self) -> MockPowerState {
        match self {
            Self::BmcInit { power_on: true, .. } => MockPowerState::On,
            Self::BmcInit {
                power_on: false, ..
            } => MockPowerState::Off,
            Self::Init => MockPowerState::On,
            Self::MachineDown => MockPowerState::Off,
            Self::DhcpComplete => MockPowerState::On,
            Self::MachineUp { .. } => MockPowerState::On,
            Self::BmcOnlyMachineUp => MockPowerState::On,
            Self::BmcOnlyMachineDown => MockPowerState::Off,
        }
    }

    pub fn state_string(&self) -> &'static str {
        match self {
            Self::BmcInit { .. } => "BmcInit",
            Self::Init => "Init",
            Self::MachineDown => "MachineDown",
            Self::DhcpComplete => "DhcpComplete",
            Self::MachineUp { .. } => "MachineUp",
            Self::BmcOnlyMachineUp => "BmcOnly/MachineUp",
            Self::BmcOnlyMachineDown => "BmcOnly/MachineDown",
        }
    }

    pub fn booted_os(&self) -> Option<OsImage> {
        match self {
            Self::MachineUp {
                os_fsm: OsFsm::Scout { .. },
            } => Some(OsImage::Scout),
            Self::MachineUp {
                os_fsm: OsFsm::DpuAgent { .. },
            } => Some(OsImage::DpuAgent),
            Self::MachineUp {
                os_fsm: OsFsm::None,
            } => Some(OsImage::None),
            _ => None,
        }
    }

    fn fsm_bmc_init(self, event: Event, power_on: bool, bmc_only: bool) -> (Self, Vec<Action>) {
        match event {
            Event::DhcpComplete(DhcpType::Bmc) => (
                if bmc_only {
                    if power_on {
                        Self::BmcOnlyMachineUp
                    } else {
                        Self::BmcOnlyMachineDown
                    }
                } else if power_on {
                    Self::Init
                } else {
                    Self::MachineDown
                },
                vec![Action::SetupBmc],
            ),
            Event::PowerOn => (
                Self::BmcInit {
                    bmc_only,
                    power_on: true,
                },
                if power_on {
                    vec![]
                } else {
                    vec![Action::SetTimer(Timer::MachineOn)]
                },
            ),
            Event::PowerOff => (
                Self::BmcInit {
                    bmc_only,
                    power_on: false,
                },
                vec![],
            ),
            Event::PowerCycle => (
                Self::BmcInit {
                    bmc_only,
                    power_on: false,
                },
                vec![Action::SetTimer(Timer::PowerCycle)],
            ),
            Event::TimerAlert(Timer::PowerCycle) => (
                Self::BmcInit {
                    bmc_only,
                    power_on: true,
                },
                vec![],
            ),
            _ => (self, vec![]),
        }
    }

    fn fsm_init(self, event: Event) -> (Self, Vec<Action>) {
        match event {
            Event::TimerAlert(Timer::MachineOn) => (
                self,
                vec![
                    Action::BmcEvent(BmcEvent::PowerOn),
                    Action::Dhcp(DhcpType::Machine),
                ],
            ),
            Event::DhcpComplete(DhcpType::Machine) => {
                (Self::DhcpComplete, vec![Action::PxeBootRequest])
            }
            Event::PowerCycle => self.machine_down_on_power_cycle(),
            Event::PowerOff => self.machine_down_on_power_off(),
            _ => (self, vec![]),
        }
    }

    fn fsm_machine_down(self, event: Event) -> (Self, Vec<Action>) {
        match event {
            Event::PowerCycle => (self, vec![Action::SetTimer(Timer::PowerCycle)]),
            Event::PowerOn | Event::TimerAlert(Timer::PowerCycle) => {
                (Self::Init, vec![Action::SetTimer(Timer::MachineOn)])
            }
            _ => (self, vec![]),
        }
    }

    fn fsm_dhcp_complete(self, event: Event) -> (Self, Vec<Action>) {
        match event {
            Event::PowerCycle => self.machine_down_on_power_cycle(),
            Event::PowerOff => self.machine_down_on_power_off(),
            Event::PxeComplete(os_image) => {
                let os_fsm = match os_image {
                    OsImage::None => OsFsm::None,
                    OsImage::DpuAgent => OsFsm::DpuAgent(DpuAgentFsm::Discovery),
                    OsImage::Scout => OsFsm::Scout(ScoutFsm::Discovery),
                };
                let mut actions = os_fsm.init_actions();
                actions.push(Action::BmcEvent(BmcEvent::BootCompleted));
                (Self::MachineUp { os_fsm }, actions)
            }
            _ => (self, vec![]),
        }
    }

    fn fsm_machine_up(self, event: Event, os_fsm: OsFsm) -> (Self, Vec<Action>) {
        match event {
            Event::PowerCycle => self.machine_down_on_power_cycle(),
            Event::PowerOff => self.machine_down_on_power_off(),
            _ => {
                let (os_fsm, actions) = os_fsm.event(event);
                (Self::MachineUp { os_fsm }, actions)
            }
        }
    }

    fn fsm_bmc_only_machine_up(self, event: Event) -> (Self, Vec<Action>) {
        match event {
            Event::PowerOff => (Self::BmcOnlyMachineDown, vec![]),
            Event::PowerCycle => (
                Self::BmcOnlyMachineDown,
                vec![
                    Action::CleanupOnPowerOff,
                    Action::SetTimer(Timer::PowerCycle),
                ],
            ),
            _ => (self, vec![]),
        }
    }

    fn fsm_bmc_only_machine_down(self, event: Event) -> (Self, Vec<Action>) {
        match event {
            Event::PowerCycle => (
                Self::BmcOnlyMachineDown,
                vec![
                    Action::CleanupOnPowerOff,
                    Action::SetTimer(Timer::PowerCycle),
                ],
            ),
            Event::PowerOn | Event::TimerAlert(Timer::PowerCycle) => {
                (Self::BmcOnlyMachineUp, vec![])
            }
            _ => (self, vec![]),
        }
    }

    fn machine_down_on_power_off(self) -> (Self, Vec<Action>) {
        (Self::MachineDown, vec![Action::CleanupOnPowerOff])
    }

    fn machine_down_on_power_cycle(self) -> (Self, Vec<Action>) {
        (
            Self::MachineDown,
            vec![
                Action::CleanupOnPowerOff,
                Action::SetTimer(Timer::PowerCycle),
            ],
        )
    }
}

#[derive(Copy, Clone, Debug)]
pub enum Event {
    DhcpComplete(DhcpType),
    PowerOn,
    PowerOff,
    PowerCycle,
    TimerAlert(Timer),
    PxeComplete(OsImage),
    InitialDiscoveryCompleted,
    AgentControlCompleted,
    MachineNotFound,
    NetworkObservationCompleted,
}

#[derive(Copy, Clone, Debug)]
pub enum Action {
    SetupBmc,
    SetTimer(Timer),
    Dhcp(DhcpType),
    PxeBootRequest,
    InitialDiscoveryRequest(OsImage),
    AgentControlRequest(OsImage),
    DpuAgentNetworkObservation,
    CleanupOnPowerOff,
    BmcEvent(BmcEvent),
}

#[derive(Copy, Clone, Debug)]
pub enum Timer {
    PowerCycle,
    MachineOn,
    ScoutAgentControlPoll,
    DpuAgentControlPoll,
}

#[derive(Copy, Clone, Debug)]
pub enum DhcpType {
    Bmc,
    Machine,
}

#[derive(Copy, Clone, Debug)]
pub enum OsFsm {
    None,
    Scout(ScoutFsm),
    DpuAgent(DpuAgentFsm),
}

impl OsFsm {
    pub fn init_actions(&self) -> Vec<Action> {
        match self {
            Self::None => vec![],
            Self::Scout(_) => vec![Action::InitialDiscoveryRequest(OsImage::Scout)],
            Self::DpuAgent(_) => vec![Action::InitialDiscoveryRequest(OsImage::DpuAgent)],
        }
    }

    pub fn event(self, event: Event) -> (Self, Vec<Action>) {
        match self {
            Self::None => (self, vec![]),
            Self::Scout(scout_fsm) => {
                let (scout_fsm, actions) = scout_fsm.event(event);
                (Self::Scout(scout_fsm), actions)
            }
            Self::DpuAgent(dpu_agent_fsm) => {
                let (dpu_agent_fsm, actions) = dpu_agent_fsm.event(event);
                (Self::DpuAgent(dpu_agent_fsm), actions)
            }
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub enum ScoutFsm {
    Discovery,
    PollingLoop,
    FailedAndWaitForReboot,
}

impl ScoutFsm {
    pub fn event(self, event: Event) -> (Self, Vec<Action>) {
        match self {
            Self::Discovery => self.fsm_discovery(event),
            Self::PollingLoop => self.fsm_polling_loop(event),
            Self::FailedAndWaitForReboot => (self, vec![]),
        }
    }

    pub fn fsm_discovery(self, event: Event) -> (Self, Vec<Action>) {
        match event {
            Event::InitialDiscoveryCompleted => (
                Self::PollingLoop,
                vec![Action::AgentControlRequest(OsImage::Scout)],
            ),
            Event::MachineNotFound => (Self::FailedAndWaitForReboot, vec![]),
            _ => (self, vec![]),
        }
    }

    pub fn fsm_polling_loop(self, event: Event) -> (Self, Vec<Action>) {
        match event {
            Event::AgentControlCompleted => {
                (self, vec![Action::SetTimer(Timer::ScoutAgentControlPoll)])
            }
            Event::TimerAlert(Timer::ScoutAgentControlPoll) => {
                (self, vec![Action::AgentControlRequest(OsImage::Scout)])
            }
            Event::MachineNotFound => (Self::FailedAndWaitForReboot, vec![]),
            _ => (self, vec![]),
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub enum DpuAgentFsm {
    Discovery,
    AgentControl,
    NetworkObservation,
    FailedAndWaitForReboot,
}

impl DpuAgentFsm {
    pub fn event(self, event: Event) -> (Self, Vec<Action>) {
        match self {
            Self::Discovery => self.fsm_discovery(event),
            Self::AgentControl => self.fsm_agent_control(event),
            Self::NetworkObservation => self.fsm_network_observation(event),
            Self::FailedAndWaitForReboot => (self, vec![]),
        }
    }

    pub fn fsm_discovery(self, event: Event) -> (Self, Vec<Action>) {
        match event {
            Event::InitialDiscoveryCompleted => (
                Self::AgentControl,
                vec![Action::AgentControlRequest(OsImage::DpuAgent)],
            ),
            Event::MachineNotFound => (Self::FailedAndWaitForReboot, vec![]),
            _ => (self, vec![]),
        }
    }

    pub fn fsm_agent_control(self, event: Event) -> (Self, Vec<Action>) {
        match event {
            Event::TimerAlert(Timer::DpuAgentControlPoll) => {
                (self, vec![Action::AgentControlRequest(OsImage::DpuAgent)])
            }
            Event::AgentControlCompleted => (
                Self::NetworkObservation,
                vec![Action::DpuAgentNetworkObservation],
            ),
            Event::MachineNotFound => (Self::FailedAndWaitForReboot, vec![]),
            _ => (self, vec![]),
        }
    }

    pub fn fsm_network_observation(self, event: Event) -> (Self, Vec<Action>) {
        match event {
            Event::NetworkObservationCompleted => (
                Self::AgentControl,
                vec![Action::SetTimer(Timer::DpuAgentControlPoll)],
            ),
            Event::MachineNotFound => (Self::FailedAndWaitForReboot, vec![]),
            _ => (self, vec![]),
        }
    }
}
