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
use bmc_mock::MockPowerState;

type FsmReturn = (SwitchFsm, Vec<Action>);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SwitchFsm {
    BmcInit {
        power_on: bool,
        power_cycle_pending: bool,
        paused: bool,
    },
    NvosInit {
        paused: bool,
    },
    DeviceUp {
        paused: bool,
    },
    DeviceDown {
        power_cycle_pending: bool,
        paused: bool,
    },
}

impl SwitchFsm {
    pub(super) fn init(power_on: bool) -> FsmReturn {
        (
            Self::BmcInit {
                power_on,
                power_cycle_pending: false,
                paused: true,
            },
            vec![Action::Dhcp(DhcpEndpoint::Bmc)],
        )
    }

    pub(super) fn event(self, event: Event) -> FsmReturn {
        match event {
            Event::Pause => return (self.with_paused(true), vec![]),
            Event::Resume => return (self.with_paused(false), vec![]),
            _ => {}
        }

        match self {
            Self::BmcInit {
                power_on,
                power_cycle_pending,
                paused,
            } => self.fsm_bmc_init(event, power_on, power_cycle_pending, paused),
            Self::NvosInit { paused } => self.fsm_nvos_init(event, paused),
            Self::DeviceUp { paused } => self.fsm_device_up(event, paused),
            Self::DeviceDown {
                power_cycle_pending,
                paused,
            } => self.fsm_device_down(event, power_cycle_pending, paused),
        }
    }

    pub(super) fn is_paused(&self) -> bool {
        match self {
            Self::BmcInit { paused, .. }
            | Self::NvosInit { paused }
            | Self::DeviceUp { paused }
            | Self::DeviceDown { paused, .. } => *paused,
        }
    }

    pub(super) fn power_state(&self) -> MockPowerState {
        match self {
            Self::BmcInit { power_on: true, .. }
            | Self::NvosInit { .. }
            | Self::DeviceUp { .. } => MockPowerState::On,
            Self::BmcInit {
                power_on: false, ..
            }
            | Self::DeviceDown { .. } => MockPowerState::Off,
        }
    }

    pub(super) fn state_string(&self) -> &'static str {
        match self {
            Self::BmcInit { .. } => "BmcInit",
            Self::NvosInit { .. } => "NvosInit",
            Self::DeviceUp { .. } => "DeviceUp",
            Self::DeviceDown { .. } => "DeviceDown",
        }
    }

    fn with_paused(self, paused: bool) -> Self {
        match self {
            Self::BmcInit {
                power_on,
                power_cycle_pending,
                ..
            } => Self::BmcInit {
                power_on,
                power_cycle_pending,
                paused,
            },
            Self::NvosInit { .. } => Self::NvosInit { paused },
            Self::DeviceUp { .. } => Self::DeviceUp { paused },
            Self::DeviceDown {
                power_cycle_pending,
                ..
            } => Self::DeviceDown {
                power_cycle_pending,
                paused,
            },
        }
    }

    fn fsm_bmc_init(
        self,
        event: Event,
        power_on: bool,
        power_cycle_pending: bool,
        paused: bool,
    ) -> FsmReturn {
        match event {
            Event::DhcpComplete(DhcpEndpoint::Bmc) => (
                if power_on {
                    Self::NvosInit { paused }
                } else {
                    Self::DeviceDown {
                        power_cycle_pending,
                        paused,
                    }
                },
                if power_on {
                    vec![Action::SetupBmc, Action::Dhcp(DhcpEndpoint::Nvos)]
                } else {
                    vec![Action::SetupBmc]
                },
            ),
            Event::PowerOn => (
                Self::BmcInit {
                    power_on: true,
                    power_cycle_pending: false,
                    paused,
                },
                cancel_timer_action(power_cycle_pending),
            ),
            Event::PowerOff => (
                Self::BmcInit {
                    power_on: false,
                    power_cycle_pending: false,
                    paused,
                },
                cancel_timer_action(power_cycle_pending),
            ),
            Event::PowerCycle => (
                Self::BmcInit {
                    power_on: false,
                    power_cycle_pending: true,
                    paused,
                },
                vec![Action::SetTimer(Timer::PowerCycle)],
            ),
            Event::TimerAlert(Timer::PowerCycle) if power_cycle_pending => (
                Self::BmcInit {
                    power_on: true,
                    power_cycle_pending: false,
                    paused,
                },
                vec![],
            ),
            Event::TimerAlert(Timer::PowerCycle) => (self, vec![]),
            Event::DhcpComplete(DhcpEndpoint::Nvos) => (self, vec![]),
            Event::Pause | Event::Resume => unreachable!("handled before state dispatch"),
        }
    }

    fn fsm_nvos_init(self, event: Event, paused: bool) -> FsmReturn {
        match event {
            Event::DhcpComplete(DhcpEndpoint::Nvos) => (Self::DeviceUp { paused }, vec![]),
            Event::PowerOff => (
                Self::DeviceDown {
                    power_cycle_pending: false,
                    paused,
                },
                vec![Action::StopNvos],
            ),
            Event::PowerCycle => (
                Self::DeviceDown {
                    power_cycle_pending: true,
                    paused,
                },
                vec![Action::StopNvos, Action::SetTimer(Timer::PowerCycle)],
            ),
            _ => (self, vec![]),
        }
    }

    fn fsm_device_up(self, event: Event, paused: bool) -> FsmReturn {
        match event {
            Event::PowerOff => (
                Self::DeviceDown {
                    power_cycle_pending: false,
                    paused,
                },
                vec![Action::StopNvos],
            ),
            Event::PowerCycle => (
                Self::DeviceDown {
                    power_cycle_pending: true,
                    paused,
                },
                vec![Action::StopNvos, Action::SetTimer(Timer::PowerCycle)],
            ),
            _ => (self, vec![]),
        }
    }

    fn fsm_device_down(self, event: Event, power_cycle_pending: bool, paused: bool) -> FsmReturn {
        match event {
            Event::PowerOn => (
                Self::NvosInit { paused },
                cancel_timer_action(power_cycle_pending)
                    .into_iter()
                    .chain([Action::Dhcp(DhcpEndpoint::Nvos)])
                    .collect(),
            ),
            Event::PowerOff => (
                Self::DeviceDown {
                    power_cycle_pending: false,
                    paused,
                },
                cancel_timer_action(power_cycle_pending),
            ),
            Event::TimerAlert(Timer::PowerCycle) if power_cycle_pending => (
                Self::NvosInit { paused },
                vec![Action::Dhcp(DhcpEndpoint::Nvos)],
            ),
            Event::TimerAlert(Timer::PowerCycle) => (self, vec![]),
            Event::PowerCycle => (
                Self::DeviceDown {
                    power_cycle_pending: true,
                    paused,
                },
                vec![Action::SetTimer(Timer::PowerCycle)],
            ),
            _ => (self, vec![]),
        }
    }
}

fn cancel_timer_action(power_cycle_pending: bool) -> Vec<Action> {
    if power_cycle_pending {
        vec![Action::CancelTimer(Timer::PowerCycle)]
    } else {
        vec![]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Event {
    DhcpComplete(DhcpEndpoint),
    PowerOn,
    PowerOff,
    PowerCycle,
    TimerAlert(Timer),
    Pause,
    Resume,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Action {
    Dhcp(DhcpEndpoint),
    SetupBmc,
    StopNvos,
    SetTimer(Timer),
    CancelTimer(Timer),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Timer {
    PowerCycle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DhcpEndpoint {
    Bmc,
    Nvos,
}

#[cfg(test)]
mod tests {
    use carbide_test_support::{Check, check_values};

    use super::*;

    #[test]
    fn switch_transitions() {
        check_values(
            [
                Check {
                    scenario: "new switch completes BMC DHCP powered off",
                    input: (
                        SwitchFsm::BmcInit {
                            power_on: false,
                            power_cycle_pending: false,
                            paused: false,
                        },
                        Event::DhcpComplete(DhcpEndpoint::Bmc),
                    ),
                    expect: (
                        SwitchFsm::DeviceDown {
                            power_cycle_pending: false,
                            paused: false,
                        },
                        vec![Action::SetupBmc],
                    ),
                },
                Check {
                    scenario: "persisted switch completes BMC DHCP powered on",
                    input: (
                        SwitchFsm::BmcInit {
                            power_on: true,
                            power_cycle_pending: false,
                            paused: false,
                        },
                        Event::DhcpComplete(DhcpEndpoint::Bmc),
                    ),
                    expect: (
                        SwitchFsm::NvosInit { paused: false },
                        vec![Action::SetupBmc, Action::Dhcp(DhcpEndpoint::Nvos)],
                    ),
                },
                Check {
                    scenario: "NVOS DHCP completes switch startup",
                    input: (
                        SwitchFsm::NvosInit { paused: false },
                        Event::DhcpComplete(DhcpEndpoint::Nvos),
                    ),
                    expect: (SwitchFsm::DeviceUp { paused: false }, vec![]),
                },
                Check {
                    scenario: "powered switch begins a power cycle",
                    input: (SwitchFsm::DeviceUp { paused: false }, Event::PowerCycle),
                    expect: (
                        SwitchFsm::DeviceDown {
                            power_cycle_pending: true,
                            paused: false,
                        },
                        vec![Action::StopNvos, Action::SetTimer(Timer::PowerCycle)],
                    ),
                },
                Check {
                    scenario: "power-cycle timer restores power",
                    input: (
                        SwitchFsm::DeviceDown {
                            power_cycle_pending: true,
                            paused: false,
                        },
                        Event::TimerAlert(Timer::PowerCycle),
                    ),
                    expect: (
                        SwitchFsm::NvosInit { paused: false },
                        vec![Action::Dhcp(DhcpEndpoint::Nvos)],
                    ),
                },
                Check {
                    scenario: "explicit power-on cancels a pending power cycle",
                    input: (
                        SwitchFsm::DeviceDown {
                            power_cycle_pending: true,
                            paused: false,
                        },
                        Event::PowerOn,
                    ),
                    expect: (
                        SwitchFsm::NvosInit { paused: false },
                        vec![
                            Action::CancelTimer(Timer::PowerCycle),
                            Action::Dhcp(DhcpEndpoint::Nvos),
                        ],
                    ),
                },
                Check {
                    scenario: "a new power cycle replaces the pending timer",
                    input: (
                        SwitchFsm::DeviceDown {
                            power_cycle_pending: true,
                            paused: false,
                        },
                        Event::PowerCycle,
                    ),
                    expect: (
                        SwitchFsm::DeviceDown {
                            power_cycle_pending: true,
                            paused: false,
                        },
                        vec![Action::SetTimer(Timer::PowerCycle)],
                    ),
                },
                Check {
                    scenario: "power off while NVOS starts leaves the switch down",
                    input: (SwitchFsm::NvosInit { paused: false }, Event::PowerOff),
                    expect: (
                        SwitchFsm::DeviceDown {
                            power_cycle_pending: false,
                            paused: false,
                        },
                        vec![Action::StopNvos],
                    ),
                },
                Check {
                    scenario: "switch processing can be paused",
                    input: (SwitchFsm::DeviceUp { paused: false }, Event::Pause),
                    expect: (SwitchFsm::DeviceUp { paused: true }, vec![]),
                },
                Check {
                    scenario: "switch processing can be resumed",
                    input: (
                        SwitchFsm::DeviceDown {
                            power_cycle_pending: false,
                            paused: true,
                        },
                        Event::Resume,
                    ),
                    expect: (
                        SwitchFsm::DeviceDown {
                            power_cycle_pending: false,
                            paused: false,
                        },
                        vec![],
                    ),
                },
            ],
            |(fsm, event)| fsm.event(event),
        );
    }

    #[test]
    fn power_off_supersedes_power_cycle() {
        let (fsm, _) = SwitchFsm::DeviceUp { paused: false }.event(Event::PowerCycle);
        let (fsm, actions) = fsm.event(Event::PowerOff);
        assert_eq!(
            (fsm, actions),
            (
                SwitchFsm::DeviceDown {
                    power_cycle_pending: false,
                    paused: false,
                },
                vec![Action::CancelTimer(Timer::PowerCycle)],
            )
        );

        let (fsm, actions) = fsm.event(Event::TimerAlert(Timer::PowerCycle));
        assert_eq!(
            (fsm, actions),
            (
                SwitchFsm::DeviceDown {
                    power_cycle_pending: false,
                    paused: false,
                },
                vec![],
            )
        );
    }
}
