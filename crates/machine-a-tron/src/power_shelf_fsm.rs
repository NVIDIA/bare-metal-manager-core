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

type FsmReturn = (PowerShelfFsm, Vec<Action>);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PowerShelfFsm {
    BmcInit {
        power_on: bool,
        power_cycle_pending: bool,
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

impl PowerShelfFsm {
    pub(super) fn init(power_on: bool) -> FsmReturn {
        (
            Self::BmcInit {
                power_on,
                power_cycle_pending: false,
                paused: true,
            },
            vec![Action::Dhcp],
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
            | Self::DeviceUp { paused }
            | Self::DeviceDown { paused, .. } => *paused,
        }
    }

    pub(super) fn power_state(&self) -> MockPowerState {
        match self {
            Self::BmcInit { power_on: true, .. } | Self::DeviceUp { .. } => MockPowerState::On,
            Self::BmcInit {
                power_on: false, ..
            }
            | Self::DeviceDown { .. } => MockPowerState::Off,
        }
    }

    pub(super) fn state_string(&self) -> &'static str {
        match self {
            Self::BmcInit { .. } => "BmcInit",
            Self::DeviceUp { .. } => "BmcOnly/DeviceUp",
            Self::DeviceDown { .. } => "BmcOnly/DeviceDown",
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
            Event::DhcpComplete => (
                if power_on {
                    Self::DeviceUp { paused }
                } else {
                    Self::DeviceDown {
                        power_cycle_pending,
                        paused,
                    }
                },
                vec![Action::SetupBmc],
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
            Event::Pause | Event::Resume => unreachable!("handled before state dispatch"),
        }
    }

    fn fsm_device_up(self, event: Event, paused: bool) -> FsmReturn {
        match event {
            Event::PowerOff => (
                Self::DeviceDown {
                    power_cycle_pending: false,
                    paused,
                },
                vec![],
            ),
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

    fn fsm_device_down(self, event: Event, power_cycle_pending: bool, paused: bool) -> FsmReturn {
        match event {
            Event::PowerOn => (
                Self::DeviceUp { paused },
                cancel_timer_action(power_cycle_pending),
            ),
            Event::PowerOff => (
                Self::DeviceDown {
                    power_cycle_pending: false,
                    paused,
                },
                cancel_timer_action(power_cycle_pending),
            ),
            Event::TimerAlert(Timer::PowerCycle) if power_cycle_pending => {
                (Self::DeviceUp { paused }, vec![])
            }
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
    DhcpComplete,
    PowerOn,
    PowerOff,
    PowerCycle,
    TimerAlert(Timer),
    Pause,
    Resume,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Action {
    Dhcp,
    SetupBmc,
    SetTimer(Timer),
    CancelTimer(Timer),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Timer {
    PowerCycle,
}

#[cfg(test)]
mod tests {
    use carbide_test_support::{Check, check_values};

    use super::*;

    #[test]
    fn power_shelf_transitions() {
        check_values(
            [
                Check {
                    scenario: "new power shelf completes BMC DHCP powered off",
                    input: (
                        PowerShelfFsm::BmcInit {
                            power_on: false,
                            power_cycle_pending: false,
                            paused: false,
                        },
                        Event::DhcpComplete,
                    ),
                    expect: (
                        PowerShelfFsm::DeviceDown {
                            power_cycle_pending: false,
                            paused: false,
                        },
                        vec![Action::SetupBmc],
                    ),
                },
                Check {
                    scenario: "persisted power shelf completes BMC DHCP powered on",
                    input: (
                        PowerShelfFsm::BmcInit {
                            power_on: true,
                            power_cycle_pending: false,
                            paused: false,
                        },
                        Event::DhcpComplete,
                    ),
                    expect: (
                        PowerShelfFsm::DeviceUp { paused: false },
                        vec![Action::SetupBmc],
                    ),
                },
                Check {
                    scenario: "powered shelf begins a power cycle",
                    input: (PowerShelfFsm::DeviceUp { paused: false }, Event::PowerCycle),
                    expect: (
                        PowerShelfFsm::DeviceDown {
                            power_cycle_pending: true,
                            paused: false,
                        },
                        vec![Action::SetTimer(Timer::PowerCycle)],
                    ),
                },
                Check {
                    scenario: "power-cycle timer restores power",
                    input: (
                        PowerShelfFsm::DeviceDown {
                            power_cycle_pending: true,
                            paused: false,
                        },
                        Event::TimerAlert(Timer::PowerCycle),
                    ),
                    expect: (PowerShelfFsm::DeviceUp { paused: false }, vec![]),
                },
                Check {
                    scenario: "explicit power-on cancels a pending power cycle",
                    input: (
                        PowerShelfFsm::DeviceDown {
                            power_cycle_pending: true,
                            paused: false,
                        },
                        Event::PowerOn,
                    ),
                    expect: (
                        PowerShelfFsm::DeviceUp { paused: false },
                        vec![Action::CancelTimer(Timer::PowerCycle)],
                    ),
                },
                Check {
                    scenario: "a new power cycle replaces the pending timer",
                    input: (
                        PowerShelfFsm::DeviceDown {
                            power_cycle_pending: true,
                            paused: false,
                        },
                        Event::PowerCycle,
                    ),
                    expect: (
                        PowerShelfFsm::DeviceDown {
                            power_cycle_pending: true,
                            paused: false,
                        },
                        vec![Action::SetTimer(Timer::PowerCycle)],
                    ),
                },
                Check {
                    scenario: "power-shelf processing can be paused",
                    input: (PowerShelfFsm::DeviceUp { paused: false }, Event::Pause),
                    expect: (PowerShelfFsm::DeviceUp { paused: true }, vec![]),
                },
                Check {
                    scenario: "power-shelf processing can be resumed",
                    input: (
                        PowerShelfFsm::DeviceDown {
                            power_cycle_pending: false,
                            paused: true,
                        },
                        Event::Resume,
                    ),
                    expect: (
                        PowerShelfFsm::DeviceDown {
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
        let (fsm, _) = PowerShelfFsm::DeviceUp { paused: false }.event(Event::PowerCycle);
        let (fsm, actions) = fsm.event(Event::PowerOff);
        assert_eq!(
            (fsm, actions,),
            (
                PowerShelfFsm::DeviceDown {
                    power_cycle_pending: false,
                    paused: false,
                },
                vec![Action::CancelTimer(Timer::PowerCycle)],
            )
        );

        let (fsm, actions) = fsm.event(Event::TimerAlert(Timer::PowerCycle));
        assert_eq!(
            (fsm, actions,),
            (
                PowerShelfFsm::DeviceDown {
                    power_cycle_pending: false,
                    paused: false,
                },
                vec![],
            )
        );
    }
}
