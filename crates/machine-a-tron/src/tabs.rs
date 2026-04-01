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

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::widgets::ListState;

use crate::tui::TuiData;

pub enum Tab {
    Machines {
        focused: bool,
        list_state: ListState,
        tab: MachinesTab,
    },
    VPCs {
        list_state: ListState,
    },
    Subnets {
        list_state: ListState,
    },
}

impl Default for Tab {
    fn default() -> Self {
        Self::Machines {
            focused: false,
            list_state: ListState::default(),
            tab: MachinesTab::default(),
        }
    }
}

impl Tab {
    pub fn next(&mut self) {
        *self = match self {
            Self::Machines { .. } => Self::VPCs {
                list_state: ListState::default(),
            },
            Self::VPCs { .. } => Self::Subnets {
                list_state: ListState::default(),
            },
            Self::Subnets { .. } => Self::Machines {
                tab: MachinesTab::default(),
                list_state: ListState::default(),
                focused: false,
            },
        }
    }
    pub fn prev(&mut self) {
        *self = match self {
            Self::Machines { .. } => Self::Subnets {
                list_state: ListState::default(),
            },
            Self::VPCs { .. } => Self::Machines {
                tab: MachinesTab::default(),
                list_state: ListState::default(),
                focused: false,
            },
            Self::Subnets { .. } => Self::VPCs {
                list_state: ListState::default(),
            },
        }
    }
    pub fn titles() -> [&'static str; 3] {
        ["Machines", "VPCs", "Subnets"]
    }
    /// Returns whether or not the key was handled and whether or not the selected
    /// machine changed.
    pub fn handle_key(&mut self, data: &mut TuiData, key: KeyEvent) -> (bool, bool) {
        if let Tab::Machines {
            focused: true, tab, ..
        } = self
        {
            // Let the machines tab try to handle.
            if tab.handle_key(data, key) {
                return (true, false);
            }
            // If it doesn't handle, then we continue handling.
        }

        match key.code {
            KeyCode::Up => match self {
                Tab::Machines { list_state, .. } => {
                    wrap_line(list_state, data.machine_cache.len(), true);
                    return (true, true);
                }
                Tab::VPCs { list_state } => wrap_line(list_state, data.vpc_cache.len(), true),
                Tab::Subnets { list_state } => wrap_line(list_state, data.subnet_cache.len(), true),
            },
            KeyCode::Down => match self {
                Tab::Machines { list_state, .. } => {
                    wrap_line(list_state, data.machine_cache.len(), false);
                    return (true, true);
                }
                Tab::VPCs { list_state } => wrap_line(list_state, data.vpc_cache.len(), false),
                Tab::Subnets { list_state } => {
                    wrap_line(list_state, data.subnet_cache.len(), false)
                }
            },
            KeyCode::Left => self.prev(),
            KeyCode::Right => self.next(),
            KeyCode::Enter => {
                if let Tab::Machines { focused, .. } = self {
                    *focused = true;
                }
            }
            KeyCode::Esc => {
                if let Tab::Machines { focused, .. } = self {
                    *focused = false;
                }
            }
            _ => return (false, false),
        };
        (true, false)
    }
}

impl From<&Tab> for u8 {
    fn from(value: &Tab) -> Self {
        match value {
            Tab::Machines { .. } => 0,
            Tab::VPCs { .. } => 1,
            Tab::Subnets { .. } => 2,
        }
    }
}

#[derive(Default, Clone)]
pub enum MachinesTab {
    #[default]
    Details,
    Logs,
    Metrics,
}

impl MachinesTab {
    pub fn next(&mut self) {
        *self = match self {
            Self::Details => Self::Logs,
            Self::Logs => Self::Metrics,
            Self::Metrics => Self::Details,
        }
    }
    pub fn prev(&mut self) {
        *self = match self {
            Self::Details => Self::Metrics,
            Self::Logs => Self::Details,
            Self::Metrics => Self::Logs,
        }
    }
    pub fn get_title(&self) -> &'static str {
        match self {
            Self::Details => "Machine Details",
            Self::Logs => "Logs (newest on top)",
            Self::Metrics => "Metrics",
        }
    }
    pub fn all() -> [Self; 3] {
        [Self::Details, Self::Logs, Self::Metrics]
    }

    fn handle_key(&mut self, _data: &mut TuiData, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Left => self.prev(),
            KeyCode::Right => self.next(),
            _ => return false,
        }
        true
    }
}

impl From<&MachinesTab> for u8 {
    fn from(value: &MachinesTab) -> Self {
        match value {
            MachinesTab::Details => 0,
            MachinesTab::Logs => 1,
            MachinesTab::Metrics => 2,
        }
    }
}
/// Handle up or down inside a list, wrapping at the top and bottom.
fn wrap_line(list_state: &mut ListState, len: usize, increment: bool) {
    if len > 0 {
        list_state.select(Some(
            list_state
                .selected()
                .map(|v| {
                    if increment {
                        if v > 0 { v - 1 } else { len - 1 }
                    } else if v < len - 1 {
                        v + 1
                    } else {
                        0
                    }
                })
                .unwrap_or(if increment { len - 1 } else { 0 }),
        ))
    }
}
