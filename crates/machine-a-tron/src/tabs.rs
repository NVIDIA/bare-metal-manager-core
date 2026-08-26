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

#[derive(Default, Clone)]
pub enum MachinesTab {
    #[default]
    Details,
    Logs,
}

impl MachinesTab {
    pub fn next(&mut self) {
        *self = match self {
            Self::Details => Self::Logs,
            Self::Logs => Self::Details,
        }
    }
    pub fn prev(&mut self) {
        *self = match self {
            Self::Details => Self::Logs,
            Self::Logs => Self::Details,
        }
    }
    pub fn get_title(&self) -> &'static str {
        match self {
            Self::Details => "Machine Details",
            Self::Logs => "Logs (newest on top)",
        }
    }
    pub fn all() -> [Self; 2] {
        [Self::Details, Self::Logs]
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> bool {
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
        }
    }
}
