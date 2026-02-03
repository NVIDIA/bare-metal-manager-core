/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::path::PathBuf;
use std::process::Stdio;
use std::str::FromStr;

use crossterm::ExecutableCommand;
use crossterm::event::{EnableMouseCapture, KeyCode, KeyEvent, KeyModifiers};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
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
    Overrides(OverrideState),
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
            Self::Subnets { .. } => Self::Overrides(OverrideState::default()),
            Self::Overrides(_) => Self::Machines {
                tab: MachinesTab::default(),
                list_state: ListState::default(),
                focused: false,
            },
        }
    }
    pub fn prev(&mut self) {
        *self = match self {
            Self::Machines { .. } => Self::Overrides(OverrideState::default()),
            Self::VPCs { .. } => Self::Machines {
                tab: MachinesTab::default(),
                list_state: ListState::default(),
                focused: false,
            },
            Self::Subnets { .. } => Self::VPCs {
                list_state: ListState::default(),
            },
            Self::Overrides(_) => Self::Subnets {
                list_state: ListState::default(),
            },
        }
    }
    pub fn titles() -> [&'static str; 4] {
        ["Machines", "VPCs", "Subnets", "Response Overrides"]
    }
    /// Returns whether or not the key was handled and whether or not the selected
    /// machine changed.
    pub fn handle_key(
        &mut self,
        terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
        data: &mut TuiData,
        key: KeyEvent,
    ) -> (bool, bool) {
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
        if let Tab::Overrides(state) = self
            && state.handle_key(terminal, data, key)
        {
            return (true, false);
        }

        match key.code {
            KeyCode::Up => match self {
                Tab::Machines { list_state, .. } => {
                    wrap_line(list_state, data.machine_cache.len(), true);
                    return (true, true);
                }
                Tab::VPCs { list_state } => wrap_line(list_state, data.vpc_cache.len(), true),
                Tab::Subnets { list_state } => wrap_line(list_state, data.subnet_cache.len(), true),
                Tab::Overrides(_) => {}
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
                Tab::Overrides(_) => {}
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
            Tab::Overrides(_) => 3,
        }
    }
}

#[derive(Default, Clone)]
pub struct OverrideState {
    mode: OverrideMode,
    pub list_state: ListState,
    pub scroll_offset: u16,
}

impl OverrideState {
    pub fn focused(&self) -> bool {
        matches!(
            self.mode,
            OverrideMode::Focused | OverrideMode::Editing { .. }
        )
    }
    pub fn scroll_focused(&self) -> bool {
        self.mode == OverrideMode::Scrolling
    }
    pub fn get_cursor_offset(&self) -> Option<(u16, u16)> {
        if let OverrideMode::Editing { cursor, .. } = self.mode {
            Some((cursor as u16, self.list_state.selected().unwrap() as u16))
        } else {
            None
        }
    }
    pub fn get_selected(&self) -> Option<usize> {
        if let OverrideMode::Unfocused = self.mode {
            return None;
        }
        self.list_state.selected()
    }

    /// Returns if the key was handled.
    fn handle_key(
        &mut self,
        terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
        data: &mut TuiData,
        key: KeyEvent,
    ) -> bool {
        let start_list_state = self.list_state.selected();
        match &mut self.mode {
            OverrideMode::Unfocused => match key.code {
                KeyCode::Down => {
                    if !data.overrides.is_empty() {
                        self.list_state = ListState::default().with_selected(Some(0));
                    }
                    self.mode = OverrideMode::Focused
                }
                _ => return false,
            },
            OverrideMode::Focused => match key.code {
                KeyCode::Left | KeyCode::Right => return false,
                KeyCode::Char('i') => {
                    if let Some(index) = self.list_state.selected() {
                        self.mode = OverrideMode::Editing {
                            original_text: data.overrides[index].clone(),
                            cursor: data.overrides[index].len(),
                        };
                    }
                }
                KeyCode::Esc => {
                    self.list_state = ListState::default();
                    self.mode = OverrideMode::Unfocused
                }
                KeyCode::Enter => self.mode = OverrideMode::Scrolling,
                KeyCode::Up => wrap_line(&mut self.list_state, data.overrides.len(), true),
                KeyCode::Down => wrap_line(&mut self.list_state, data.overrides.len(), false),
                KeyCode::Backspace => {
                    if let Some(index) = self.list_state.selected() {
                        let path = data.overrides.remove(index);
                        if let Some(_original) = data.original_routes.get(&path) {
                            // TODO: cleanup overrides with path.
                            tracing::error!("Not implemented clear override");
                        }
                        if data.overrides.is_empty() {
                            self.list_state = ListState::default();
                        } else {
                            self.list_state.select(Some(index.saturating_sub(1)))
                        }
                    }
                }
                // Open an editor to modify the MAT response.
                KeyCode::Char('e') if self.get_selected().is_some() => {
                    let selected = self.get_selected().unwrap();
                    let request = |path| {
                        // TODO: overrides: implement request to the API.
                        Some(format!(
                            "TODO not implemented getting routes from path. Path was: {path}"
                        ))
                    };
                    if let Some(response) = request(&data.overrides[selected]) {
                        let path = format!(
                            "/tmp/machine-a-tron/rewrite/{}/index.json",
                            data.overrides[selected]
                        );
                        // Save the original in case we remove the override.
                        data.original_routes
                            .insert(data.overrides[selected].clone(), response.clone());
                        let path_buf = PathBuf::from_str(&path).unwrap();
                        std::fs::create_dir_all(path_buf.parent().unwrap())
                            .expect("could not create tempfile directory");
                        std::fs::write(&path, response).expect("could not write to tempfile");

                        // User edits file.
                        let editor = std::env::var("EDITOR").unwrap_or("/usr/bin/vim".to_string());
                        std::process::Command::new(editor)
                            .arg(&path)
                            .stdin(Stdio::inherit())
                            .stdout(Stdio::inherit())
                            .stderr(Stdio::inherit())
                            .output()
                            .unwrap();

                        // Reenable mouse capture (editors like helix disable
                        // capture on exit).
                        let mut stdout = std::io::stdout();
                        stdout.execute(EnableMouseCapture).unwrap();

                        // Read back modified response from file.
                        // TODO: validate the response is valid JSON
                        // and maybe validate if is valid redfish response.
                        let content =
                            std::fs::read_to_string(path).expect("could not read from tempfile");
                        // TODO: overrides: implement overrides.
                        tracing::error!(
                            "Applying overrides is not implemented yet. Content was: {content}"
                        );
                    }
                    // Fully redraw TUI next frame.
                    terminal.clear().unwrap();
                }
                KeyCode::Char('a') => {
                    let index = self.list_state.selected().map(|i| i + 1).unwrap_or(0);
                    data.overrides.insert(index, String::new());
                    self.list_state.select(Some(index));
                    self.mode = OverrideMode::Editing {
                        original_text: String::new(),
                        cursor: 0,
                    };
                }
                _ => return false,
            },
            OverrideMode::Editing {
                original_text,
                cursor,
            } => {
                let index = self
                    .list_state
                    .selected()
                    .expect("if editing overrides, should have selected an option");
                let target = &mut data.overrides[index];
                match key.code {
                    KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        *target = target.split_at(*cursor).1.to_string();
                        *cursor = 0
                    }
                    KeyCode::Delete => {
                        target.truncate(*cursor);
                    }
                    KeyCode::Char(c) => {
                        target.insert(*cursor, c);
                        *cursor += 1;
                    }
                    KeyCode::Backspace => {
                        if !target.is_empty() && *cursor > 0 {
                            target.remove(*cursor - 1);
                            *cursor -= 1;
                        }
                    }
                    KeyCode::Left => *cursor = cursor.saturating_sub(1),
                    KeyCode::Right => *cursor = (*cursor + 1).min(target.len()),
                    KeyCode::Enter => {
                        // TODO: handle duplicate overrides

                        // Reset the original override if overriden.
                        if let Some(original) = data.original_routes.get(original_text) {
                            // TODO: overrides: clear overrides on original_text
                            tracing::error!("Not implemented clear override: original {original}");
                        }
                        self.mode = OverrideMode::Focused
                    }
                    KeyCode::Esc => {
                        *target = original_text.clone();
                        self.mode = OverrideMode::Focused
                    }
                    // Swallow all other keys.
                    _ => return true,
                }
                // Remove the override if we exited editing mode and the
                // submitted path is empty.
                if !matches!(self.mode, OverrideMode::Editing { .. }) && target.is_empty() {
                    data.overrides.remove(index);
                    self.list_state.select(if !data.overrides.is_empty() {
                        self.list_state
                            .selected()
                            .map(|i| i.min(data.overrides.len() - 1))
                    } else {
                        None
                    })
                }
            }
            OverrideMode::Scrolling => match key.code {
                KeyCode::Down => self.scroll_offset = self.scroll_offset.saturating_add(1),
                KeyCode::Up => self.scroll_offset = self.scroll_offset.saturating_sub(1),
                KeyCode::Esc => self.mode = OverrideMode::Focused,
                _ => return false,
            },
        }
        // If we changed which override is selected, then reset preview scroll.
        if self.list_state.selected() != start_list_state {
            self.scroll_offset = 0;
        }

        true
    }
}

#[derive(Default, Clone, PartialEq, Eq)]
enum OverrideMode {
    #[default]
    Unfocused,
    Focused,
    Editing {
        original_text: String,
        cursor: usize,
    },
    Scrolling,
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
