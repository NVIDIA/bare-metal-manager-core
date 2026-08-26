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
use std::borrow::Cow;
use std::collections::HashMap;
use std::error::Error;
use std::time::Duration;

use bmc_mock::{HardwareType, MockPowerState};
use crossterm::ExecutableCommand;
use crossterm::event::{self, Event, EventStream, KeyCode, KeyModifiers};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use futures::StreamExt;
use ratatui::prelude::*;
use ratatui::symbols::DOT;
use ratatui::widgets::*;
use tokio::select;
use tokio::sync::mpsc::{Receiver, Sender};
use uuid::Uuid;

use crate::TuiHostLogs;
use crate::tabs::MachinesTab;

#[derive(Default)]
pub struct HostDetails {
    pub mat_id: Uuid,
    pub machine_id: Option<String>,
    pub hw_type: Option<HardwareType>,
    pub power_state: MockPowerState,
    pub mat_state: Option<&'static str>,
    pub api_state: String,
    pub oob_ip: String,
    pub machine_ip: String,
    pub dpus: Vec<HostDetails>,
    pub booted_os: String,
    pub next_boot_kind: Cow<'static, str>,
}

impl HostDetails {
    fn header(&self) -> String {
        format!(
            "{}: {}/{}",
            self.machine_id
                .clone()
                .unwrap_or_else(|| self.mat_id.to_string()),
            self.mat_state.unwrap_or("Unknown"),
            self.api_state
        )
    }
    fn details(&self) -> String {
        let mut result = String::with_capacity(1024);

        [
            &format!("MAT ID: {}\n", self.mat_id),
            &format!(
                "Machine ID: {}\n",
                self.machine_id.as_deref().unwrap_or_default()
            ),
            &self
                .hw_type
                .map(|t| format!("Hardware type: {t}\n"))
                .unwrap_or_default(),
            &format!("Machine IP: {}\n", self.machine_ip),
            &format!("BMC IP: {}\n", self.oob_ip),
            &format!("Power State: {}\n", self.power_state),
            &format!("Booted OS: {}\n", self.booted_os),
            &format!("Next boot: {}\n", self.next_boot_kind),
            &format!("MAT State: {}\n", self.mat_state.unwrap_or("Unknown")),
            &format!("API State: {}\n", self.api_state),
        ]
        .into_iter()
        .for_each(|v| result.push_str(v));

        if !self.dpus.is_empty() {
            result.push('\n');
            result.push_str("DPUs:\n");
            for d in self.dpus.iter() {
                result.push('\n');
                result.push_str(&d.details());
            }
        }
        result
    }
}

pub enum UiUpdate {
    Machine(HostDetails),
}

pub struct Tui {
    /// The stored data of the ui.
    data: TuiData,
    list_state: ListState,
    machine_details_focused: bool,
    machine_tab: MachinesTab,
    /// A handle to a TuiHostLogs where logs for hosts are stored
    host_logs: Option<TuiHostLogs>,
}

struct TuiData {
    event_rx: Receiver<UiUpdate>,
    quit_rx: Receiver<()>,
    stop_tx: Sender<()>,
    machine_cache: HashMap<Uuid, HostDetails>,
    machine_details: String,
    machine_logs: String,
}

impl Tui {
    pub fn new(
        event_rx: Receiver<UiUpdate>,
        quit_rx: Receiver<()>,
        stop_tx: Sender<()>,
        host_logs: Option<TuiHostLogs>,
    ) -> Self {
        Self {
            data: TuiData {
                event_rx,
                quit_rx,
                stop_tx,
                machine_cache: HashMap::default(),
                machine_details: String::default(),
                machine_logs: String::default(),
            },
            list_state: ListState::default(),
            machine_details_focused: false,
            machine_tab: MachinesTab::default(),
            host_logs,
        }
    }
    fn setup_terminal() -> Result<Terminal<CrosstermBackend<std::io::Stdout>>, std::io::Error> {
        enable_raw_mode()?;
        let mut stdout = std::io::stdout();
        stdout.execute(EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout);
        Terminal::new(backend)
    }

    fn teardown_terminal(
        terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    ) -> Result<(), std::io::Error> {
        disable_raw_mode()?;
        let mut stdout = std::io::stdout();
        stdout.execute(LeaveAlternateScreen)?;
        terminal.show_cursor()?;
        Ok(())
    }

    async fn handle_event(&mut self, event: Event) -> bool {
        match event {
            Event::Key(key) => {
                // Handle global triggers.
                if key.kind == event::KeyEventKind::Press {
                    let machine_changed = self.handle_key(key);
                    if key.code == KeyCode::Char('q') {
                        self.data
                            .stop_tx
                            .send(())
                            .await
                            .expect("Could not send quit signal to TUI, crashing.");
                    }
                    machine_changed
                } else {
                    false
                }
            }
            // Interpret scroll as up down arrow keys.
            Event::Mouse(mouse) if mouse.kind == event::MouseEventKind::ScrollUp => {
                self.handle_key(event::KeyEvent::new(KeyCode::Up, KeyModifiers::empty()))
            }
            Event::Mouse(mouse) if mouse.kind == event::MouseEventKind::ScrollDown => {
                self.handle_key(event::KeyEvent::new(KeyCode::Down, KeyModifiers::empty()))
            }
            _ => {
                tracing::warn!(
                    event = ?event,
                    "Unexpected event",
                );
                false
            }
        }
    }

    /// Returns whether the selected machine changed.
    fn handle_key(&mut self, key: event::KeyEvent) -> bool {
        if self.machine_details_focused && self.machine_tab.handle_key(key) {
            return false;
        }

        match key.code {
            KeyCode::Up => {
                wrap_line(&mut self.list_state, self.data.machine_cache.len(), true);
                true
            }
            KeyCode::Down => {
                wrap_line(&mut self.list_state, self.data.machine_cache.len(), false);
                true
            }
            KeyCode::Enter => {
                self.machine_details_focused = true;
                false
            }
            KeyCode::Esc => {
                self.machine_details_focused = false;
                false
            }
            _ => false,
        }
    }

    fn draw_list_with_details(
        f: &mut Frame,
        layout: &layout::Rect,
        machine_details: &str,
        machine_logs: &str,
        sub_tab: &mut MachinesTab,
    ) {
        let layout_right = Layout::new(
            Direction::Vertical,
            [Constraint::Length(3), Constraint::Fill(1)],
        )
        .split(*layout);

        let tabs = Tabs::new(MachinesTab::all().map(|t| MachinesTab::get_title(&t)))
            .block(Block::bordered())
            .style(Style::default().fg(Color::White))
            .highlight_style(Style::default().fg(Color::LightGreen))
            .select(u8::from(&*sub_tab) as usize)
            .divider(DOT);

        f.render_widget(tabs, layout_right[0]);

        let data = match sub_tab {
            MachinesTab::Details => machine_details,
            MachinesTab::Logs => machine_logs,
        };
        let p = Paragraph::new(data)
            .block(Block::bordered().title(sub_tab.get_title()))
            .wrap(Wrap { trim: true });
        f.render_widget(p, layout_right[1]);
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn Error>> {
        let mut running = true;
        let mut terminal = Tui::setup_terminal()?;

        let mut items: Vec<ListItem<'_>> = Vec::default();

        let mut event_stream = EventStream::new();
        let mut list_updated = true;
        while running {
            let Self {
                data,
                list_state,
                machine_details_focused,
                machine_tab,
                host_logs,
            } = self;

            if list_updated {
                items.clear();

                for machine in data.machine_cache.values() {
                    items.push(ListItem::new(machine.header()));
                }
                list_updated = false;

                let machine_index = list_state.selected();
                let (machine_details, logs_fut) = if let Some(machine_index) = machine_index {
                    data.machine_cache
                        .iter()
                        .nth(machine_index)
                        .map(|(id, m)| (m.details(), host_logs.as_ref().map(|h| h.get_logs(*id))))
                        .unwrap_or_default()
                } else {
                    (String::default(), None)
                };

                data.machine_details = machine_details;
                data.machine_logs = if let Some(logs_fut) = logs_fut {
                    logs_fut
                        .await
                        .iter()
                        .cloned()
                        .rev()
                        .collect::<Vec<_>>()
                        .join("\n")
                } else {
                    String::default()
                };
            }

            let list = List::new(items.clone())
                .block(Block::default()
                .borders(Borders::ALL))
                .style(Style::default()
                    //.fg(Color::Black)
                )
                .highlight_style(Style::default()
                .add_modifier(Modifier::REVERSED))
                //.highlight_symbol(">>")
                ;

            terminal.draw(|f| {
                let chunks = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
                    .split(f.area());

                f.render_stateful_widget(list.clone(), chunks[0], list_state);
                if *machine_details_focused {
                    Self::draw_list_with_details(
                        f,
                        &chunks[1],
                        &data.machine_details,
                        &data.machine_logs,
                        machine_tab,
                    );
                }
            })?;

            select! {
                biased; // ensure quit messages are handled first
                _ = self.data.quit_rx.recv() => {
                    running = false;
                    continue;
                }
                maybe_event = event_stream.next() => {
                    match maybe_event {
                        Some(Ok(event)) => {
                            list_updated = self.handle_event(event).await;
                        }
                        Some(Err(e)) => tracing::warn!(
                            error = ?e,
                            "TUI error",
                        ),
                        None => break,
                    }
                }
                msg = self.data.event_rx.recv() => {
                    match msg {
                        Some(UiUpdate::Machine(m)) => {
                            list_updated = true;
                            self.data.machine_cache.insert(m.mat_id, m);
                        }
                        None => {}
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(200)) => { },
            };
        }

        Tui::teardown_terminal(&mut terminal)?;
        Ok(())
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
