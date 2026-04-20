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

use bmc_mock::{HostHardwareType, MockPowerState};
use carbide_uuid::network::NetworkSegmentId;
use carbide_uuid::vpc::VpcId;
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
use crate::machine_a_tron::AppEvent;
use crate::subnet::Subnet;
use crate::tabs::{MachinesTab, Tab};
use crate::vpc::Vpc;

pub struct VpcDetails {
    pub vpc_id: VpcId,
    pub vpc_name: Option<String>,
}

impl From<&Vpc> for VpcDetails {
    fn from(value: &Vpc) -> Self {
        Self {
            vpc_id: value.vpc_id,
            vpc_name: Some(value.vpc_name.clone()),
        }
    }
}

impl VpcDetails {
    fn header(&self) -> String {
        format!(
            "{}: {}",
            self.vpc_name.clone().unwrap_or("Without name".to_string()),
            self.vpc_id.clone(),
        )
    }
}

pub struct SubnetDetails {
    pub segment_id: NetworkSegmentId,
    pub prefix: Option<String>,
}

impl From<&Subnet> for SubnetDetails {
    fn from(value: &Subnet) -> Self {
        Self {
            segment_id: value.segment_id,
            prefix: Some(value.prefixes.join(", ")),
        }
    }
}

impl SubnetDetails {
    fn header(&self) -> String {
        format!(
            "{}: {}",
            self.segment_id,
            self.prefix.as_ref().unwrap_or(&"prefix???".to_string()),
        )
    }
}

#[derive(Default)]
pub struct HostDetails {
    pub mat_id: Uuid,
    pub machine_id: Option<String>,
    pub hw_type: Option<HostHardwareType>,
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
    Vpc(VpcDetails),
    Subnet(SubnetDetails),
}

pub struct Tui {
    /// The stored data of the ui.
    data: TuiData,
    /// The (transient) state of the ui
    ui: Tab,
    /// A handle to a TuiHostLogs where logs for hosts are stored
    host_logs: Option<TuiHostLogs>,
}

pub struct TuiData {
    pub event_rx: Receiver<UiUpdate>,
    pub quit_rx: Receiver<()>,
    pub app_tx: Sender<AppEvent>,
    pub machine_cache: HashMap<Uuid, HostDetails>,
    pub vpc_cache: HashMap<VpcId, VpcDetails>,
    pub subnet_cache: HashMap<NetworkSegmentId, SubnetDetails>,
    pub machine_details: String,
    pub machine_logs: String,
    pub original_routes: HashMap<String, String>,
}

impl Tui {
    pub fn new(
        event_rx: Receiver<UiUpdate>,
        quit_rx: Receiver<()>,
        app_tx: Sender<AppEvent>,
        host_logs: Option<TuiHostLogs>,
    ) -> Self {
        Self {
            data: TuiData {
                event_rx,
                quit_rx,
                app_tx,
                machine_cache: HashMap::default(),
                vpc_cache: HashMap::default(),
                subnet_cache: HashMap::default(),
                machine_details: String::default(),
                machine_logs: String::default(),
                original_routes: HashMap::new(),
            },
            ui: Tab::default(),
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
        let Self {
            data,
            ui,
            host_logs: _,
        } = self;
        match event {
            Event::Key(key) => {
                // Handle global triggers.
                if key.kind == event::KeyEventKind::Press {
                    let (handled, machine_changed) = ui.handle_key(data, key);
                    if !handled {
                        match key.code {
                            KeyCode::Char('q') => {
                                data.app_tx
                                    .send(AppEvent::Quit)
                                    .await
                                    .expect("Could not send quit signal to TUI, crashing.");
                            }
                            KeyCode::Char('i') => {
                                data.app_tx.send(AppEvent::AllocateInstance).await.expect(
                                    "Could not send allocate instance signal to TUI, crashing.",
                                );
                            }
                            _ => {}
                        }
                    }
                    machine_changed
                } else {
                    false
                }
            }
            // Interpret scroll as up down arrow keys.
            Event::Mouse(mouse) if mouse.kind == event::MouseEventKind::ScrollUp => {
                ui.handle_key(
                    data,
                    event::KeyEvent::new(KeyCode::Up, KeyModifiers::empty()),
                )
                .1
            }
            Event::Mouse(mouse) if mouse.kind == event::MouseEventKind::ScrollDown => {
                ui.handle_key(
                    data,
                    event::KeyEvent::new(KeyCode::Down, KeyModifiers::empty()),
                )
                .1
            }
            _ => {
                tracing::warn!("Unexpected event: {:?}", event);
                false
            }
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
            MachinesTab::Metrics => "Not Implemented",
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
        let mut vpc_items: Vec<ListItem<'_>> = Vec::default();
        let mut subnet_items: Vec<ListItem<'_>> = Vec::default();

        let mut event_stream = EventStream::new();
        let mut list_updated = true;
        while running {
            let Self {
                data,
                ui,
                host_logs,
            } = self;

            if list_updated && let Tab::Machines { list_state, .. } = ui {
                items.clear();

                for (_uuid, machine) in data.machine_cache.iter() {
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

            vpc_items.clear();
            for (_uuid, vpc) in data.vpc_cache.iter() {
                vpc_items.push(ListItem::new(vpc.header()));
            }
            let vpc_list = List::new(vpc_items.clone())
                .block(Block::default().borders(Borders::ALL))
                .style(Style::default())
                .highlight_style(Style::default().add_modifier(Modifier::REVERSED));

            subnet_items.clear();
            for (_uuid, subnet) in data.subnet_cache.iter() {
                subnet_items.push(ListItem::new(subnet.header()));
            }
            let subnet_list = List::new(subnet_items.clone())
                .block(Block::default().borders(Borders::ALL))
                .style(Style::default())
                .highlight_style(Style::default().add_modifier(Modifier::REVERSED));

            terminal.draw(|f| {
                let chunks = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
                    .split(f.area());

                let left_chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Length(3), Constraint::Min(0)].as_ref())
                    .split(chunks[0]);

                let titles = Tab::titles()
                    .map(|t| {
                        let (first, rest) = t.split_at(1);
                        format!(
                            "{}{}",
                            first.to_string().bold().fg(Color::Yellow),
                            rest.to_string().fg(Color::Green)
                        )
                    })
                    .to_vec();

                let tabs = Tabs::new(titles)
                    .block(Block::default().borders(Borders::ALL).title("Tabs"))
                    .select(u8::from(&*ui) as usize)
                    .highlight_style(Style::default().fg(Color::LightYellow));

                f.render_widget(tabs.clone(), chunks[0]);

                match ui {
                    Tab::Machines {
                        tab,
                        list_state,
                        focused,
                    } => {
                        f.render_stateful_widget(list.clone(), left_chunks[1], list_state);
                        if *focused {
                            Self::draw_list_with_details(
                                f,
                                &chunks[1],
                                &data.machine_details,
                                &data.machine_logs,
                                tab,
                            );
                        }
                    }
                    Tab::VPCs { list_state } => {
                        f.render_stateful_widget(vpc_list, left_chunks[1], list_state);

                        let paragraph = Paragraph::new("Not implemented yet")
                            .block(Block::default().borders(Borders::ALL).title("Details"));
                        f.render_widget(paragraph, chunks[1]);
                    }
                    Tab::Subnets { list_state } => {
                        f.render_stateful_widget(subnet_list, left_chunks[1], list_state);

                        let paragraph = Paragraph::new("Not implemented yet")
                            .block(Block::default().borders(Borders::ALL).title("Details"));
                        f.render_widget(paragraph, chunks[1]);
                    }
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
                        Some(Err(e)) => tracing::warn!("Error: {:?}", e),
                        None => break,
                    }
                }
                msg = self.data.event_rx.recv() => {
                    match msg {
                        Some(UiUpdate::Machine(m)) => {
                            list_updated = true;
                            self.data.machine_cache.insert(m.mat_id, m);
                        }
                        Some(UiUpdate::Vpc(m)) => {
                            self.data.vpc_cache.insert(m.vpc_id, m);
                        }
                        Some(UiUpdate::Subnet(m)) => {
                            self.data.subnet_cache.insert(m.segment_id, m);
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
