use std::{collections::HashMap, error::Error, time::Duration};

use crossterm::{
    event::{self, Event, EventStream, KeyCode},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};

use futures::StreamExt;

#[allow(unused_imports)]
use ratatui::{prelude::*, symbols::DOT, widgets::*};
use tokio::{
    select,
    sync::mpsc::{Receiver, Sender},
};

use uuid::Uuid;

use crate::{
    dpu_machine::DpuMachine, host_machine::HostMachine, machine_a_tron::AppEvent, vpc::Vpc,
};

pub struct VpcDetails {
    pub vpc_id: Uuid,
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

pub struct HostDetails {
    pub mat_id: Uuid,
    pub machine_id: Option<String>,
    pub mat_state: String,
    pub api_state: String,
    pub oob_ip: String,
    pub machine_ip: String,
    pub dpus: Vec<HostDetails>,
    pub logs: Vec<String>,
}

impl From<&DpuMachine> for HostDetails {
    fn from(value: &DpuMachine) -> Self {
        Self {
            mat_id: value.mat_id,
            machine_id: value.get_machine_id_opt().map(|id| id.to_string()),
            mat_state: value.mat_state.to_string(),
            api_state: value.api_state.clone(),
            oob_ip: value
                .bmc_dhcp_info
                .as_ref()
                .map(|dhcp_info| dhcp_info.ip_address)
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            machine_ip: value
                .machine_dhcp_info
                .as_ref()
                .map(|dhcp_info| dhcp_info.ip_address)
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            dpus: Vec::default(),
            logs: Vec::default(),
        }
    }
}

impl From<&HostMachine> for HostDetails {
    fn from(value: &HostMachine) -> Self {
        let mut dpus = Vec::with_capacity(value.dpu_machines.len());
        value
            .dpu_machines
            .iter()
            .for_each(|d| dpus.push(HostDetails::from(d)));

        HostDetails {
            mat_id: value.mat_id,
            machine_id: value.get_machine_id_opt().map(|id| id.to_string()),
            mat_state: value.mat_state.to_string(),
            api_state: value.api_state.clone(),
            oob_ip: value
                .bmc_dhcp_info
                .as_ref()
                .map(|dhcp_info| dhcp_info.ip_address)
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            machine_ip: value
                .machine_dhcp_info
                .as_ref()
                .map(|dhcp_info| dhcp_info.ip_address)
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            dpus,
            logs: value.logs.clone(),
        }
    }
}

impl HostDetails {
    fn header(&self) -> String {
        format!(
            "{}: {}/{}",
            self.machine_id
                .clone()
                .unwrap_or_else(|| self.mat_id.to_string()),
            self.mat_state,
            self.api_state
        )
    }
    fn details(&self) -> String {
        let mut result = String::with_capacity(1024);

        result.push_str(&format!("MAT ID: {}\n", self.mat_id));
        result.push_str(&format!(
            "Machine ID: {}\n",
            self.machine_id
                .as_ref()
                .map(|id| id.to_string())
                .unwrap_or_default()
        ));
        result.push_str(&format!("Machine IP: {}\n", self.machine_ip));
        result.push_str(&format!("BMC IP: {}\n", self.oob_ip));
        result.push('\n');
        result.push_str(&format!("MAT State: {}\n", self.mat_state));
        result.push_str(&format!("API State: {}\n", self.api_state));

        if !self.dpus.is_empty() {
            result.push_str("DPUs:\n");
            for d in self.dpus.iter() {
                result.push_str(&d.details());
            }
        }
        result
    }

    fn logs(&self) -> String {
        self.logs.join("\n")
    }
}

pub enum UiEvent {
    MachineUpdate(HostDetails),
    VpcUpdate(VpcDetails),
    Quit,
}

pub struct Tui {
    list_state: ListState,
    selected_tab: usize,
    event_rx: Receiver<UiEvent>,
    app_tx: Sender<AppEvent>,
    machine_cache: HashMap<Uuid, HostDetails>,
    vpc_cache: HashMap<Uuid, VpcDetails>,
    machine_details: String,
    machine_logs: String,
    selected_sub_tab: usize,
    is_left: bool, // Determines if pressing left and right arrow keys moves the tabs on the left or right window
}

impl Tui {
    pub fn new(event_rx: Receiver<UiEvent>, app_tx: Sender<AppEvent>) -> Self {
        Self {
            list_state: ListState::default(),
            selected_tab: 0,
            event_rx,
            app_tx,
            machine_cache: HashMap::default(),
            vpc_cache: HashMap::default(),
            machine_details: String::default(),
            machine_logs: String::default(),
            //            items: vec!["create_new"],
            selected_sub_tab: 0,
            is_left: true,
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
                if key.kind == event::KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') => {
                            self.app_tx
                                .send(AppEvent::Quit)
                                .await
                                .expect("Could not send quit signal to TUI, crashing.");
                            false
                        }
                        KeyCode::Up => {
                            let list_size = self.machine_cache.len();
                            if list_size > 0 {
                                let selection = self
                                    .list_state
                                    .selected()
                                    .map(|v| if v > 0 { v - 1 } else { list_size - 1 })
                                    .unwrap_or(list_size - 1);
                                self.list_state.select(Some(selection));
                            }
                            true
                        }
                        KeyCode::Down => {
                            let list_size = self.machine_cache.len();
                            if list_size > 0 {
                                let selection = self
                                    .list_state
                                    .selected()
                                    .map(|v| if v < (list_size - 1) { v + 1 } else { 0 })
                                    .unwrap_or(0);
                                self.list_state.select(Some(selection));
                            }
                            true
                        }
                        KeyCode::Right => {
                            if self.is_left {
                                self.selected_tab = self.selected_tab.saturating_add(1);
                            } else {
                                self.selected_sub_tab = self.selected_sub_tab.saturating_add(1);
                            }
                            false
                        }
                        KeyCode::Left => {
                            if self.is_left {
                                self.selected_tab = self.selected_tab.saturating_sub(1);
                            } else {
                                self.selected_sub_tab = self.selected_sub_tab.saturating_sub(1);
                            }
                            false
                        }
                        KeyCode::Esc => {
                            self.is_left = true;
                            self.list_state.select(None);
                            self.selected_sub_tab = 0;
                            true
                        }
                        KeyCode::Enter => {
                            self.is_left = false;
                            true
                        }
                        _ => false,
                    }
                } else {
                    false
                }
            }
            _ => {
                tracing::warn!("Unexpected event: {:?}", event);
                false
            }
        }
    }

    fn draw_list_with_details(&mut self, f: &mut Frame, _list: &List, layout: &layout::Rect) {
        //let size = f.size();
        let tab_titles = ["Machine Details", "Logs", "Metrics"];

        let selected_tab = self.selected_sub_tab % tab_titles.len();

        let layout_right = Layout::new(
            Direction::Vertical,
            [Constraint::Length(3), Constraint::Fill(1)],
        )
        .split(*layout);

        let tabs = Tabs::new(tab_titles)
            .block(Block::bordered())
            .style(Style::default().fg(Color::White))
            .highlight_style(Style::default().fg(Color::LightGreen))
            .select(selected_tab)
            .divider(DOT);

        let data = match self.selected_sub_tab {
            0 => self.machine_details.as_str(),
            1 => self.machine_logs.as_str(),
            _ => "Not Implemented",
        };
        let p = Paragraph::new(data).block(Block::bordered().title(tab_titles[selected_tab]));
        f.render_widget(tabs, layout_right[0]);
        f.render_widget(p, layout_right[1]);
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn Error>> {
        let mut running = true;
        let mut terminal = Tui::setup_terminal()?;

        let mut items: Vec<ListItem<'_>> = Vec::default();
        let mut vpc_items: Vec<ListItem<'_>> = Vec::default();
        let mut event_stream = EventStream::new();
        let mut list_updated = true;
        while running {
            if list_updated {
                items.clear();

                for (_uuid, machine) in self.machine_cache.iter() {
                    items.push(ListItem::new(machine.header()));
                }
                list_updated = false;

                let machine_index = self.list_state.selected();
                (self.machine_details, self.machine_logs) =
                    if let Some(machine_index) = machine_index {
                        self.machine_cache
                            .iter()
                            .nth(machine_index)
                            .map(|(_id, m)| (m.details(), m.logs()))
                            .unwrap_or_default()
                    } else {
                        (String::default(), String::default())
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
            for (_uuid, vpc) in self.vpc_cache.iter() {
                vpc_items.push(ListItem::new(vpc.header()));
            }
            let vpc_list = List::new(vpc_items.clone())
                .block(Block::default().borders(Borders::ALL))
                .style(
                    Style::default(), //.fg(Color::Black)
                )
                .highlight_style(Style::default().add_modifier(Modifier::REVERSED));

            let tabs = ["Machines", "VPCs", "Subnets"];

            terminal.draw(|f| {
                let chunks = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
                    .split(f.size());

                let left_chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Length(3), Constraint::Min(0)].as_ref())
                    .split(chunks[0]);

                let titles = tabs
                    .iter()
                    .map(|t| {
                        let (first, rest) = t.split_at(1);
                        format!(
                            "{}{}",
                            first.to_string().bold().fg(Color::Yellow),
                            rest.to_string().fg(Color::Green)
                        )
                    })
                    .collect::<Vec<String>>();

                let tabs = Tabs::new(titles)
                    .block(Block::default().borders(Borders::ALL).title("Tabs"))
                    .select(self.selected_tab)
                    .highlight_style(Style::default().fg(Color::LightYellow));

                f.render_widget(tabs.clone(), chunks[0]);

                match self.selected_tab {
                    0 => {
                        f.render_stateful_widget(
                            list.clone(),
                            left_chunks[1],
                            &mut self.list_state,
                        );
                        if !self.is_left {
                            self.draw_list_with_details(f, &list, &chunks[1]);
                        }
                    }
                    1 => {
                        f.render_stateful_widget(vpc_list, left_chunks[1], &mut self.list_state);

                        let paragraph = Paragraph::new("Not implemented yet")
                            .block(Block::default().borders(Borders::ALL).title("Details"));
                        f.render_widget(paragraph, chunks[1]);
                    }
                    2 => {
                        let paragraph = Paragraph::new("Not implemented yet")
                            .block(Block::default().borders(Borders::ALL).title("Details"));
                        f.render_widget(paragraph, chunks[1]);
                    }
                    _ => {}
                }
            })?;

            select! {
                _ = tokio::time::sleep(Duration::from_millis(200)) => { },
                maybe_event = event_stream.next() => {
                    match maybe_event {
                        Some(Ok(event)) => {
                            list_updated = self.handle_event(event).await;
                        }
                        Some(Err(e)) => tracing::warn!("Error: {:?}", e),
                        None => break,
                    }
                }
                msg = self.event_rx.recv() => {
                    match msg {
                        Some(UiEvent::Quit) => {
                            running = false;
                        },
                        Some(UiEvent::MachineUpdate(m)) => {
                            list_updated = true;
                            self.machine_cache.insert(m.mat_id, m);
                        }
                        Some(UiEvent::VpcUpdate(m)) => {
                            self.vpc_cache.insert(m.vpc_id, m);

                        }
                        None => {}
                    }
                }
            };
        }

        Tui::teardown_terminal(&mut terminal)?;
        Ok(())
    }
}
