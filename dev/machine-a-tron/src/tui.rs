use std::{collections::HashMap, time::Duration};

use crossterm::{
    event::{self, Event, EventStream, KeyCode},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};

use futures::StreamExt;

use ratatui::{prelude::*, widgets::*};
use tokio::{
    select,
    sync::mpsc::{Receiver, Sender},
    time::Instant,
};

use uuid::Uuid;

use crate::{host_machine::HostMachine, machine_a_tron::AppEvent};

pub enum UiEvent {
    MachineUpdate(HostMachine),
    Quit,
}

pub struct Tui {
    list_state: ListState,
    event_rx: Receiver<UiEvent>,
    app_tx: Sender<AppEvent>,
    machine_cache: HashMap<Uuid, HostMachine>,
}

impl Tui {
    pub fn new(event_rx: Receiver<UiEvent>, app_tx: Sender<AppEvent>) -> Self {
        Self {
            list_state: ListState::default(),
            event_rx,
            app_tx,
            machine_cache: HashMap::default(),
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

    async fn handle_event(&mut self, event: Event) {
        match event {
            Event::Key(key) => {
                if key.kind == event::KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') => {
                            self.app_tx.send(AppEvent::Quit).await.unwrap();
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
                        }
                        KeyCode::Esc => {
                            self.list_state.select(None);
                        }
                        _ => {}
                    }
                }
            }
            _ => {
                tracing::warn!("Unexpected event: {:?}", event);
            }
        }
    }

    pub async fn run(&mut self) {
        let mut running = true;
        let mut terminal = Tui::setup_terminal().unwrap();

        let update_interval = Duration::from_secs(1);
        let mut last_update: Instant = Instant::now() - update_interval;
        let mut items: Vec<ListItem<'_>> = Vec::default();
        let mut event_stream = EventStream::new();
        let mut last_selected = None;
        let mut machine_details = String::default();

        while running {
            let time_since_machine_update = last_update.elapsed();
            if time_since_machine_update > update_interval {
                items.clear();

                for (_uuid, machine) in self.machine_cache.iter() {
                    items.push(ListItem::new(machine.get_name_and_state().await));
                }
                last_update = Instant::now();
            }

            let machine_index = self.list_state.selected();
            if last_selected != machine_index {
                last_selected = machine_index;
                machine_details = if let Some(machine_index) = machine_index {
                    self.machine_cache
                        .iter()
                        .nth(machine_index)
                        .map(|(_id, m)| format!("{}", m))
                        .unwrap_or_default()
                } else {
                    String::default()
                };
            }

            let list = List::new(items.clone())
                .block(Block::default().title("Machines").borders(Borders::ALL))
                .style(Style::default().fg(Color::White))
                .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
                //.highlight_symbol(">>")
                ;

            terminal
                .draw(|f| {
                    let size = f.size();
                    let layout = Layout::new(
                        Direction::Horizontal,
                        [Constraint::Percentage(30), Constraint::Fill(1)],
                    )
                    .split(size);
                    let b = Block::default()
                        .title("Machine Details")
                        .borders(Borders::all());
                    let p = Paragraph::new(machine_details.as_str()).block(b);
                    f.render_stateful_widget(list, layout[0], &mut self.list_state);
                    f.render_widget(p, layout[1]);
                })
                .unwrap();

            select! {
                _ = tokio::time::sleep(Duration::from_millis(200)) => { },
                maybe_event = event_stream.next() => {
                    match maybe_event {
                        Some(Ok(event)) => {
                            self.handle_event(event).await;
                        }
                        Some(Err(e)) => tracing::warn!("Error: {:?}\r", e),
                        None => break,
                    }
                }
                msg = self.event_rx.recv() => {
                    match msg {
                        Some(UiEvent::Quit) => {
                            running = false;
                        },
                        Some(UiEvent::MachineUpdate(m)) => {
                            self.machine_cache.insert(m.mat_id, m);
                            last_selected = None;
                        }
                        None => {}
                    }
                }
            };
        }

        Tui::teardown_terminal(&mut terminal).unwrap();
    }
}
