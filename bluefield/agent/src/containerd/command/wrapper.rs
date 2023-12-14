use std::time::{Duration, Instant};

use crate::containerd::command::Command;
use crate::containerd::{AsAny, DynEq, DynHash};

#[derive(Debug)]
pub struct CommandWrapper {
    pub command: Box<dyn Command>,
    last_refresh: Instant,
    duration: Duration,
    output: Option<String>,
}

impl std::hash::Hash for CommandWrapper {
    fn hash<H>(&self, state: &mut H)
    where
        H: std::hash::Hasher,
    {
        self.command.dyn_hash(state);
    }
}

impl PartialEq for CommandWrapper {
    fn eq(&self, other: &CommandWrapper) -> bool {
        DynEq::dyn_eq(self, other.as_any())
    }
}

impl Eq for CommandWrapper {}

impl CommandWrapper {
    pub fn new(cmd: Box<dyn Command>, duration: Duration) -> Self {
        CommandWrapper {
            last_refresh: Instant::now(),
            duration,
            output: None,
            command: cmd,
        }
    }

    fn refresh(&mut self) -> eyre::Result<()> {
        self.output = Some(self.command.run()?);
        self.last_refresh = Instant::now();
        Ok(())
    }

    fn needs_refresh(&self) -> bool {
        self.last_refresh.elapsed() >= self.duration
    }

    pub fn get(&mut self) -> eyre::Result<String> {
        if self.needs_refresh() || self.output.is_none() {
            self.refresh()?;
        }
        self.output.clone().ok_or(eyre::eyre!(
            "Unable to produce output, or output does not exist"
        ))
    }
}
