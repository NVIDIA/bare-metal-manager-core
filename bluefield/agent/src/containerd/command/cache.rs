use std::collections::HashSet;
use std::time::Duration;

use crate::containerd::command::wrapper::CommandWrapper;
use crate::containerd::command::Command;

// Concrete implementation of a command cache
#[derive(Debug)]
pub struct CommandCache {
    commands: HashSet<CommandWrapper>,
}

impl Default for CommandCache {
    fn default() -> Self {
        Self::new()
    }
}

impl CommandCache {
    pub fn new() -> Self {
        CommandCache {
            commands: HashSet::new(),
        }
    }

    pub fn get_or_insert(&mut self, command: Box<dyn Command>) -> eyre::Result<String> {
        let new_cmd_wrapper = CommandWrapper::new(command.clone(), Duration::from_secs(300));
        if !self.commands.contains(&new_cmd_wrapper) {
            self.commands.insert(new_cmd_wrapper);
        }

        let new_cmd_wrapper = CommandWrapper::new(command.clone(), Duration::from_secs(300));

        let mut command_wrapper = self
            .commands
            .take(&new_cmd_wrapper)
            .expect("Command not found Unpossible");

        let res = command_wrapper.get();
        self.commands.insert(command_wrapper);
        res
    }
}
