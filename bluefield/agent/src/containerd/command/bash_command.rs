use std::time::Duration;

use eyre::WrapErr;

use crate::containerd::command::Command;
use crate::pretty_cmd;

const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct BashCommand {
    command: String,
    args: Vec<String>,
    output: Option<String>,
}

impl std::hash::Hash for BashCommand {
    fn hash<H>(&self, state: &mut H)
    where
        H: std::hash::Hasher,
    {
        self.command.hash(state);
        self.args.hash(state);
        state.finish();
    }
}

impl BashCommand {
    pub fn new(command: &str) -> Self {
        BashCommand {
            command: command.to_string(),
            args: Vec::new(),
            output: None,
        }
    }

    pub fn args(self, args: Vec<&str>) -> Self {
        BashCommand {
            command: self.command,
            args: args.iter().map(|x| x.to_string()).collect(),
            output: self.output,
        }
    }
}

#[async_trait::async_trait]
impl Command for BashCommand {
    async fn run(&mut self) -> eyre::Result<String> {
        let mut cmd = tokio::process::Command::new(&self.command);
        let fullcmd = cmd.args(&self.args);
        fullcmd.kill_on_drop(true);

        let cmd_str = pretty_cmd(fullcmd.as_std());

        let output = tokio::time::timeout(COMMAND_TIMEOUT, fullcmd.output())
            .await
            .wrap_err_with(|| format!("Timeout while running command: {:?}", cmd_str))??;

        let fout = String::from_utf8_lossy(&output.stdout).to_string();
        Ok(fout)
    }
}
