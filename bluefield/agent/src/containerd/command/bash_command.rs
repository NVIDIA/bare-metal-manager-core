use crate::containerd::command::Command;

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

impl Command for BashCommand {
    fn run(&mut self) -> eyre::Result<String> {
        let output = std::process::Command::new(&self.command)
            .args(&self.args)
            .output()?;
        let fout = String::from_utf8_lossy(&output.stdout).to_string();
        Ok(fout)
    }
}
