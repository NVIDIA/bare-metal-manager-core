use std::ffi::OsStr;
use std::process::Command;
use std::time::Duration;

use tokio::process::Command as TokioCommand;

#[derive(thiserror::Error, Debug)]
pub enum CmdError {
    #[error("Invalid retry value {0} for {1}")]
    InvalidRetry(u32, String),
    #[error("Subprocess {0} with arguments {1:?} failed with output: {2}")]
    Subprocess(String, Vec<String>, String),
    #[error("Command {0} with args {1:?} produced output that is not valid UTF8")]
    OutputParse(String, Vec<String>),
    #[error("Error running '{0}': {1:#}")]
    RunError(String, String),
    #[error("Error async running '{0}': {1:#}")]
    TokioRunError(String, String),
}

impl CmdError {
    pub fn subprocess_error(
        command: &std::process::Command,
        output: &std::process::Output,
    ) -> Self {
        let error_details = if output.stderr.is_empty() {
            String::from_utf8_lossy(&output.stdout).to_string()
        } else {
            String::from_utf8_lossy(&output.stderr).to_string()
        };

        Self::Subprocess(
            command.get_program().to_string_lossy().to_string(),
            command
                .get_args()
                .map(|arg| arg.to_string_lossy().to_string())
                .collect::<Vec<String>>(),
            error_details,
        )
    }
    pub fn output_parse_error(command: &Command) -> Self {
        Self::OutputParse(
            command.get_program().to_string_lossy().to_string(),
            command
                .get_args()
                .map(|arg| arg.to_string_lossy().to_string())
                .collect::<Vec<String>>(),
        )
    }
}

pub type CmdResult<T> = std::result::Result<T, CmdError>;

#[derive(Debug)]
pub struct Cmd {
    command: Command,
    attempts: u32,
    ignore_return: bool,
}

impl Cmd {
    pub fn new<S: AsRef<OsStr>>(program: S) -> Self {
        Self {
            command: Command::new(program),
            attempts: 1,
            ignore_return: false,
        }
    }

    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.command.args(args);
        self
    }

    pub fn env<S>(mut self, key: S, value: S) -> Self
    where
        S: AsRef<OsStr>,
    {
        self.command.env(key, value);
        self
    }

    pub fn attempts(mut self, attempts: u32) -> Self {
        self.attempts = attempts;
        self
    }

    pub fn ignore_return(mut self, ignore: bool) -> Self {
        self.ignore_return = ignore;
        self
    }

    pub fn output(mut self) -> CmdResult<String> {
        if cfg!(test) {
            return Ok("test string".to_string());
        }

        let mut last_output = None;
        for _attempt in 0..self.attempts {
            let output = self
                .command
                .output()
                .map_err(|x| CmdError::RunError(self.pretty_cmd(), x.to_string()))?;

            last_output = Some(output.clone());

            if output.status.success() || self.ignore_return {
                return String::from_utf8(output.stdout)
                    .map_err(|_| CmdError::output_parse_error(&self.command));
            }

            // Give some breathing time.
            std::thread::sleep(Duration::from_millis(100));
        }
        if let Some(output) = last_output {
            Err(CmdError::subprocess_error(&self.command, &output))
        } else {
            Err(CmdError::InvalidRetry(self.attempts, self.pretty_cmd()))
        }
    }

    fn pretty_cmd(&self) -> String {
        format!(
            "{} {}",
            self.command.get_program().to_string_lossy(),
            self.command
                .get_args()
                .map(|x| x.to_string_lossy())
                .collect::<Vec<std::borrow::Cow<'_, str>>>()
                .join(" ")
        )
    }
}

/// Async implementation of Cmd.
#[derive(Debug)]
pub struct TokioCmd {
    command: TokioCommand,
    attempts: u32,
}

impl TokioCmd {
    pub fn new<S: AsRef<OsStr>>(program: S) -> Self {
        Self {
            command: TokioCommand::new(program),
            attempts: 1,
        }
    }

    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.command.args(args);
        self
    }

    pub fn env<S>(mut self, key: S, value: S) -> Self
    where
        S: AsRef<OsStr>,
    {
        self.command.env(key, value);
        self
    }

    pub fn attempts(mut self, attempts: u32) -> Self {
        self.attempts = attempts;
        self
    }

    pub async fn output(mut self) -> CmdResult<String> {
        if cfg!(test) {
            return Ok("test string".to_string());
        }

        let mut last_output = None;
        for _attempt in 0..self.attempts {
            let output = self
                .command
                .output()
                .await
                .map_err(|x| CmdError::TokioRunError(self.pretty_cmd(), x.to_string()))?;

            last_output = Some(output.clone());

            if output.status.success() {
                return String::from_utf8(output.stdout)
                    .map_err(|_| CmdError::output_parse_error(self.command.as_std()));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        if let Some(output) = last_output {
            Err(CmdError::subprocess_error(self.command.as_std(), &output))
        } else {
            Err(CmdError::InvalidRetry(self.attempts, self.pretty_cmd()))
        }
    }

    fn pretty_cmd(&self) -> String {
        let c = self.command.as_std();
        format!(
            "{} {}",
            c.get_program().to_string_lossy(),
            c.get_args()
                .map(|x| x.to_string_lossy())
                .collect::<Vec<std::borrow::Cow<'_, str>>>()
                .join(" ")
        )
    }
}
