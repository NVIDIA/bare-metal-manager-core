use std::ffi::OsStr;
use std::process::Command;

#[derive(thiserror::Error, Debug)]
pub enum CmdError {
    #[error("Cmd error: {0}")]
    Generic(String),
    #[error("Subprocess {0} with arguments {1:?} failed with output: {2}")]
    Subprocess(String, Vec<String>, String),
    #[error("Command {0} with args {1:?} produced output that is not valid UTF8")]
    OutputParse(String, Vec<String>),
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
    pub fn output_parse_error(command: &Cmd) -> Self {
        Self::OutputParse(
            command.command.get_program().to_string_lossy().to_string(),
            command
                .command
                .get_args()
                .map(|arg| arg.to_string_lossy().to_string())
                .collect::<Vec<String>>(),
        )
    }
}

pub type CmdResult<T> = std::result::Result<T, CmdError>;

pub struct Cmd {
    command: Command,
}

impl Cmd {
    pub fn new<S: AsRef<OsStr>>(program: S) -> Self {
        Self {
            command: Command::new(program),
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

    pub fn output(mut self) -> CmdResult<String> {
        if cfg!(test) {
            return Ok("test string".to_string());
        }

        let output = self
            .command
            .output()
            .map_err(|x| CmdError::Generic(x.to_string()))?;

        if !output.status.success() {
            return Err(CmdError::subprocess_error(&self.command, &output));
        }

        String::from_utf8(output.stdout).map_err(|_| CmdError::output_parse_error(&self))
    }
}
