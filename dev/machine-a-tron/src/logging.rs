use chrono::{DateTime, Local};
use std::fmt::{Display, Formatter};
use std::time::SystemTime;
use tokio::sync::mpsc;
use tracing::Level;

/// This module exists so that we can log in a way that goes to tracing::event as well as into a logs
/// array held on a HostMachine, so that we can show the logs on the TUI. Rather than having to
/// manage pushing to the logs array separately from doing trace logging, this allows us to more
/// easily do both.
#[derive(Debug)]
pub struct LogCollector {
    log_rx: mpsc::UnboundedReceiver<LogMessage>,
    log_tx: mpsc::UnboundedSender<LogMessage>,
}

#[derive(Clone)]
pub struct LogMessage {
    pub message: String,
    pub level: tracing::Level,
}

impl Display for LogMessage {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(format!("{}: {}", self.level, self.message).as_str())
    }
}

impl Default for LogCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl LogCollector {
    pub fn new() -> Self {
        let (log_tx, log_rx) = mpsc::unbounded_channel();
        Self { log_tx, log_rx }
    }
    pub fn log_sink(&self, prefix: Option<String>) -> LogSink {
        LogSink {
            prefix,
            log_tx: self.log_tx.clone(),
        }
    }

    pub fn get_last_logs(&mut self) -> Vec<LogMessage> {
        let mut result = Vec::new();
        while let Ok(message) = self.log_rx.try_recv() {
            result.push(message);
        }
        result
    }
}

#[derive(Debug, Clone)]
pub struct LogSink {
    prefix: Option<String>,
    log_tx: mpsc::UnboundedSender<LogMessage>,
}

impl LogSink {
    pub fn log(&self, level: tracing::Level, message: String) {
        let log_time = DateTime::<Local>::from(SystemTime::now());

        // Prepend prefix
        let message = if let Some(prefix) = self.prefix.as_ref() {
            format!("{prefix} {message}")
        } else {
            message
        };

        // tracing::event! doesn't accept a non-constant value for its level param so we have to do a match here.
        match level {
            Level::TRACE => tracing::trace!(message),
            Level::DEBUG => tracing::debug!(message),
            Level::INFO => tracing::info!(message),
            Level::WARN => tracing::warn!(message),
            Level::ERROR => tracing::error!(message),
        }

        // For the log_tx object, prepend a timestamp (trace logging already prepends one.)
        let message = format!("{log_time} {message}");
        self.log_tx.send(LogMessage { message, level }).unwrap();
    }

    pub fn info(&self, message: String) {
        self.log(Level::INFO, message)
    }

    pub fn warn(&self, message: String) {
        self.log(Level::WARN, message)
    }

    pub fn error(&self, message: String) {
        self.log(Level::ERROR, message)
    }

    pub fn debug(&self, message: String) {
        self.log(Level::DEBUG, message)
    }
}
