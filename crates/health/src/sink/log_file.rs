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

use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::Serialize;

use super::{CollectorEvent, DataSink, EventContext, LogRecord};
use crate::config::LogFileSinkConfig;

/// Durable JSONL log sink. Writes CollectorEvent::Log records to rotating
/// files using sync I/O, safe to call from DataSink::handle_event.
pub struct LogFileSink {
    writer: Mutex<SyncLogFileWriter>,
}

impl LogFileSink {
    pub fn new(config: &LogFileSinkConfig) -> Result<Self, String> {
        let writer = SyncLogFileWriter::new(
            PathBuf::from(&config.output_dir),
            config.max_file_size,
            config.max_backups,
        )?;
        Ok(Self {
            writer: Mutex::new(writer),
        })
    }
}

impl DataSink for LogFileSink {
    fn sink_type(&self) -> &'static str {
        "log_file_sink"
    }

    fn handle_event(&self, context: &EventContext, event: &CollectorEvent) {
        let CollectorEvent::Log(record) = event else {
            return;
        };

        let json_record = JsonLogRecord::from_event(context, record);

        let line = match serde_json::to_string(&json_record) {
            Ok(json) => json,
            Err(e) => {
                tracing::error!(error = ?e, "failed to serialize log record");
                return;
            }
        };

        let Ok(mut writer) = self.writer.lock() else {
            tracing::error!("log file writer lock poisoned");
            return;
        };

        if let Err(e) = writer.write_line(&line) {
            tracing::error!(error = ?e, "failed to write log record to file");
        }
    }
}

#[derive(Serialize)]
struct JsonLogRecord<'a> {
    endpoint: &'a str,
    collector: &'a str,
    severity: &'a str,
    body: &'a str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    attributes: Vec<(&'a str, &'a str)>,
}

impl<'a> JsonLogRecord<'a> {
    fn from_event(context: &'a EventContext, record: &'a LogRecord) -> Self {
        Self {
            endpoint: context.endpoint_key(),
            collector: context.collector_type,
            severity: &record.severity,
            body: &record.body,
            attributes: record
                .attributes
                .iter()
                .map(|(k, v)| (k.as_ref(), v.as_str()))
                .collect(),
        }
    }
}

struct SyncLogFileWriter {
    output_dir: PathBuf,
    max_file_size: u64,
    max_backups: usize,
    current_file: Option<BufWriter<File>>,
    current_size: u64,
}

impl SyncLogFileWriter {
    fn new(output_dir: PathBuf, max_file_size: u64, max_backups: usize) -> Result<Self, String> {
        fs::create_dir_all(&output_dir)
            .map_err(|e| format!("failed to create log output directory: {e}"))?;

        let mut writer = Self {
            output_dir,
            max_file_size,
            max_backups,
            current_file: None,
            current_size: 0,
        };

        writer.open_current_file()?;
        Ok(writer)
    }

    fn log_path(&self) -> PathBuf {
        self.output_dir.join("health_logs.jsonl")
    }

    fn rotated_path(&self, index: usize) -> PathBuf {
        self.output_dir.join(format!("health_logs.{index}.jsonl"))
    }

    fn open_current_file(&mut self) -> Result<(), String> {
        let path = self.log_path();

        self.current_size = fs::metadata(&path).ok().map(|m| m.len()).unwrap_or(0);

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| format!("failed to open log file {}: {e}", path.display()))?;

        self.current_file = Some(BufWriter::new(file));
        Ok(())
    }

    fn write_line(&mut self, line: &str) -> Result<(), String> {
        let bytes = line.as_bytes();
        let write_size = bytes.len() as u64 + 1; // +1 for trailing newline

        // a single line larger than max_file_size is allowed into a fresh file
        self.rotate_if_needed(write_size)?;

        let file = self.current_file.as_mut().ok_or("log file not open")?;

        file.write_all(bytes)
            .and_then(|_| file.write_all(b"\n"))
            .and_then(|_| file.flush())
            .map_err(|e| format!("failed to write to log file: {e}"))?;

        self.current_size += write_size;
        Ok(())
    }

    fn rotate_if_needed(&mut self, pending_size: u64) -> Result<(), String> {
        if self.current_size + pending_size <= self.max_file_size {
            return Ok(());
        }

        tracing::info!(size = self.current_size, "rotating log file");

        // flush and drop the current file handle before renaming
        if let Some(mut file) = self.current_file.take() {
            let _ = file.flush();
        }

        let current_path = self.log_path();

        if self.max_backups == 0 {
            let _ = fs::remove_file(&current_path);
        } else {
            self.shift_backups(&current_path);
        }

        self.current_size = 0;
        self.open_current_file()
    }

    fn shift_backups(&self, current_path: &Path) {
        // shift existing backups up by one index
        for i in (1..self.max_backups).rev() {
            let from = self.rotated_path(i);
            let to = self.rotated_path(i + 1);
            if from.exists() {
                let _ = fs::rename(&from, &to);
            }
        }

        // current -> .1
        let backup = self.rotated_path(1);
        let _ = fs::rename(current_path, &backup);

        // prune the oldest backup beyond the limit
        let oldest = self.rotated_path(self.max_backups + 1);
        if oldest.exists() {
            let _ = fs::remove_file(&oldest);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::str::FromStr;

    use mac_address::MacAddress;

    use super::*;
    use crate::endpoint::BmcAddr;

    fn test_context() -> EventContext {
        EventContext {
            endpoint_key: "aa:bb:cc:dd:ee:ff".to_string(),
            addr: BmcAddr {
                ip: "10.0.0.1".parse().expect("valid ip"),
                port: Some(443),
                mac: MacAddress::from_str("aa:bb:cc:dd:ee:ff").unwrap(),
            },
            collector_type: "test",
            metadata: None,
            rack_id: None,
        }
    }

    #[test]
    fn test_ignores_non_log_events() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = LogFileSinkConfig {
            output_dir: dir.path().to_string_lossy().into_owned(),
            max_file_size: 1024,
            max_backups: 2,
        };
        let sink = LogFileSink::new(&config).expect("sink");
        let ctx = test_context();

        let metric_event = CollectorEvent::MetricCollectionStart;
        sink.handle_event(&ctx, &metric_event);

        let log_path = dir.path().join("health_logs.jsonl");
        let contents = fs::read_to_string(&log_path).unwrap_or_default();
        assert!(contents.is_empty(), "non-log events should be ignored");
    }

    #[test]
    fn test_writes_log_events_as_jsonl() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = LogFileSinkConfig {
            output_dir: dir.path().to_string_lossy().into_owned(),
            max_file_size: 1024 * 1024,
            max_backups: 2,
        };
        let sink = LogFileSink::new(&config).expect("sink");
        let ctx = test_context();

        let event = CollectorEvent::Log(
            LogRecord {
                body: "something happened".to_string(),
                severity: "INFO".to_string(),
                attributes: vec![(Cow::Borrowed("entry_id"), "42".to_string())],
            }
            .into(),
        );
        sink.handle_event(&ctx, &event);

        let log_path = dir.path().join("health_logs.jsonl");
        let contents = fs::read_to_string(log_path).expect("read log");
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 1);

        let parsed: serde_json::Value = serde_json::from_str(lines[0]).expect("valid json");
        assert_eq!(parsed["body"], "something happened");
        assert_eq!(parsed["severity"], "INFO");
        assert_eq!(parsed["endpoint"], "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn test_rotation_creates_backups() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = LogFileSinkConfig {
            output_dir: dir.path().to_string_lossy().into_owned(),
            // tiny limit to force rotation quickly
            max_file_size: 50,
            max_backups: 2,
        };
        let sink = LogFileSink::new(&config).expect("sink");
        let ctx = test_context();

        for i in 0..5 {
            let event = CollectorEvent::Log(
                LogRecord {
                    body: format!("log entry {i}"),
                    severity: "INFO".to_string(),
                    attributes: Vec::new(),
                }
                .into(),
            );
            sink.handle_event(&ctx, &event);
        }

        let current = dir.path().join("health_logs.jsonl");
        let backup1 = dir.path().join("health_logs.1.jsonl");

        assert!(current.exists(), "current log file should exist");
        assert!(backup1.exists(), "at least one backup should exist");
    }

    #[test]
    fn test_rotation_zero_backups_truncates() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = LogFileSinkConfig {
            output_dir: dir.path().to_string_lossy().into_owned(),
            max_file_size: 50,
            max_backups: 0,
        };
        let sink = LogFileSink::new(&config).expect("sink");
        let ctx = test_context();

        for i in 0..5 {
            let event = CollectorEvent::Log(
                LogRecord {
                    body: format!("entry {i}"),
                    severity: "WARN".to_string(),
                    attributes: Vec::new(),
                }
                .into(),
            );
            sink.handle_event(&ctx, &event);
        }

        let current = dir.path().join("health_logs.jsonl");
        assert!(current.exists());

        // no backup files should exist
        let backup1 = dir.path().join("health_logs.1.jsonl");
        assert!(!backup1.exists(), "no backups when max_backups = 0");
    }
}
