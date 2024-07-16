/*
 * SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::collections::HashMap;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio::process::Command;
use tracing::trace;

use crate::MachineValidation;

pub const MAX_STRING_STD_SIZE: usize = 1024 * 1024; // 1MB in bytes;

#[derive(thiserror::Error, Debug)]
pub enum MachineValidationError {
    #[error("Generic Error: {0}")]
    Generic(String),
    #[error("Unable to config read: {0}")]
    ConfigFileRead(String),
    #[error("Yaml parse error: {0}")]
    Parse(String),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Suite {
    #[serde(flatten)]
    components: HashMap<String, Component>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Component {
    #[serde(flatten)]
    subcategories: HashMap<String, HashMap<String, ExecCommand>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExecCommand {
    #[serde(rename = "Command")]
    command: String,
    #[serde(rename = "Args")]
    args: String,
    #[serde(rename = "Desc")]
    description: String,
    #[serde(rename = "Contexts")]
    contexts: Vec<String>,
}
impl MachineValidation {
    async fn execute_machinevalidation_command(
        name: String,
        cmd: ExecCommand,
        in_context: String,
        uuid: rpc::common::Uuid,
    ) -> Option<rpc::forge::MachineValidationResult> {
        let command_string = format!("{} {}", cmd.command, cmd.args);
        trace!("Executing command '{}'", command_string);
        let start_time = Utc::now();
        match Command::new("sh")
            .arg("-c")
            .arg(&command_string)
            .output()
            .await
        {
            Ok(output) => {
                let stdout_str = String::from_utf8_lossy(&output.stdout).to_string();
                let stderr_str = String::from_utf8_lossy(&output.stderr).to_string();
                let end_time = Utc::now();
                Some(rpc::forge::MachineValidationResult {
                    name,
                    description: cmd.description.clone(),
                    command: cmd.command.clone(),
                    args: cmd.args.clone(),
                    std_out: if stdout_str.len() > MAX_STRING_STD_SIZE {
                        stdout_str[..MAX_STRING_STD_SIZE].to_string()
                    } else {
                        stdout_str
                    },
                    std_err: if stderr_str.len() > MAX_STRING_STD_SIZE {
                        stderr_str[..MAX_STRING_STD_SIZE].to_string()
                    } else {
                        stderr_str
                    },
                    context: in_context,
                    exit_code: if output.status.success() { 0 } else { -1 },
                    start_time: Some(start_time.into()),
                    end_time: Some(end_time.into()),
                    validation_id: Some(uuid),
                })
            }
            Err(e) => {
                trace!("Error {}", e);
                let end_time = Utc::now();
                Some(rpc::forge::MachineValidationResult {
                    name,
                    description: cmd.description.clone(),
                    command: cmd.command.clone(),
                    args: cmd.args.clone(),
                    std_out: e.to_string(),
                    std_err: e.to_string(),
                    context: in_context,
                    exit_code: -1,
                    start_time: Some(start_time.into()),
                    end_time: Some(end_time.into()),
                    validation_id: Some(uuid),
                })
            }
        }
    }
    pub fn read_yaml_data(file_path: &str) -> Result<Suite, MachineValidationError> {
        let yaml_content = match std::fs::read_to_string(file_path) {
            Ok(content) => content,
            Err(e) => {
                return Err(MachineValidationError::ConfigFileRead(e.to_string()));
            }
        };
        let parsed_data: Result<Suite, serde_yaml::Error> = serde_yaml::from_str(&yaml_content);
        let config = match parsed_data {
            Ok(data) => data,
            Err(e) => return Err(MachineValidationError::Parse(e.to_string())),
        };
        Ok(config)
    }
    pub async fn run(
        self,
        s: Suite,
        execute_tests_sequentially: bool,
    ) -> Result<(), MachineValidationError> {
        if execute_tests_sequentially {
            for (suite_name, components) in s.components {
                trace!("Suite {}", suite_name);
                for (category_name, category) in components.subcategories {
                    trace!("Category {}", category_name);
                    for (test_name, command) in category {
                        if !command.contexts.contains(&self.context) {
                            continue;
                        }
                        let result = MachineValidation::execute_machinevalidation_command(
                            test_name,
                            command,
                            self.context.clone(),
                            rpc::common::Uuid {
                                value: self.uuid.clone(),
                            },
                        )
                        .await;
                        self.sender_tx.send(result).await.unwrap();
                    }
                }
            }
            // Send Stop signal to receiver
            self.sender_tx.send(None).await.unwrap();
        } else {
            trace!("To be implemented");
        }
        Ok(())
    }
}
