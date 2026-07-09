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

use serde_json::json;

use crate::json::JsonExt;
use crate::redfish::Builder;

#[derive(Clone)]
pub struct SerialConsole {
    value: serde_json::Value,
}

impl SerialConsole {
    pub fn to_json(&self) -> serde_json::Value {
        self.value.clone()
    }
}

pub fn builder() -> SerialConsoleBuilder {
    SerialConsoleBuilder { value: json!({}) }
}

pub struct SerialConsoleBuilder {
    value: serde_json::Value,
}

impl Builder for SerialConsoleBuilder {
    fn apply_patch(self, patch: serde_json::Value) -> Self {
        Self {
            value: self.value.patch(patch),
        }
    }
}

impl SerialConsoleBuilder {
    pub fn max_concurrent_sessions(self, value: u64) -> Self {
        self.apply_patch(json!({ "MaxConcurrentSessions": value }))
    }

    pub fn ssh(self, value: &SerialConsoleProtocol) -> Self {
        self.apply_patch(json!({ "SSH": value.to_json() }))
    }

    pub fn ipmi(self, value: &SerialConsoleProtocol) -> Self {
        self.apply_patch(json!({ "IPMI": value.to_json() }))
    }

    pub fn build(self) -> SerialConsole {
        SerialConsole { value: self.value }
    }
}

#[derive(Clone)]
pub struct SerialConsoleProtocol {
    value: serde_json::Value,
}

impl SerialConsoleProtocol {
    fn to_json(&self) -> serde_json::Value {
        self.value.clone()
    }
}

pub fn protocol_builder() -> SerialConsoleProtocolBuilder {
    SerialConsoleProtocolBuilder { value: json!({}) }
}

pub struct SerialConsoleProtocolBuilder {
    value: serde_json::Value,
}

impl Builder for SerialConsoleProtocolBuilder {
    fn apply_patch(self, patch: serde_json::Value) -> Self {
        Self {
            value: self.value.patch(patch),
        }
    }
}

impl SerialConsoleProtocolBuilder {
    pub fn service_enabled(self, value: bool) -> Self {
        self.apply_patch(json!({ "ServiceEnabled": value }))
    }

    pub fn port(self, value: u16) -> Self {
        self.apply_patch(json!({ "Port": value }))
    }

    pub fn shared_with_manager_cli(self, value: bool) -> Self {
        self.apply_patch(json!({ "SharedWithManagerCLI": value }))
    }

    pub fn console_entry_command(self, value: &str) -> Self {
        self.add_str_field("ConsoleEntryCommand", value)
    }

    pub fn hot_key_sequence_display(self, value: &str) -> Self {
        self.add_str_field("HotKeySequenceDisplay", value)
    }

    pub fn build(self) -> SerialConsoleProtocol {
        SerialConsoleProtocol { value: self.value }
    }
}
