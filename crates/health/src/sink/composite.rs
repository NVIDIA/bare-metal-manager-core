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

use std::sync::Arc;

use super::{CollectorEvent, DataSink, EventContext};
use crate::HealthError;

pub struct CompositeDataSink {
    sinks: Vec<Arc<dyn DataSink>>,
}

impl CompositeDataSink {
    pub fn new(sinks: Vec<Arc<dyn DataSink>>) -> Self {
        Self { sinks }
    }
}

impl DataSink for CompositeDataSink {
    fn handle_event(
        &self,
        context: &EventContext,
        event: &CollectorEvent,
    ) -> Result<(), HealthError> {
        for sink in &self.sinks {
            if let Err(error) = sink.handle_event(context, event) {
                tracing::warn!(error = ?error, "sink failed to process event");
            }
        }

        Ok(())
    }
}
