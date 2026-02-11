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

use std::str::FromStr;

use health_report::{HealthAlertClassification, HealthProbeId};
use nv_redfish::resource::Health as BmcHealth;

#[derive(Debug, Clone, Copy)]
enum SensorHealth {
    Ok,
    Warning,
    Critical,
    SensorFailure,
}

impl SensorHealth {
    fn to_classification(self) -> &'static str {
        match self {
            Self::Ok => "SensorOk",
            Self::Warning => "SensorWarning",
            Self::Critical => "SensorCritical",
            Self::SensorFailure => "SensorFailure",
        }
    }
}

#[derive(Debug)]
pub(crate) struct SensorHealthData {
    pub(crate) entity_type: String,
    pub(crate) sensor_id: String,
    pub(crate) reading: f64,
    pub(crate) reading_type: String,
    pub(crate) unit: String,
    pub(crate) upper_critical: Option<f64>,
    pub(crate) lower_critical: Option<f64>,
    pub(crate) upper_caution: Option<f64>,
    pub(crate) lower_caution: Option<f64>,
    pub(crate) range_max: Option<f64>,
    pub(crate) range_min: Option<f64>,
    pub(crate) bmc_health: Option<BmcHealth>,
}

impl SensorHealthData {
    fn fmt_range(low: Option<f64>, high: Option<f64>) -> String {
        match (low, high) {
            (None, None) => "not set".to_string(),
            (Some(l), Some(h)) => format!("{:.1} to {:.1}", l, h),
            (Some(l), None) => format!("min {:.1}", l),
            (None, Some(h)) => format!("max {:.1}", h),
        }
    }

    fn classify(&self) -> SensorHealth {
        if let Some(max) = self.range_max
            && self.reading > max
            && self.range_max > self.range_min
        {
            return SensorHealth::SensorFailure;
        }

        if let Some(min) = self.range_min
            && self.reading < min
            && self.range_max > self.range_min
        {
            return SensorHealth::SensorFailure;
        }

        if let Some(upper_critical) = self.upper_critical
            && self.reading >= upper_critical
            && self.upper_critical > self.lower_critical
        {
            return SensorHealth::Critical;
        }

        if let Some(lower_critical) = self.lower_critical
            && self.reading <= lower_critical
            && self.upper_critical > self.lower_critical
        {
            return SensorHealth::Critical;
        }

        if let Some(upper_caution) = self.upper_caution
            && self.reading >= upper_caution
            && self.upper_caution > self.lower_caution
        {
            return SensorHealth::Warning;
        }
        if let Some(lower_caution) = self.lower_caution
            && self.reading <= lower_caution
            && self.upper_caution > self.lower_caution
        {
            return SensorHealth::Warning;
        }

        SensorHealth::Ok
    }

    pub(crate) fn to_health_result(&self) -> SensorHealthResult {
        let health = self.classify();
        let probe_id = HealthProbeId::from_str("BMC_Sensor").expect("cannot fail");

        let bmc_reports_ok = matches!(self.bmc_health, Some(BmcHealth::Ok));

        match health {
            SensorHealth::Ok => SensorHealthResult::Success(health_report::HealthProbeSuccess {
                id: probe_id,
                target: Some(self.sensor_id.clone()),
            }),
            health => {
                if bmc_reports_ok {
                    tracing::warn!(
                        sensor_id = %self.sensor_id,
                        entity_type = %self.entity_type,
                        reading = self.reading,
                        unit = %self.unit,
                        reading_type = %self.reading_type,
                        valid_range = %Self::fmt_range(self.range_min, self.range_max),
                        caution_range = %Self::fmt_range(self.lower_caution, self.upper_caution),
                        critical_range = %Self::fmt_range(self.lower_critical, self.upper_critical),
                        calculated_status = ?health,
                        "Threshold check indicates issue but BMC reports sensor as OK - likely incorrect thresholds, reporting OK"
                    );
                    return SensorHealthResult::Success(health_report::HealthProbeSuccess {
                        id: probe_id,
                        target: Some(self.sensor_id.clone()),
                    });
                }

                let status = match health {
                    SensorHealth::Warning => "Warning",
                    SensorHealth::Critical => "Critical",
                    SensorHealth::SensorFailure => "Sensor Failure",
                    SensorHealth::Ok => "Ok",
                };

                let message = format!(
                    "{} '{}': {} - reading {:.2}{} ({}), valid range: {}, caution: {}, critical: {}",
                    self.entity_type,
                    self.sensor_id,
                    status,
                    self.reading,
                    self.unit,
                    self.reading_type,
                    Self::fmt_range(self.range_min, self.range_max),
                    Self::fmt_range(self.lower_caution, self.upper_caution),
                    Self::fmt_range(self.lower_critical, self.upper_critical),
                );
                let classifications = if let Ok(classification) = health.to_classification().parse()
                {
                    vec![classification, HealthAlertClassification::hardware()]
                } else {
                    vec![HealthAlertClassification::hardware()]
                };

                SensorHealthResult::Alert(health_report::HealthProbeAlert {
                    id: probe_id,
                    target: Some(self.sensor_id.clone()),
                    in_alert_since: None,
                    message,
                    tenant_message: None,
                    classifications,
                })
            }
        }
    }
}

pub(crate) enum SensorHealthResult {
    Success(health_report::HealthProbeSuccess),
    Alert(health_report::HealthProbeAlert),
}
