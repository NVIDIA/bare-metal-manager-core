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

use std::borrow::Cow;

use serde_json::json;

use crate::json::{JsonExt, JsonPatch};
use crate::redfish;
use crate::redfish::Builder;

pub fn system_collection(system_id: &str) -> redfish::Collection<'static> {
    let odata_id = format!("/redfish/v1/Systems/{system_id}/Processors");
    redfish::Collection {
        odata_id: Cow::Owned(odata_id),
        odata_type: Cow::Borrowed("#ProcessorCollection.ProcessorCollection"),
        name: Cow::Borrowed("Processors Collection"),
    }
}

pub fn system_resource<'a>(system_id: &str, processor_id: &'a str) -> redfish::Resource<'a> {
    let odata_id = format!("/redfish/v1/Systems/{system_id}/Processors/{processor_id}");
    redfish::Resource {
        odata_id: Cow::Owned(odata_id),
        odata_type: Cow::Borrowed("#Processor.v1_20_0.Processor"),
        id: Cow::Borrowed(processor_id),
        name: Cow::Borrowed("Processor"),
    }
}

pub fn metrics_resource(system_id: &str, processor_id: &str) -> redfish::Resource<'static> {
    let odata_id =
        format!("/redfish/v1/Systems/{system_id}/Processors/{processor_id}/ProcessorMetrics");
    redfish::Resource {
        odata_id: Cow::Owned(odata_id),
        odata_type: Cow::Borrowed("#ProcessorMetrics.v1_6_1.ProcessorMetrics"),
        id: Cow::Borrowed("ProcessorMetrics"),
        name: Cow::Borrowed("Processor Metrics"),
    }
}

/// A mock Redfish `Processor` plus its associated `ProcessorMetrics` resource.
pub struct Processor {
    pub id: Cow<'static, str>,
    resource: serde_json::Value,
    metrics: serde_json::Value,
}

impl Processor {
    pub fn to_json(&self) -> serde_json::Value {
        self.resource.clone()
    }

    pub fn metrics_json(&self) -> serde_json::Value {
        self.metrics.clone()
    }
}

pub fn builder(resource: &redfish::Resource) -> ProcessorBuilder {
    ProcessorBuilder {
        id: Cow::Owned(resource.id.to_string()),
        value: resource.json_patch(),
    }
}

pub struct ProcessorBuilder {
    id: Cow<'static, str>,
    value: serde_json::Value,
}

impl Builder for ProcessorBuilder {
    fn apply_patch(self, patch: serde_json::Value) -> Self {
        Self {
            value: self.value.patch(patch),
            id: self.id,
        }
    }
}

impl ProcessorBuilder {
    pub fn processor_type(self, value: &str) -> Self {
        self.add_str_field("ProcessorType", value)
    }

    pub fn metrics(self, metrics: &redfish::Resource<'_>) -> Self {
        self.apply_patch(metrics.nav_property("Metrics"))
    }

    pub fn status(self, status: redfish::resource::Status) -> Self {
        self.apply_patch(json!({ "Status": status.into_json() }))
    }

    fn build(self, metrics: serde_json::Value) -> Processor {
        Processor {
            id: self.id,
            resource: self.value,
            metrics,
        }
    }
}

pub fn gpu(system_id: &str, processor_id: &str, core_voltage_sensor_uri: &str) -> Processor {
    let metrics = metrics_resource(system_id, processor_id);
    let metrics_json = nvidia_gpu_metrics(&metrics, processor_id, core_voltage_sensor_uri);
    builder(&system_resource(system_id, processor_id))
        .processor_type("GPU")
        .status(redfish::resource::Status::Ok)
        .metrics(&metrics)
        .build(metrics_json)
}

fn nvidia_gpu_metrics(
    resource: &redfish::Resource<'_>,
    processor_id: &str,
    core_voltage_sensor_uri: &str,
) -> serde_json::Value {
    resource.json_patch().patch(json!({
        "Name": format!("{processor_id} Processor Metrics"),
        "BandwidthPercent": 0,
        "OperatingSpeedMHz": 0,
        "PowerLimitThrottleDuration": "PT0S",
        "ThermalLimitThrottleDuration": "PT0S",
        "CacheMetricsTotal": {
            "LifeTime": {
                "CorrectableECCErrorCount": 0,
                "UncorrectableECCErrorCount": 0
            }
        },
        "CoreVoltage": {
            "DataSourceUri": core_voltage_sensor_uri,
            "Reading": 0.8
        },
        "PCIeErrors": {
            "CorrectableErrorCount": 2,
            "FatalErrorCount": 0,
            "L0ToRecoveryCount": 2,
            "NAKReceivedCount": 0,
            "NAKSentCount": 0,
            "NonFatalErrorCount": 0,
            "ReplayCount": 0,
            "ReplayRolloverCount": 0,
            "UnsupportedRequestCount": 0
        },
        "Oem": {
            "Nvidia": {
                "@odata.type": "#NvidiaProcessorMetrics.v1_4_0.NvidiaGPUProcessorMetrics",
                "PCIeRXBytes": 45388,
                "PCIeTXBytes": 51108,
                "SMUtilizationPercent": 0,
                "SRAMECCErrorThresholdExceeded": false,
                "ThrottleReasons": ["NA"]
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::gpu;

    #[test]
    fn gpu_processor_links_to_metrics_and_chassis_sensor() {
        let processor = gpu(
            "HGX_Baseboard_0",
            "GPU_0",
            "/redfish/v1/Chassis/HGX_GPU_0/Sensors/Voltage_1",
        );

        let resource = processor.to_json();
        assert_eq!(resource["Id"], "GPU_0");
        assert_eq!(resource["ProcessorType"], "GPU");
        assert_eq!(
            resource["Metrics"]["@odata.id"],
            "/redfish/v1/Systems/HGX_Baseboard_0/Processors/GPU_0/ProcessorMetrics"
        );

        let metrics = processor.metrics_json();
        assert_eq!(
            metrics["@odata.id"],
            "/redfish/v1/Systems/HGX_Baseboard_0/Processors/GPU_0/ProcessorMetrics"
        );
        // CoreVoltage is sensor-backed, so the health metrics collector skips it
        // (it is emitted by the sensor collector via this DataSourceUri instead).
        assert_eq!(
            metrics["CoreVoltage"]["DataSourceUri"],
            "/redfish/v1/Chassis/HGX_GPU_0/Sensors/Voltage_1"
        );
        // Fields the metrics collector flattens and emits.
        assert_eq!(metrics["PCIeErrors"]["CorrectableErrorCount"], 2);
        assert_eq!(metrics["PowerLimitThrottleDuration"], "PT0S");
        assert_eq!(metrics["ThermalLimitThrottleDuration"], "PT0S");
    }
}
