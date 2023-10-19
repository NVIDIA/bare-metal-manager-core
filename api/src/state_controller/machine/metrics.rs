/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

//! Defines custom metrics that are collected and emitted by the Machine State Controller

use std::collections::{HashMap, HashSet};

use opentelemetry_api::{
    metrics::{self, Meter, ObservableGauge},
    KeyValue,
};

use crate::state_controller::metrics::MetricsEmitter;

#[derive(Debug, Default)]
pub struct MachineMetrics {
    pub agent_version: Option<String>,
    pub dpu_up: bool,
    pub dpu_healthy: bool,
    pub failed_dpu_healthchecks: HashSet<String>,
    pub dpu_firmware_version: Option<String>,
    pub client_certificate_expiry: Option<u64>,
    pub machine_id: Option<String>,
}

#[derive(Debug, Default)]
pub struct MachineStateControllerIterationMetrics {
    pub agent_versions: HashMap<String, usize>,
    pub dpus_up: usize,
    pub dpus_healthy: usize,
    pub failed_dpu_healthchecks: HashMap<String, usize>,
    pub dpu_firmware_versions: HashMap<String, usize>,
    pub client_certificate_expiration_times: HashMap<String, u64>,
}

#[derive(Debug)]
pub struct MachineMetricsEmitter {
    dpus_up_gauge: ObservableGauge<u64>,
    dpus_healthy_gauge: ObservableGauge<u64>,
    failed_dpu_healthchecks_gauge: ObservableGauge<u64>,
    dpu_agent_version_gauge: ObservableGauge<u64>,
    dpu_firmware_version_gauge: ObservableGauge<u64>,
    client_certificate_expiration_gauge: ObservableGauge<u64>,
}

impl MetricsEmitter for MachineMetricsEmitter {
    type ObjectMetrics = MachineMetrics;
    type IterationMetrics = MachineStateControllerIterationMetrics;

    fn new(_object_type: &str, meter: &Meter) -> Self {
        let dpus_up_gauge = meter
            .u64_observable_gauge("forge_dpus_up_count")
            .with_description("The total number of DPUs in the system that are up. Up means we have received a health report less than 5 minutes ago.")
            .init();
        let dpus_healthy_gauge = meter
            .u64_observable_gauge("forge_dpus_healthy_count")
            .with_description("The total number of DPUs in the system that have reported healthy in the last report. Healthy does not imply up - the report from the DPU might be outdated.")
            .init();
        let failed_dpu_healthchecks_gauge = meter
            .u64_observable_gauge("forge_dpu_health_check_failed_count")
            .with_description(
                "The total number of DPUs in the system that have failed a health-check.",
            )
            .init();

        let dpu_agent_version_gauge = meter
            .u64_observable_gauge("forge_dpu_agent_version_count")
            .with_description(
                "The amount of Forge DPU agents which have reported a certain version.",
            )
            .init();

        let dpu_firmware_version_gauge = meter
            .u64_observable_gauge("forge_dpu_firmware_version_count")
            .with_description("The amount of DPUs which have reported a certain firmware version.")
            .init();

        let client_certificate_expiration_gauge = meter
            .u64_observable_gauge("forge_dpu_client_certificate_expiration_time")
            .with_description("The expiration time (epoch seconds) for the client certificate associated with a given DPU.")
            .init();

        Self {
            dpus_up_gauge,
            dpus_healthy_gauge,
            dpu_agent_version_gauge,
            failed_dpu_healthchecks_gauge,
            dpu_firmware_version_gauge,
            client_certificate_expiration_gauge,
        }
    }

    fn instruments(&self) -> Vec<std::sync::Arc<dyn std::any::Any>> {
        vec![
            self.dpus_up_gauge.as_any(),
            self.dpus_healthy_gauge.as_any(),
            self.dpu_agent_version_gauge.as_any(),
            self.failed_dpu_healthchecks_gauge.as_any(),
            self.dpu_firmware_version_gauge.as_any(),
        ]
    }

    fn merge_object_handling_metrics(
        iteration_metrics: &mut Self::IterationMetrics,
        object_metrics: &Self::ObjectMetrics,
    ) {
        if object_metrics.dpu_up {
            iteration_metrics.dpus_up += 1;
        }
        if object_metrics.dpu_healthy {
            iteration_metrics.dpus_healthy += 1;
        }

        for failed_healthcheck in &object_metrics.failed_dpu_healthchecks {
            *iteration_metrics
                .failed_dpu_healthchecks
                .entry(failed_healthcheck.clone())
                .or_default() += 1;
        }

        if let Some(version) = object_metrics.agent_version.as_ref() {
            *iteration_metrics
                .agent_versions
                .entry(version.clone())
                .or_default() += 1;
        }

        if let Some(version) = object_metrics.dpu_firmware_version.as_ref() {
            *iteration_metrics
                .dpu_firmware_versions
                .entry(version.clone())
                .or_default() += 1;
        }

        if let Some(time) = object_metrics.client_certificate_expiry {
            if let Some(machine_id) = object_metrics.machine_id.as_ref() {
                iteration_metrics
                    .client_certificate_expiration_times
                    .entry(machine_id.clone())
                    .and_modify(|entry| *entry = time)
                    .or_insert(time);
            }
        }
    }

    fn emit_gauges(
        &self,
        observer: &dyn metrics::Observer,
        iteration_metrics: &Self::IterationMetrics,
        attributes: &[KeyValue],
    ) {
        observer.observe_u64(
            &self.dpus_up_gauge,
            iteration_metrics.dpus_up as u64,
            attributes,
        );
        observer.observe_u64(
            &self.dpus_healthy_gauge,
            iteration_metrics.dpus_healthy as u64,
            attributes,
        );

        let mut failed_health_check_attr = attributes.to_vec();
        // Placeholder that is replaced in the loop in order not having to reallocate the Vec each time
        failed_health_check_attr.push(KeyValue::new("failure", "".to_string()));
        for (failure, count) in &iteration_metrics.failed_dpu_healthchecks {
            failed_health_check_attr.last_mut().unwrap().value = failure.clone().into();
            observer.observe_u64(
                &self.failed_dpu_healthchecks_gauge,
                *count as u64,
                &failed_health_check_attr,
            );
        }

        let mut agent_version_attrs = attributes.to_vec();
        // Placeholder that is replaced in the loop in order not having to reallocate the Vec each time
        agent_version_attrs.push(KeyValue::new("version", "".to_string()));
        for (version, count) in &iteration_metrics.agent_versions {
            // TODO: Can prometheus labels hold arbitrary strings?
            // Since there is no `try_into()` into method for those values,
            // we assume OpenTelemetry escapes them internally
            agent_version_attrs.last_mut().unwrap().value = version.clone().into();
            observer.observe_u64(
                &self.dpu_agent_version_gauge,
                *count as u64,
                &agent_version_attrs,
            );
        }

        agent_version_attrs.pop();
        // Placeholder that is replaced in the loop in order not having to reallocate the Vec each time
        agent_version_attrs.push(KeyValue::new("firmware_version", "".to_string()));
        for (version, count) in &iteration_metrics.dpu_firmware_versions {
            agent_version_attrs.last_mut().unwrap().value = version.clone().into();
            observer.observe_u64(
                &self.dpu_firmware_version_gauge,
                *count as u64,
                &agent_version_attrs,
            );
        }

        let mut dpu_machine_id_attributes = attributes.to_vec();
        // Placeholder that is replaced in the loop in order not having to reallocate the Vec each time
        dpu_machine_id_attributes.push(KeyValue::new("dpu_machine_id", "".to_string()));
        for (id, time) in &iteration_metrics.client_certificate_expiration_times {
            dpu_machine_id_attributes.last_mut().unwrap().value = id.clone().into();
            observer.observe_u64(
                &self.client_certificate_expiration_gauge,
                *time,
                dpu_machine_id_attributes.as_slice(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_machine_metrics() {
        let object_metrics = vec![
            MachineMetrics {
                agent_version: None,
                dpu_up: true,
                dpu_healthy: true,
                failed_dpu_healthchecks: HashSet::from_iter([]),
                dpu_firmware_version: None,
                client_certificate_expiry: Some(1),
                machine_id: Some("machine a".to_string()),
            },
            MachineMetrics {
                agent_version: Some("v1".to_string()),
                dpu_up: true,
                dpu_healthy: false,
                failed_dpu_healthchecks: HashSet::from_iter(["bgp".to_string(), "ntp".to_string()]),
                dpu_firmware_version: None,
                client_certificate_expiry: Some(2),
                machine_id: Some("machine a".to_string()),
            },
            MachineMetrics {
                agent_version: Some("v3".to_string()),
                dpu_up: false,
                dpu_healthy: true,
                failed_dpu_healthchecks: HashSet::from_iter([]),
                dpu_firmware_version: Some("v4".to_string()),
                client_certificate_expiry: Some(3),
                machine_id: Some("machine b".to_string()),
            },
            MachineMetrics {
                agent_version: Some("v3".to_string()),
                dpu_up: true,
                dpu_healthy: true,
                failed_dpu_healthchecks: HashSet::from_iter([]),
                dpu_firmware_version: Some("v2".to_string()),
                client_certificate_expiry: None,
                machine_id: Some("machine b".to_string()),
            },
            MachineMetrics {
                agent_version: None,
                dpu_up: true,
                dpu_healthy: false,
                failed_dpu_healthchecks: HashSet::from_iter(["bgp".to_string(), "dns".to_string()]),
                dpu_firmware_version: Some("v4".to_string()),
                client_certificate_expiry: Some(55),
                machine_id: None,
            },
        ];

        let mut iteration_metrics = MachineStateControllerIterationMetrics::default();
        for om in &object_metrics {
            MachineMetricsEmitter::merge_object_handling_metrics(&mut iteration_metrics, om);
        }

        assert_eq!(
            iteration_metrics.agent_versions,
            HashMap::from_iter([("v1".to_string(), 1), ("v3".to_string(), 2)])
        );
        assert_eq!(iteration_metrics.dpus_up, 4);
        assert_eq!(iteration_metrics.dpus_healthy, 3);
        assert_eq!(
            iteration_metrics.failed_dpu_healthchecks,
            HashMap::from_iter([
                ("bgp".to_string(), 2),
                ("ntp".to_string(), 1),
                ("dns".to_string(), 1)
            ])
        );
        assert_eq!(
            iteration_metrics.dpu_firmware_versions,
            HashMap::from_iter([("v2".to_string(), 1), ("v4".to_string(), 2)])
        );

        assert_eq!(
            iteration_metrics.client_certificate_expiration_times,
            HashMap::from_iter([("machine a".to_string(), 2), ("machine b".to_string(), 3)])
        );
    }
}
