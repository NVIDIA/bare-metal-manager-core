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

use opentelemetry::{
    metrics::{self, Histogram, Meter, ObservableGauge},
    KeyValue,
};

use crate::{
    model::{hardware_info::MachineInventorySoftwareComponent, tenant::TenantOrganizationId},
    state_controller::metrics::MetricsEmitter,
};

#[derive(Debug, Default)]
pub struct MachineMetrics {
    pub agent_versions: HashMap<String, usize>,
    pub dpus_up: usize,
    pub dpus_healthy: usize,
    /// DPU probe alerts by Probe ID and Target
    /// For Multi-DPU, the same host could experience failures on multiple DPUs
    pub dpu_health_probe_alerts: HashMap<(health_report::HealthProbeId, Option<String>), usize>,
    pub dpu_firmware_versions: HashMap<String, usize>,
    pub machine_inventory_component_versions: HashMap<MachineInventorySoftwareComponent, usize>,
    pub client_certificate_expiry: HashMap<String, Option<i64>>,
    pub machine_reboot_attempts_in_booting_with_discovery_image: Option<u64>,
    pub machine_reboot_attempts_in_failed_during_discovery: Option<u64>,
    pub num_gpus: usize,
    pub in_use_by_tenant: Option<TenantOrganizationId>,
    /// Health probe alerts for the aggregate host by Probe ID and Target
    pub health_probe_alerts: HashSet<(health_report::HealthProbeId, Option<String>)>,
    pub health_alert_classifications: HashSet<health_report::HealthAlertClassification>,
    /// The amount of configured `merge` overrides
    pub num_merge_overrides: usize,
    /// Whether an override of type `replace` is configured
    pub replace_override_enabled: bool,
    /// Whether the Machine is usable as an instance for a tenant
    /// Doing so requires
    /// - the Machine to be in `Ready` state
    /// - the Machine has not yet been target of an instance creation request
    /// - no health alerts which classification `PreventAllocations` to be set
    /// - the machine not to be in Maintenance Mode
    pub is_usable_as_instance: bool,
    /// is the host's bios password set
    pub is_host_bios_password_set: bool,
}

#[derive(Debug, Default)]
pub struct MachineStateControllerIterationMetrics {
    pub agent_versions: HashMap<String, usize>,
    pub dpus_up: usize,
    pub dpus_healthy: usize,
    pub unhealthy_dpus_by_probe_id: HashMap<(String, Option<String>), usize>,
    pub dpu_firmware_versions: HashMap<String, usize>,
    /// Map from Machine component (names and version string) to the count of
    /// machines which run that version combination
    pub machine_inventory_component_versions: HashMap<MachineInventorySoftwareComponent, usize>,
    pub client_certificate_expiration_times: HashMap<String, i64>,
    pub machine_reboot_attempts_in_booting_with_discovery_image: Vec<u64>,
    pub machine_reboot_attempts_in_failed_during_discovery: Vec<u64>,
    pub gpus_usable: usize,
    pub gpus_total: usize,
    pub gpus_in_use_by_tenant: HashMap<TenantOrganizationId, usize>,
    pub hosts_in_use_by_tenant: HashMap<TenantOrganizationId, usize>,
    pub hosts_usable: usize,
    pub hosts_total: usize,
    /// The amount of hosts by Health status (healthy==true) and assignment status
    pub hosts_healthy: HashMap<(bool, IsInUseByTenant), usize>,
    /// The amount of unhealthy hosts by Probe ID, Probe Target and assignment status
    pub unhealthy_hosts_by_probe_id: HashMap<(String, Option<String>, IsInUseByTenant), usize>,
    /// The amount of unhealthy hosts by Alert classification and assignment status
    pub unhealthy_hosts_by_classification_id: HashMap<(String, IsInUseByTenant), usize>,
    /// The amount of configured overrides by type (merge vs replace) and assignment status
    pub num_overrides: HashMap<(&'static str, IsInUseByTenant), usize>,
    pub hosts_with_bios_password_set: usize,
}

#[derive(Copy, Clone, Hash, PartialEq, Eq, Debug)]
pub struct IsInUseByTenant(bool);

#[derive(Debug)]
pub struct MachineMetricsEmitter {
    dpus_up_gauge: ObservableGauge<u64>,
    dpus_healthy_gauge: ObservableGauge<u64>,
    gpus_in_use_gauge: ObservableGauge<u64>,
    gpus_in_use_by_tenant_gauge: ObservableGauge<u64>,
    gpus_total_gauge: ObservableGauge<u64>,
    hosts_in_use_by_tenant_gauge: ObservableGauge<u64>,
    hosts_in_use_gauge: ObservableGauge<u64>,
    hosts_usable_gauge: ObservableGauge<u64>,
    gpus_usable_gauge: ObservableGauge<u64>,
    hosts_health_status_gauge: ObservableGauge<u64>,
    failed_dpu_healthchecks_gauge: ObservableGauge<u64>,
    unhealthy_hosts_by_probe_id_gauge: ObservableGauge<u64>,
    unhealthy_hosts_by_classification_gauge: ObservableGauge<u64>,
    dpu_agent_version_gauge: ObservableGauge<u64>,
    dpu_firmware_version_gauge: ObservableGauge<u64>,
    machine_inventory_component_versions_gauge: ObservableGauge<u64>,
    client_certificate_expiration_gauge: ObservableGauge<i64>,
    machine_reboot_attempts_in_booting_with_discovery_image: Histogram<u64>,
    machine_reboot_attempts_in_failed_during_discovery: Histogram<u64>,
    hosts_health_overrides_gauge: ObservableGauge<u64>,
    hosts_with_bios_password_set: ObservableGauge<u64>,
}

impl MetricsEmitter for MachineMetricsEmitter {
    type ObjectMetrics = MachineMetrics;
    type IterationMetrics = MachineStateControllerIterationMetrics;

    fn new(_object_type: &str, meter: &Meter) -> Self {
        let gpus_total_gauge = meter
            .u64_observable_gauge("forge_gpus_total_count")
            .with_description("The total number of GPUs available in the Forge site")
            .init();
        let hosts_usable_gauge = meter
            .u64_observable_gauge("forge_hosts_usable_count")
            .with_description("The remaining number of hosts in the Forge site which are available for immediate instance creation")
            .init();
        let gpus_usable_gauge = meter
            .u64_observable_gauge("forge_gpus_usable_count")
            .with_description("The remaining number of GPUs in the Forge site which are available for immediate instance creation")
            .init();
        let gpus_in_use_gauge = meter
            .u64_observable_gauge("forge_gpus_in_use_count")
            .with_description("The total number of GPUs that are actively used by tenants in instances in the Forge site")
            .init();
        let hosts_in_use_gauge = meter
            .u64_observable_gauge("forge_hosts_in_use_count")
            .with_description("The total number of hosts that are actively used by tenants as instances in the Forge site")
            .init();
        let gpus_in_use_by_tenant_gauge = meter
            .u64_observable_gauge("forge_gpus_in_use_by_tenant_count")
            .with_description(
                "The number of GPUs that are actively used by tenants as instances - by tenant",
            )
            .init();
        let hosts_in_use_by_tenant_gauge = meter
            .u64_observable_gauge("forge_hosts_in_use_by_tenant_count")
            .with_description(
                "The number of hosts that are actively used by tenants as instances - by tenant",
            )
            .init();

        let dpus_up_gauge = meter
            .u64_observable_gauge("forge_dpus_up_count")
            .with_description("The total number of DPUs in the system that are up. Up means we have received a health report less than 5 minutes ago.")
            .init();
        let dpus_healthy_gauge = meter
            .u64_observable_gauge("forge_dpus_healthy_count")
            .with_description("The total number of DPUs in the system that have reported healthy in the last report. Healthy does not imply up - the report from the DPU might be outdated.")
            .init();
        let hosts_health_status_gauge = meter
            .u64_observable_gauge("forge_hosts_health_status_count")
            .with_description("The total number of Managed Hosts in the system that have reported any a healthy nor not healthy status - based on the presence of health probe alerts")
            .init();
        let hosts_health_overrides_gauge = meter
            .u64_observable_gauge("forge_hosts_health_overrides_count")
            .with_description("The amount of health overrides that are configured in the site")
            .init();

        let failed_dpu_healthchecks_gauge = meter
            .u64_observable_gauge("forge_dpu_health_check_failed_count")
            .with_description(
                "The total number of DPUs in the system that have failed a health-check.",
            )
            .init();

        let unhealthy_hosts_by_probe_id_gauge = meter
            .u64_observable_gauge("forge_hosts_unhealthy_by_probe_id_count")
            .with_description(
                "The amount of ManagedHosts which reported a certain Health Probe Alert",
            )
            .init();

        let unhealthy_hosts_by_classification_gauge = meter
            .u64_observable_gauge("forge_hosts_unhealthy_by_classification_count")
            .with_description(
                "The amount of ManagedHosts which are marked with a certain classification due to being unhealthy",
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

        let machine_inventory_component_versions_gauge = meter
            .u64_observable_gauge("forge_machine_inventory_component_version_count")
            .with_description(
                "The amount of machines report software components with a certain version.",
            )
            .init();

        let client_certificate_expiration_gauge = meter
            .i64_observable_gauge("forge_dpu_client_certificate_expiration_time")
            .with_description("The expiration time (epoch seconds) for the client certificate associated with a given DPU.")
            .init();

        let machine_reboot_attempts_in_booting_with_discovery_image = meter
            .u64_histogram("forge_reboot_attempts_in_booting_with_discovery_image")
            .with_description("The amount of machines rebooted again in BootingWithDiscoveryImage since there is no response after a certain time from host.")
            .init();

        let machine_reboot_attempts_in_failed_during_discovery = meter
            .u64_histogram("forge_reboot_attempts_in_failed_during_discovery")
            .with_description("The amount of machines rebooted again in Failed state due to discovery failure since there is no response after a certain time from host.")
            .init();

        let hosts_with_bios_password_set = meter
            .u64_observable_gauge("forge_hosts_with_bios_password_set")
            .with_description(
                "The total number of Hosts in the system that have their BIOS password set.",
            )
            .init();

        Self {
            gpus_in_use_gauge,
            gpus_in_use_by_tenant_gauge,
            hosts_in_use_gauge,
            hosts_in_use_by_tenant_gauge,
            hosts_usable_gauge,
            gpus_total_gauge,
            gpus_usable_gauge,
            dpus_up_gauge,
            dpus_healthy_gauge,
            dpu_agent_version_gauge,
            hosts_health_status_gauge,
            failed_dpu_healthchecks_gauge,
            unhealthy_hosts_by_probe_id_gauge,
            unhealthy_hosts_by_classification_gauge,
            hosts_health_overrides_gauge,
            dpu_firmware_version_gauge,
            machine_inventory_component_versions_gauge,
            client_certificate_expiration_gauge,
            machine_reboot_attempts_in_booting_with_discovery_image,
            machine_reboot_attempts_in_failed_during_discovery,
            hosts_with_bios_password_set,
        }
    }

    fn instruments(&self) -> Vec<std::sync::Arc<dyn std::any::Any>> {
        vec![
            self.gpus_total_gauge.as_any(),
            self.gpus_in_use_gauge.as_any(),
            self.gpus_in_use_by_tenant_gauge.as_any(),
            self.hosts_in_use_gauge.as_any(),
            self.hosts_in_use_by_tenant_gauge.as_any(),
            self.hosts_usable_gauge.as_any(),
            self.gpus_usable_gauge.as_any(),
            self.dpus_up_gauge.as_any(),
            self.dpus_healthy_gauge.as_any(),
            self.dpu_agent_version_gauge.as_any(),
            self.hosts_health_status_gauge.as_any(),
            self.hosts_health_overrides_gauge.as_any(),
            self.failed_dpu_healthchecks_gauge.as_any(),
            self.unhealthy_hosts_by_probe_id_gauge.as_any(),
            self.unhealthy_hosts_by_classification_gauge.as_any(),
            self.dpu_firmware_version_gauge.as_any(),
            self.machine_inventory_component_versions_gauge.as_any(),
            self.client_certificate_expiration_gauge.as_any(),
            self.hosts_with_bios_password_set.as_any(),
        ]
    }

    fn merge_object_handling_metrics(
        iteration_metrics: &mut Self::IterationMetrics,
        object_metrics: &Self::ObjectMetrics,
    ) {
        iteration_metrics.hosts_total += 1;
        iteration_metrics.dpus_up += object_metrics.dpus_up;
        iteration_metrics.dpus_healthy += object_metrics.dpus_healthy;

        let is_healthy = object_metrics.health_probe_alerts.is_empty();
        let is_assigned = IsInUseByTenant(object_metrics.in_use_by_tenant.is_some());
        *iteration_metrics
            .hosts_healthy
            .entry((is_healthy, is_assigned))
            .or_default() += 1;

        iteration_metrics.gpus_total += object_metrics.num_gpus;
        if object_metrics.is_usable_as_instance {
            iteration_metrics.hosts_usable += 1;
            iteration_metrics.gpus_usable += object_metrics.num_gpus;
        }

        // The object_metrics.is_host_bios_password_set bool cast as usize will translate to 0 or 1
        iteration_metrics.hosts_with_bios_password_set +=
            object_metrics.is_host_bios_password_set as usize;

        if let Some(tenant) = object_metrics.in_use_by_tenant.as_ref() {
            *iteration_metrics
                .gpus_in_use_by_tenant
                .entry(tenant.clone())
                .or_default() += object_metrics.num_gpus;
            *iteration_metrics
                .hosts_in_use_by_tenant
                .entry(tenant.clone())
                .or_default() += 1;
        }

        if let Some(machine_reboot_attempts_in_booting_with_discovery_image) =
            object_metrics.machine_reboot_attempts_in_booting_with_discovery_image
        {
            iteration_metrics
                .machine_reboot_attempts_in_booting_with_discovery_image
                .push(machine_reboot_attempts_in_booting_with_discovery_image);
        }

        if let Some(machine_reboot_attempts_in_failed_during_discovery) =
            object_metrics.machine_reboot_attempts_in_failed_during_discovery
        {
            iteration_metrics
                .machine_reboot_attempts_in_failed_during_discovery
                .push(machine_reboot_attempts_in_failed_during_discovery);
        }
        for ((probe_id, target), count) in &object_metrics.dpu_health_probe_alerts {
            *iteration_metrics
                .unhealthy_dpus_by_probe_id
                .entry((probe_id.to_string(), target.clone()))
                .or_default() += count;
        }

        for (probe_id, target) in &object_metrics.health_probe_alerts {
            *iteration_metrics
                .unhealthy_hosts_by_probe_id
                .entry((probe_id.to_string(), target.clone(), is_assigned))
                .or_default() += 1;
        }
        for classification in &object_metrics.health_alert_classifications {
            *iteration_metrics
                .unhealthy_hosts_by_classification_id
                .entry((classification.to_string(), is_assigned))
                .or_default() += 1;
        }
        *iteration_metrics
            .num_overrides
            .entry(("merge", is_assigned))
            .or_default() += object_metrics.num_merge_overrides;
        if object_metrics.replace_override_enabled {
            *iteration_metrics
                .num_overrides
                .entry(("replace", is_assigned))
                .or_default() += 1;
        }

        for (version, count) in object_metrics.agent_versions.iter() {
            *iteration_metrics
                .agent_versions
                .entry(version.clone())
                .or_default() += count;
        }

        for (version, count) in object_metrics.dpu_firmware_versions.iter() {
            *iteration_metrics
                .dpu_firmware_versions
                .entry(version.clone())
                .or_default() += count;
        }

        for (component, count) in object_metrics.machine_inventory_component_versions.iter() {
            *iteration_metrics
                .machine_inventory_component_versions
                .entry(component.clone())
                .or_default() += count;
        }

        for (machine_id, maybe_time) in object_metrics.client_certificate_expiry.iter() {
            if let Some(time) = maybe_time {
                iteration_metrics
                    .client_certificate_expiration_times
                    .entry(machine_id.clone())
                    .and_modify(|entry| *entry = *time)
                    .or_insert(*time);
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
            &self.hosts_usable_gauge,
            iteration_metrics.hosts_usable as u64,
            attributes,
        );
        observer.observe_u64(
            &self.hosts_with_bios_password_set,
            iteration_metrics.hosts_with_bios_password_set as u64,
            attributes,
        );
        observer.observe_u64(
            &self.gpus_usable_gauge,
            iteration_metrics.gpus_usable as u64,
            attributes,
        );
        observer.observe_u64(
            &self.gpus_total_gauge,
            iteration_metrics.gpus_total as u64,
            attributes,
        );

        let mut tenant_org_attr = attributes.to_vec();
        // Placeholder that is replaced in the loop in order not having to reallocate the Vec each time
        tenant_org_attr.push(KeyValue::new("tenant_org_id", "".to_string()));
        let mut total_in_use_gpus = 0;
        for (org, count) in &iteration_metrics.gpus_in_use_by_tenant {
            total_in_use_gpus += *count;
            tenant_org_attr.last_mut().unwrap().value = org.to_string().into();
            observer.observe_u64(
                &self.gpus_in_use_by_tenant_gauge,
                *count as u64,
                &tenant_org_attr,
            );
        }
        let mut total_in_use_hosts = 0;
        for (org, count) in &iteration_metrics.hosts_in_use_by_tenant {
            total_in_use_hosts += *count;
            tenant_org_attr.last_mut().unwrap().value = org.to_string().into();
            observer.observe_u64(
                &self.hosts_in_use_by_tenant_gauge,
                *count as u64,
                &tenant_org_attr,
            );
        }

        observer.observe_u64(
            &self.gpus_in_use_gauge,
            total_in_use_gpus as u64,
            attributes,
        );
        observer.observe_u64(
            &self.hosts_in_use_gauge,
            total_in_use_hosts as u64,
            attributes,
        );

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

        let mut health_status_attr = attributes.to_vec();
        health_status_attr.push(KeyValue::new("healthy", "".to_string()));
        health_status_attr.push(KeyValue::new("in_use", "".to_string()));
        let health_status_attr_len = health_status_attr.len();
        // The HashMap access is used here instead of iterating order to make sure that
        // all 4 combinations always emit metrics. No metric will be absent in case
        // no host falls into that category
        for healthy in [true, false] {
            for in_use in [true, false] {
                let count = iteration_metrics
                    .hosts_healthy
                    .get(&(healthy, IsInUseByTenant(in_use)))
                    .cloned()
                    .unwrap_or_default();
                health_status_attr[health_status_attr_len - 2].value = healthy.to_string().into();
                health_status_attr[health_status_attr_len - 1].value = in_use.to_string().into();
                observer.observe_u64(
                    &self.hosts_health_status_gauge,
                    count as u64,
                    &health_status_attr,
                );
            }
        }

        let mut failed_health_check_attr = attributes.to_vec();
        // Placeholder that is replaced in the loop in order not having to reallocate the Vec each time
        failed_health_check_attr.push(KeyValue::new("failure", "".to_string()));
        failed_health_check_attr.push(KeyValue::new("probe_id", "".to_string()));
        failed_health_check_attr.push(KeyValue::new("probe_target", "".to_string()));
        let failed_health_check_attr_len = failed_health_check_attr.len();
        for ((probe, target), count) in &iteration_metrics.unhealthy_dpus_by_probe_id {
            let failure = match target {
                None => probe.to_string(),
                Some(target) => format!("{probe} [Target: {target}]"),
            };
            failed_health_check_attr[failed_health_check_attr_len - 3].value =
                failure.clone().into();
            failed_health_check_attr[failed_health_check_attr_len - 2].value = probe.clone().into();
            failed_health_check_attr[failed_health_check_attr_len - 1].value =
                target.clone().unwrap_or_default().into();
            observer.observe_u64(
                &self.failed_dpu_healthchecks_gauge,
                *count as u64,
                &failed_health_check_attr,
            );
        }

        let mut probe_id_attr = attributes.to_vec();
        probe_id_attr.push(KeyValue::new("probe_id", "".to_string()));
        probe_id_attr.push(KeyValue::new("probe_target", "".to_string()));
        probe_id_attr.push(KeyValue::new("in_use", "".to_string()));
        let probe_id_attr_len = probe_id_attr.len();
        for ((probe, target, in_use), count) in &iteration_metrics.unhealthy_hosts_by_probe_id {
            probe_id_attr[probe_id_attr_len - 3].value = probe.clone().into();
            probe_id_attr[probe_id_attr_len - 2].value = target.clone().unwrap_or_default().into();
            probe_id_attr[probe_id_attr_len - 1].value = in_use.0.to_string().into();
            observer.observe_u64(
                &self.unhealthy_hosts_by_probe_id_gauge,
                *count as u64,
                &probe_id_attr,
            );
        }

        let mut probe_classification_attr = attributes.to_vec();
        probe_classification_attr.push(KeyValue::new("classification", "".to_string()));
        probe_classification_attr.push(KeyValue::new("in_use", "".to_string()));
        let probe_classification_attr_len = probe_classification_attr.len();
        for ((classification, in_use), count) in
            &iteration_metrics.unhealthy_hosts_by_classification_id
        {
            probe_classification_attr[probe_classification_attr_len - 2].value =
                classification.clone().into();
            probe_classification_attr[probe_classification_attr_len - 1].value =
                in_use.0.to_string().into();
            observer.observe_u64(
                &self.unhealthy_hosts_by_classification_gauge,
                *count as u64,
                &probe_classification_attr,
            );
        }

        let mut override_type_attr = attributes.to_vec();
        override_type_attr.push(KeyValue::new("override_type", "merge".to_string()));
        override_type_attr.push(KeyValue::new("in_use", "".to_string()));
        let override_type_attr_len = override_type_attr.len();
        // The HashMap access is used here instead of iterating order to make sure that
        // all 4 combinations always emit metrics. No metric will be absent in case
        // no host falls into that category
        for override_type in ["merge", "replace"] {
            for in_use in [true, false] {
                let count = iteration_metrics
                    .num_overrides
                    .get(&(override_type, IsInUseByTenant(in_use)))
                    .cloned()
                    .unwrap_or_default();
                override_type_attr[override_type_attr_len - 2].value =
                    override_type.to_string().into();
                override_type_attr[override_type_attr_len - 1].value = in_use.to_string().into();
                observer.observe_u64(
                    &self.hosts_health_overrides_gauge,
                    count as u64,
                    &override_type_attr,
                );
            }
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

        let mut component_version_attrs = attributes.to_vec();
        // Placeholders that are replaced in the loop in order not having to reallocate the Vec each time
        component_version_attrs.push(KeyValue::new("name", "".to_string()));
        component_version_attrs.push(KeyValue::new("version", "".to_string()));
        for (component, count) in &iteration_metrics.machine_inventory_component_versions {
            component_version_attrs[attributes.len()].value = component.name.clone().into();
            component_version_attrs[attributes.len() + 1].value = component.version.clone().into();
            observer.observe_u64(
                &self.machine_inventory_component_versions_gauge,
                *count as u64,
                &component_version_attrs,
            );
        }

        let mut dpu_machine_id_attributes = attributes.to_vec();
        // Placeholder that is replaced in the loop in order not having to reallocate the Vec each time
        dpu_machine_id_attributes.push(KeyValue::new("dpu_machine_id", "".to_string()));
        for (id, time) in &iteration_metrics.client_certificate_expiration_times {
            dpu_machine_id_attributes.last_mut().unwrap().value = id.clone().into();
            observer.observe_i64(
                &self.client_certificate_expiration_gauge,
                *time,
                dpu_machine_id_attributes.as_slice(),
            );
        }
    }

    fn emit_counters_and_histograms(&self, iteration_metrics: &Self::IterationMetrics) {
        iteration_metrics
            .machine_reboot_attempts_in_booting_with_discovery_image
            .iter()
            .for_each(|x| {
                self.machine_reboot_attempts_in_booting_with_discovery_image
                    .record(*x, &[]);
            });

        iteration_metrics
            .machine_reboot_attempts_in_failed_during_discovery
            .iter()
            .for_each(|x| {
                self.machine_reboot_attempts_in_failed_during_discovery
                    .record(*x, &[]);
            });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_machine_metrics() {
        let object_metrics = vec![
            MachineMetrics {
                agent_versions: HashMap::new(),
                num_gpus: 0,
                in_use_by_tenant: Some("a".parse().unwrap()),
                dpus_up: 1,
                dpus_healthy: 0,
                dpu_health_probe_alerts: HashMap::from_iter([(
                    ("FileExists".parse().unwrap(), Some("def.txt".to_string())),
                    1,
                )]),
                dpu_firmware_versions: HashMap::new(),
                machine_inventory_component_versions: HashMap::new(),
                client_certificate_expiry: HashMap::from_iter([("machine a".to_string(), Some(1))]),
                machine_reboot_attempts_in_booting_with_discovery_image: None,
                machine_reboot_attempts_in_failed_during_discovery: None,
                health_probe_alerts: HashSet::from_iter([(
                    "FileExists".parse().unwrap(),
                    Some("def.txt".to_string()),
                )]),
                health_alert_classifications: HashSet::new(),
                num_merge_overrides: 0,
                replace_override_enabled: false,
                is_usable_as_instance: true,
                is_host_bios_password_set: true,
            },
            MachineMetrics {
                num_gpus: 2,
                in_use_by_tenant: Some("a".parse().unwrap()),
                agent_versions: HashMap::from_iter([("v1".to_string(), 1)]),
                dpus_up: 1,
                dpus_healthy: 0,
                dpu_health_probe_alerts: HashMap::from_iter([
                    (("bgp".parse().unwrap(), None), 1),
                    (("ntp".parse().unwrap(), None), 1),
                    (
                        ("FileExists".parse().unwrap(), Some("def.txt".to_string())),
                        1,
                    ),
                    (
                        ("FileExists".parse().unwrap(), Some("abc.txt".to_string())),
                        1,
                    ),
                ]),
                dpu_firmware_versions: HashMap::new(),
                machine_inventory_component_versions: HashMap::from_iter([(
                    MachineInventorySoftwareComponent {
                        name: "doca_hbn".to_string(),
                        version: "2.0.0-doca2.5.0".to_string(),
                        url: "nvcr.io/nvidia/doca".to_string(),
                    },
                    1,
                )]),
                client_certificate_expiry: HashMap::from_iter([("machine a".to_string(), Some(2))]),
                machine_reboot_attempts_in_booting_with_discovery_image: Some(0),
                machine_reboot_attempts_in_failed_during_discovery: Some(0),
                health_probe_alerts: HashSet::from_iter([
                    ("bgp".parse().unwrap(), None),
                    ("ntp".parse().unwrap(), None),
                    ("FileExists".parse().unwrap(), Some("def.txt".to_string())),
                    ("FileExists".parse().unwrap(), Some("abc.txt".to_string())),
                ]),
                health_alert_classifications: [
                    "Class1".parse().unwrap(),
                    "Class3".parse().unwrap(),
                ]
                .into_iter()
                .collect(),
                num_merge_overrides: 0,
                replace_override_enabled: false,
                is_usable_as_instance: true,
                is_host_bios_password_set: true,
            },
            MachineMetrics {
                num_gpus: 3,
                in_use_by_tenant: None,
                agent_versions: HashMap::from_iter([("v3".to_string(), 1)]),
                dpus_up: 0,
                dpus_healthy: 1,
                dpu_health_probe_alerts: HashMap::from_iter([]),
                dpu_firmware_versions: HashMap::from_iter([("v4".to_string(), 1)]),
                machine_inventory_component_versions: HashMap::from_iter([(
                    MachineInventorySoftwareComponent {
                        name: "doca_telemetry".to_string(),
                        version: "1.15.5-doca2.5.0".to_string(),
                        url: "nvcr.io/nvidia/doca".to_string(),
                    },
                    1,
                )]),
                client_certificate_expiry: HashMap::from_iter([("machine b".to_string(), Some(3))]),
                machine_reboot_attempts_in_booting_with_discovery_image: Some(1),
                machine_reboot_attempts_in_failed_during_discovery: Some(1),
                health_probe_alerts: HashSet::new(),
                health_alert_classifications: HashSet::new(),
                num_merge_overrides: 1,
                replace_override_enabled: true,
                is_usable_as_instance: false,
                is_host_bios_password_set: true,
            },
            MachineMetrics {
                num_gpus: 1,
                in_use_by_tenant: Some("a".parse().unwrap()),
                agent_versions: HashMap::from_iter([("v3".to_string(), 1)]),
                dpus_up: 1,
                dpus_healthy: 1,
                dpu_health_probe_alerts: HashMap::from_iter([]),
                dpu_firmware_versions: HashMap::from_iter([("v2".to_string(), 1)]),
                machine_inventory_component_versions: HashMap::from_iter([
                    (
                        MachineInventorySoftwareComponent {
                            name: "doca_hbn".to_string(),
                            version: "2.0.0-doca2.5.0".to_string(),
                            url: "nvcr.io/nvidia/doca".to_string(),
                        },
                        1,
                    ),
                    (
                        MachineInventorySoftwareComponent {
                            name: "doca_telemetry".to_string(),
                            version: "1.15.5-doca2.5.0".to_string(),
                            url: "nvcr.io/nvidia/doca".to_string(),
                        },
                        1,
                    ),
                ]),
                client_certificate_expiry: HashMap::from_iter([("machine b".to_string(), None)]),
                machine_reboot_attempts_in_booting_with_discovery_image: Some(2),
                machine_reboot_attempts_in_failed_during_discovery: Some(2),
                health_probe_alerts: HashSet::new(),
                health_alert_classifications: HashSet::new(),
                num_merge_overrides: 0,
                replace_override_enabled: false,
                is_usable_as_instance: true,
                is_host_bios_password_set: true,
            },
            MachineMetrics {
                num_gpus: 2,
                in_use_by_tenant: None,
                agent_versions: HashMap::new(),
                dpus_up: 1,
                dpus_healthy: 0,
                dpu_health_probe_alerts: [
                    (("BgpStats".parse().unwrap(), None), 1),
                    (
                        (
                            "HeartbeatTimeout".parse().unwrap(),
                            Some("forge-dpu-agent".to_string()),
                        ),
                        1,
                    ),
                ]
                .into_iter()
                .collect(),
                dpu_firmware_versions: HashMap::from_iter([("v4".to_string(), 1)]),
                machine_inventory_component_versions: HashMap::from_iter([
                    (
                        MachineInventorySoftwareComponent {
                            name: "doca_hbn".to_string(),
                            version: "3.0.0-doca3.5.0".to_string(),
                            url: "nvcr.io/nvidia/doca".to_string(),
                        },
                        1,
                    ),
                    (
                        MachineInventorySoftwareComponent {
                            name: "doca_telemetry".to_string(),
                            version: "3.15.5-doca3.5.0".to_string(),
                            url: "nvcr.io/nvidia/doca".to_string(),
                        },
                        1,
                    ),
                ]),
                client_certificate_expiry: HashMap::default(),
                machine_reboot_attempts_in_booting_with_discovery_image: None,
                machine_reboot_attempts_in_failed_during_discovery: None,
                health_probe_alerts: [
                    ("BgpStats".parse().unwrap(), None),
                    (
                        "HeartbeatTimeout".parse().unwrap(),
                        Some("forge-dpu-agent".to_string()),
                    ),
                ]
                .into_iter()
                .collect(),
                health_alert_classifications: [
                    "Class1".parse().unwrap(),
                    "Class2".parse().unwrap(),
                ]
                .into_iter()
                .collect(),
                num_merge_overrides: 1,
                replace_override_enabled: false,
                is_usable_as_instance: false,
                is_host_bios_password_set: true,
            },
            MachineMetrics {
                num_gpus: 3,
                in_use_by_tenant: None,
                agent_versions: HashMap::new(),
                dpus_up: 2,
                dpus_healthy: 0,
                dpu_health_probe_alerts: HashMap::from_iter([(
                    ("BgpStats".parse().unwrap(), None),
                    2,
                )]),
                dpu_firmware_versions: HashMap::from_iter([
                    ("v4".to_string(), 1),
                    ("v5".to_string(), 1),
                ]),
                machine_inventory_component_versions: HashMap::from_iter([
                    (
                        MachineInventorySoftwareComponent {
                            name: "doca_hbn".to_string(),
                            version: "3.0.0-doca3.6.0".to_string(),
                            url: "nvcr.io/nvidia/doca".to_string(),
                        },
                        2,
                    ),
                    (
                        MachineInventorySoftwareComponent {
                            name: "doca_telemetry".to_string(),
                            version: "3.15.5-doca3.6.0".to_string(),
                            url: "nvcr.io/nvidia/doca".to_string(),
                        },
                        2,
                    ),
                ]),
                client_certificate_expiry: HashMap::default(),
                machine_reboot_attempts_in_booting_with_discovery_image: None,
                machine_reboot_attempts_in_failed_during_discovery: None,
                health_probe_alerts: [("BgpStats".parse().unwrap(), None)].into_iter().collect(),
                health_alert_classifications: [
                    "Class1".parse().unwrap(),
                    "Class2".parse().unwrap(),
                ]
                .into_iter()
                .collect(),
                num_merge_overrides: 0,
                replace_override_enabled: true,
                is_usable_as_instance: false,
                is_host_bios_password_set: false,
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
        assert_eq!(
            *iteration_metrics
                .gpus_in_use_by_tenant
                .get(&"a".parse().unwrap())
                .unwrap(),
            3
        );
        assert_eq!(
            *iteration_metrics
                .hosts_in_use_by_tenant
                .get(&"a".parse().unwrap())
                .unwrap(),
            3
        );
        assert_eq!(iteration_metrics.hosts_usable, 3);
        assert_eq!(iteration_metrics.hosts_with_bios_password_set, 5);
        assert_eq!(iteration_metrics.gpus_usable, 3);
        assert_eq!(iteration_metrics.gpus_total, 11);
        assert_eq!(iteration_metrics.dpus_up, 6);
        assert_eq!(iteration_metrics.dpus_healthy, 2);
        assert_eq!(
            &iteration_metrics.machine_reboot_attempts_in_booting_with_discovery_image,
            &[0, 1, 2]
        );
        assert_eq!(
            &iteration_metrics.machine_reboot_attempts_in_failed_during_discovery,
            &[0, 1, 2]
        );
        assert_eq!(
            iteration_metrics.unhealthy_dpus_by_probe_id,
            HashMap::from_iter([
                (("BgpStats".parse().unwrap(), None), 3),
                (("bgp".to_string(), None), 1),
                (("ntp".to_string(), None), 1),
                (("FileExists".to_string(), Some("abc.txt".to_string())), 1),
                (("FileExists".to_string(), Some("def.txt".to_string())), 2),
                (
                    (
                        "HeartbeatTimeout".parse().unwrap(),
                        Some("forge-dpu-agent".to_string()),
                    ),
                    1,
                ),
            ])
        );
        assert_eq!(
            iteration_metrics.dpu_firmware_versions,
            HashMap::from_iter([
                ("v2".to_string(), 1),
                ("v4".to_string(), 3),
                ("v5".to_string(), 1)
            ])
        );

        assert_eq!(iteration_metrics.hosts_total, 6);
        assert_eq!(
            iteration_metrics.hosts_healthy,
            HashMap::from_iter([
                ((true, IsInUseByTenant(true)), 1),
                ((false, IsInUseByTenant(true)), 2),
                ((true, IsInUseByTenant(false)), 1),
                ((false, IsInUseByTenant(false)), 2),
            ])
        );
        assert_eq!(
            iteration_metrics.unhealthy_hosts_by_probe_id,
            HashMap::from_iter([
                (
                    ("BgpStats".parse().unwrap(), None, IsInUseByTenant(false)),
                    2
                ),
                (("bgp".to_string(), None, IsInUseByTenant(true)), 1),
                (("ntp".to_string(), None, IsInUseByTenant(true)), 1),
                (
                    (
                        "FileExists".to_string(),
                        Some("abc.txt".to_string()),
                        IsInUseByTenant(true)
                    ),
                    1
                ),
                (
                    (
                        "FileExists".to_string(),
                        Some("def.txt".to_string()),
                        IsInUseByTenant(true)
                    ),
                    2
                ),
                (
                    (
                        "HeartbeatTimeout".parse().unwrap(),
                        Some("forge-dpu-agent".to_string()),
                        IsInUseByTenant(false)
                    ),
                    1,
                ),
            ])
        );
        assert_eq!(
            iteration_metrics.unhealthy_hosts_by_classification_id,
            HashMap::from_iter([
                (("Class1".parse().unwrap(), IsInUseByTenant(true)), 1),
                (("Class1".parse().unwrap(), IsInUseByTenant(false)), 2),
                (("Class2".parse().unwrap(), IsInUseByTenant(false)), 2),
                (("Class3".parse().unwrap(), IsInUseByTenant(true)), 1),
            ])
        );
        assert_eq!(
            iteration_metrics.num_overrides,
            HashMap::from_iter([
                (("merge", IsInUseByTenant(true)), 0),
                (("merge", IsInUseByTenant(false)), 2),
                (("replace", IsInUseByTenant(false)), 2),
            ])
        );

        assert_eq!(
            iteration_metrics.machine_inventory_component_versions,
            HashMap::from_iter([
                (
                    MachineInventorySoftwareComponent {
                        name: "doca_hbn".to_string(),
                        version: "2.0.0-doca2.5.0".to_string(),
                        url: "nvcr.io/nvidia/doca".to_string(),
                    },
                    2
                ),
                (
                    MachineInventorySoftwareComponent {
                        name: "doca_hbn".to_string(),
                        version: "3.0.0-doca3.5.0".to_string(),
                        url: "nvcr.io/nvidia/doca".to_string(),
                    },
                    1
                ),
                (
                    MachineInventorySoftwareComponent {
                        name: "doca_hbn".to_string(),
                        version: "3.0.0-doca3.6.0".to_string(),
                        url: "nvcr.io/nvidia/doca".to_string(),
                    },
                    2
                ),
                (
                    MachineInventorySoftwareComponent {
                        name: "doca_telemetry".to_string(),
                        version: "1.15.5-doca2.5.0".to_string(),
                        url: "nvcr.io/nvidia/doca".to_string(),
                    },
                    2
                ),
                (
                    MachineInventorySoftwareComponent {
                        name: "doca_telemetry".to_string(),
                        version: "3.15.5-doca3.5.0".to_string(),
                        url: "nvcr.io/nvidia/doca".to_string(),
                    },
                    1
                ),
                (
                    MachineInventorySoftwareComponent {
                        name: "doca_telemetry".to_string(),
                        version: "3.15.5-doca3.6.0".to_string(),
                        url: "nvcr.io/nvidia/doca".to_string(),
                    },
                    2
                )
            ])
        );

        assert_eq!(
            iteration_metrics.client_certificate_expiration_times,
            HashMap::from_iter([("machine a".to_string(), 2), ("machine b".to_string(), 3)])
        );
    }
}
