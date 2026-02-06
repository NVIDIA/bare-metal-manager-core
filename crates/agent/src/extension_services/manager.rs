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
use std::collections::HashMap;

use ::rpc::forge::{self as rpc, DpuExtensionServiceType};

use super::k8s_pod_handler::KubernetesPodServicesHandler;
use super::service_handler::{ExtensionServiceHandler, ServiceConfig};

/// Manager for all extension services on the DPU
///
/// This manager is responsible for updating the desired services and getting the statuses of the services.
pub struct ExtensionServiceManager {
    service_handlers: HashMap<DpuExtensionServiceType, Box<dyn ExtensionServiceHandler>>,
}

impl Default for ExtensionServiceManager {
    fn default() -> Self {
        let mut service_handlers = HashMap::new();
        service_handlers.insert(
            DpuExtensionServiceType::KubernetesPod,
            Box::new(KubernetesPodServicesHandler::default()) as Box<dyn ExtensionServiceHandler>,
        );

        Self { service_handlers }
    }
}

impl ExtensionServiceManager {
    fn get_handler_mut(
        &mut self,
        t: &DpuExtensionServiceType,
    ) -> eyre::Result<&mut dyn ExtensionServiceHandler> {
        self.service_handlers
            .get_mut(t)
            .map(|handler| handler.as_mut() as &mut dyn ExtensionServiceHandler)
            .ok_or_else(|| eyre::eyre!("No handler for {:?}", t))
    }

    pub async fn update_desired_services(
        &mut self,
        configs: Vec<rpc::ManagedHostDpuExtensionServiceConfig>,
    ) -> eyre::Result<()> {
        let mut services_by_type: HashMap<DpuExtensionServiceType, Vec<ServiceConfig>> =
            HashMap::new();

        for config in configs {
            let service = ServiceConfig::try_from(config).map_err(|e| {
                eyre::eyre!(
                    "Failed to convert ManagedHostDpuExtensionServiceConfig to ServiceConfig: {}",
                    e
                )
            })?;
            services_by_type
                .entry(service.service_type)
                .or_default()
                .push(service);
        }

        for (service_type, handler) in self.service_handlers.iter_mut() {
            // Note if no service configs are provided for a given service type, the handler still needs to be called
            // to ensure all services are cleaned up.
            let desired_services = services_by_type.remove(service_type).unwrap_or_default();
            handler.update_active_services(&desired_services).await?;
        }

        Ok(())
    }

    pub async fn get_service_statuses(
        &mut self,
        configs: Vec<rpc::ManagedHostDpuExtensionServiceConfig>,
    ) -> eyre::Result<Vec<rpc::DpuExtensionServiceStatusObservation>> {
        let service_configs: Vec<ServiceConfig> = configs
            .into_iter()
            .map(|c| {
                ServiceConfig::try_from(c).map_err(|e| eyre::eyre!(
                "Failed to convert ManagedHostDpuExtensionServiceConfig to ServiceConfig: {e}"
            ))
            })
            .collect::<Result<_, _>>()?;

        let mut service_statuses = Vec::with_capacity(service_configs.len());
        for service in service_configs {
            let handler = self.get_handler_mut(&service.service_type).unwrap();
            let status = handler.get_service_status(&service).await?;
            service_statuses.push(status);
        }

        Ok(service_statuses)
    }
}
