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

#include <hooks/hooks.h>
#include <log/logger.h>
#include <log/macros.h>
#include <asiolink/io_address.h>
#include <asiolink/io_error.h>

#include "carbide_logger.h"
#include "callouts.h"
#include "carbide_rust.h"

isc::log::Logger loader_logger("kea-shim-loader");

using namespace isc::hooks;
using namespace isc::data;

extern "C" {
	int shim_version() {
		return KEA_HOOKS_VERSION;
	}

	int shim_load(void *handle_ptr) {
		if (!handle_ptr) {
			LOG_INFO(loader_logger, isc::log::LOG_CARBIDE_INVALID_HANDLE);
			return 1;
		}

		LibraryHandle *handle = static_cast<LibraryHandle *>(handle_ptr);

		LOG_INFO(loader_logger, isc::log::LOG_CARBIDE_INITIALIZATION);

		ConstElementPtr next_server  = handle->getParameter("carbide-provisioning-server-ipv4");
		if (next_server) {
			if(next_server->getType() != Element::string) {
				// TODO(ajf): handle invalid data here
				return (1);
			} else {
				try {
					auto nextserver_ipv4 = isc::asiolink::IOAddress(next_server->stringValue());

					if (nextserver_ipv4.isV4()) {
						carbide_set_config_next_server_ipv4(nextserver_ipv4.toUint32());
					} else {
						LOG_ERROR(loader_logger, isc::log::LOG_CARBIDE_INVALID_NEXTSERVER_IPV4).arg("");
						return 1;
					}

				} catch(const isc::asiolink::IOError &e) {
					LOG_ERROR(loader_logger, isc::log::LOG_CARBIDE_INVALID_NEXTSERVER_IPV4).arg(e.getMessage());
					return 1;
				}
			}
		}

		// TODO(ajf): add config options for mutual TLS authentication to the API

		ConstElementPtr api_endpoint = handle->getParameter("carbide-api-url");
		if (api_endpoint) {
			if(api_endpoint->getType() != Element::string) {
				// TODO: handle invalid data type for carbide-api-url
				return (1);
			} else {
				// TODO: proper logging
				carbide_set_config_api(api_endpoint->stringValue().c_str());
			}
		}

        ConstElementPtr ntpservers = handle->getParameter("carbide-ntpserver");
        if (ntpservers) {
            if(ntpservers->getType() != Element::string) {
                // TODO: handle invalid data type for ntpserver
                return (1);
            } else {
                // TODO: proper logging
                carbide_set_config_ntp(ntpservers->stringValue().c_str());
            }
        }

        ConstElementPtr nameservers = handle->getParameter("carbide-nameservers");
        if (nameservers) {
            if(nameservers->getType() != Element::string) {
                // TODO: handle invalid data type for nameservers
                return (1);
            } else {
                // TODO: proper logging
                carbide_set_config_name_servers(nameservers->stringValue().c_str());
            }
        }

        ConstElementPtr mqtt_server = handle->getParameter("carbide-mqtt-server");
        if (mqtt_server) {
            if(mqtt_server->getType() != Element::string) {
                // TODO: handle invalid data type for mqtt_server.
                return (1);
            } else {
                // TODO: proper logging
                carbide_set_config_mqtt_server(mqtt_server->stringValue().c_str());
            }
        }

        ConstElementPtr metrics_endpoint = handle->getParameter("carbide-metrics-endpoint");
        if (metrics_endpoint) {
            if(metrics_endpoint->getType() != Element::string) {
                // TODO: handle invalid data type for carbide-metrics-endpoint
                return (1);
            } else {
                // TODO: proper logging
                carbide_set_config_metrics_endpoint(metrics_endpoint->stringValue().c_str());
            }
        }

		handle->registerCallout("pkt4_receive", pkt4_receive);
		// lease4_select fires between pkt4_receive and pkt4_send, and is the
		// only place where we can override the IP that Kea will persist into
		// its lease memfile. The pkt4_send hook still runs and still sets
		// yiaddr/options on the outgoing packet, but lease4_select is what
		// keeps the Kea memfile aligned with the NICo database regardless of
		// what address the client requested (option 50 / ciaddr), because
        // just because the client requested it doesn't mean that's what
        // they're going to get, and that's ok.
		handle->registerCallout("lease4_select", lease4_select);
		// lease4_renew is the renewal-time side of lease4_select.
		// Together they keep the Kea memfile aligned with the NICo
		// database through both initial allocation and renewal.
		handle->registerCallout("lease4_renew", lease4_renew);
		handle->registerCallout("pkt4_send", pkt4_send);
		handle->registerCallout("lease4_expire", lease4_expire);
		handle->registerCallout("lease6_expire", lease6_expire);

		return 0;
	}

	int shim_unload() {
		return 0;
	}

	int shim_multi_threading_compatible() {
		return (1);
	}
}
