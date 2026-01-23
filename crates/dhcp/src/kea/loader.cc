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
		handle->registerCallout("pkt4_send", pkt4_send);

		return 0;
	}

	int shim_unload() {
		return 0;
	}

	int shim_multi_threading_compatible() {
		return (1);
	}
}
