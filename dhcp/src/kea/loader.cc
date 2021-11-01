#include <hooks/hooks.h>
#include <log/logger.h>
#include <log/macros.h>

#include "carbide_logger.h"
#include "callouts.h"
#include "carbide_rust.h"

isc::log::Logger loader_logger("kea-shim-loader");

using namespace isc::hooks;

extern "C" {
	int shim_version() {
		return KEA_HOOKS_VERSION;
	}

	int shim_load(LibraryHandle &handle) {
		LOG_INFO(loader_logger, isc::log::LOG_CARBIDE_INITIALIZATION);

		auto api_endpoint = handle.getParameter("carbide_api_url");
		if (!api_endpoint) {
			carbide_set_config_api(api_endpoint.get()->str().c_str());
		}

		handle.registerCallout("pkt4_receive", pkt4_receive);
		handle.registerCallout("lease4_select", lease4_select);
//		handle.registerCallout("subnet4_select", subnet4_select);
		handle.registerCallout("pkt4_send", pkt4_send);

		return 0;
	}

	int shim_unload() {
		return 0;
	}

	int shim_multi_threaded_compatible() {
		return 0;
	}
}
