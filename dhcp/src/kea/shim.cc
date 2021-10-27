#include <hooks/hooks.h>
#include <dhcp/pkt4.h>
#include <log/logger.h>
#include <log/macros.h>

#include <string>

#include "carbide_logger.h"

using namespace isc::hooks;
using namespace isc::dhcp;
using namespace std;

isc::log::Logger logger("kea-carbide-shim");

extern "C" {
	int pkt4_receive(CalloutHandle &handle) {
		Pkt4Ptr query4_ptr;

		handle.getArgument("query4", query4_ptr);
		LOG_INFO(logger, isc::log::LOG_CARBIDE_PKT4_RECEIVE).arg(query4_ptr->getLabel());
		return 0;
	}

	int pkt4_send(CalloutHandle &handle) {
		Pkt4Ptr query4_ptr;

		handle.getArgument("query4", query4_ptr);

		LOG_INFO(logger, isc::log::LOG_CARBIDE_PKT4_SEND).arg(query4_ptr->getLabel());
		try {

		} catch (const NoSuchCalloutContext &) {
		}
		return 0;
	}
	int shim_version() {
		return KEA_HOOKS_VERSION;
	}

	int shim_load(LibraryHandle &handle) {
		LOG_INFO(logger, isc::log::LOG_CARBIDE_INITIALIZATION);

		handle.registerCallout("pkt4_receive", pkt4_receive);

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
