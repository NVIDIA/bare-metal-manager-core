#include <hooks/hooks.h>
#include <dhcp/pkt4.h>
#include <log/logger.h>
#include <log/macros.h>
#include <dhcpsrv/lease.h>
#include <asiolink/io_address.h>
#include <string>

#include "carbide_logger.h"
#include "carbide_rust.h"

using namespace isc::hooks;
using namespace isc::dhcp;
using namespace std;

isc::log::Logger logger("kea-carbide-shim");

extern "C" {
	int pkt4_receive(CalloutHandle &handle) {
		Pkt4Ptr query4_ptr;

		handle.getArgument("query4", query4_ptr);
		auto mac = query4_ptr->getHWAddr()->hwaddr_;

		LOG_INFO(logger, isc::log::LOG_CARBIDE_PKT4_RECEIVE).arg(query4_ptr->getLabel());

		MachineDiscovery *discovery = discover_allocate();
		discover_set_relay(discovery, query4_ptr->getGiaddr().toUint32());
		discover_set_client_macaddress(discovery, mac.data(), mac.size());

		handle.setContext("machine", discovery);

		return 0;
	}

	int subnet4_select(CalloutHandle &handle) {
		handle.setStatus(CalloutHandle::NEXT_STEP_SKIP);
		return 0;
	}

	int lease4_select(CalloutHandle &handle) {
		Lease4Ptr lease4_ptr;

		handle.getArgument("lease4", lease4_ptr);

		LOG_INFO(logger, isc::log::LOG_CARBIDE_PKT4_RECEIVE).arg(lease4_ptr->toText());

		//handle.setStatus(CalloutHandle::NEXT_STEP_SKIP);
		return 0;
	}

	int pkt4_send(CalloutHandle &handle) {
		Pkt4Ptr query4_ptr, response4_ptr;

		handle.getArgument("query4", query4_ptr);
		handle.getArgument("response4", response4_ptr);

		MachineDiscovery *discovery;
		handle.getContext("machine", discovery);
		auto addr = discover_invoke(discovery);

		response4_ptr->setYiaddr(isc::asiolink::IOAddress(addr));

		discover_free(discovery);

		LOG_INFO(logger, isc::log::LOG_CARBIDE_PKT4_SEND).arg(response4_ptr->toText());
		return 0;
	}
	int shim_version() {
		return KEA_HOOKS_VERSION;
	}

	int shim_load(LibraryHandle &handle) {
		LOG_INFO(logger, isc::log::LOG_CARBIDE_INITIALIZATION);

		handle.registerCallout("pkt4_receive", pkt4_receive);
//		handle.registerCallout("lease4_select", lease4_select);
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
