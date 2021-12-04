#include <hooks/hooks.h>
#include <dhcp/pkt4.h>
#include <log/logger.h>
#include <log/macros.h>
#include <dhcpsrv/lease.h>
#include <asiolink/io_address.h>
#include <string>

#include <dhcp/option_definition.h>
#include <dhcp/option4_addrlst.h>
#include <dhcp/option_string.h>

#include <dhcp/option_int.h>

#include "carbide_logger.h"
#include "carbide_rust.h"

using namespace isc::hooks;
using namespace isc::dhcp;
using namespace std;

isc::log::Logger logger("kea-carbide-callouts");

extern "C" {
	int pkt4_receive(CalloutHandle &handle) {
		Pkt4Ptr query4_ptr;

		handle.getArgument("query4", query4_ptr);
		auto mac = query4_ptr->getHWAddr()->hwaddr_;

		if (!query4_ptr->isRelayed()) {
			LOG_ERROR(logger, isc::log::LOG_CARBIDE_PKT4_RECEIVE).arg("Received a non-relayed packet, dropping it");
			handle.setStatus(CalloutHandle::NEXT_STEP_DROP);
		}

		LOG_ERROR(logger, isc::log::LOG_CARBIDE_PKT4_RECEIVE).arg(query4_ptr->getOption(DHO_SYSTEM));
		LOG_INFO(logger, isc::log::LOG_CARBIDE_GENERIC).arg(query4_ptr->getLabel());

		DiscoveryBuilderFFI *discovery = discovery_allocate();

		uint16_t client_system = 0;

		discovery_set_relay(discovery, query4_ptr->getGiaddr().toUint32());
		discovery_set_mac_address(discovery, mac.data(), mac.size());
		discovery_set_client_system(discovery, client_system);

		Machine *machine = discovery_fetch_machine(discovery);

		if (!machine) {
			LOG_ERROR(logger, isc::log::LOG_CARBIDE_PKT4_RECEIVE).arg("error in discovery_fetch_machine");
			handle.setStatus(CalloutHandle::NEXT_STEP_DROP);
			return 1;
		} else {
			handle.setContext("machine", machine);
			return 0;
		}
	}

	int subnet4_select(CalloutHandle &handle) {
		handle.setStatus(CalloutHandle::NEXT_STEP_SKIP);
		return 0;
	}

	int lease4_select(CalloutHandle &handle) {
		Lease4Ptr lease4_ptr;
		handle.getArgument("lease4", lease4_ptr);

		LOG_INFO(logger, isc::log::LOG_CARBIDE_LEASE4_SELECT).arg(lease4_ptr->toText());
		return 0;
	}

	int pkt4_send(CalloutHandle &handle) {
		Pkt4Ptr query4_ptr, response4_ptr;

		handle.getArgument("query4", query4_ptr);
		handle.getArgument("response4", response4_ptr);

		Machine *machine;
		handle.getContext("machine", machine);

		response4_ptr->setYiaddr(isc::asiolink::IOAddress(machine_get_interface_address(machine)));

		OptionPtr option_routers = response4_ptr->getOption(DHO_ROUTERS);
		if(option_routers) {
			response4_ptr->delOption(DHO_ROUTERS);
		}
		response4_ptr->addOption(OptionPtr(new Option4AddrLst(DHO_ROUTERS, isc::asiolink::IOAddress(machine_get_interface_router(machine)))));

		// Set subnet-mask
		OptionPtr option_mtu = response4_ptr->getOption(DHO_INTERFACE_MTU);
		if (option_mtu) {
			response4_ptr->delOption(DHO_INTERFACE_MTU);
		}
		option_mtu.reset(new OptionInt<uint16_t>(Option::V4, DHO_INTERFACE_MTU, 1500));
		response4_ptr->addOption(option_mtu);

		// Set subnet-mask
		OptionPtr option_subnet = response4_ptr->getOption(DHO_SUBNET_MASK);
		if (option_subnet) {
			response4_ptr->delOption(DHO_SUBNET_MASK);
		}
		option_subnet.reset(new OptionInt<uint32_t>(Option::V4, DHO_SUBNET_MASK, machine_get_interface_subnet_mask(machine)));
		response4_ptr->addOption(option_subnet);

		OptionPtr option_broadcast = response4_ptr->getOption(DHO_BROADCAST_ADDRESS);
		if (option_broadcast) {
			response4_ptr->delOption(DHO_BROADCAST_ADDRESS);
		}
		option_broadcast.reset(new OptionInt<uint32_t>(Option::V4, DHO_BROADCAST_ADDRESS, machine_get_broadcast_address(machine)));
		response4_ptr->addOption(option_broadcast);

		// Set hostname
		OptionPtr option_hostname = response4_ptr->getOption(DHO_HOST_NAME);
		if (option_hostname) {
			response4_ptr->delOption(DHO_HOST_NAME);
		}
		char* hostname = machine_get_interface_hostname(machine);
		option_hostname.reset(new OptionString(Option::V4, DHO_HOST_NAME, hostname));
		response4_ptr->addOption(option_hostname);

		// Set next-server
		response4_ptr->setSiaddr(isc::asiolink::IOAddress(machine_get_next_server(machine)));

		// Set filename
		OptionPtr option_filename = response4_ptr->getOption(DHO_BOOT_FILE_NAME);
		if (option_filename) {
			response4_ptr->delOption(DHO_BOOT_FILE_NAME);
		}
		char *filename = machine_get_filename(machine);
		option_filename.reset(new OptionString(Option::V4, DHO_BOOT_FILE_NAME, filename));
		response4_ptr->addOption(option_filename);

		LOG_INFO(logger, isc::log::LOG_CARBIDE_PKT4_SEND).arg(response4_ptr->toText());

		// Tell rust code to free the memory, since we can't free memory that isn't ours
		machine_free(machine);
		machine_free_fqdn(hostname);
//		machine_free_filename(filename);

		return 0;
	}
}
