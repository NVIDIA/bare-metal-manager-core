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

		/*
		 * We only work on relayed packets (i.e. we never provide DHCP
		 * for the network in which this daemon is running.
		 */
		if (!query4_ptr->isRelayed()) {
			LOG_ERROR(logger, isc::log::LOG_CARBIDE_PKT4_RECEIVE).arg("Received a non-relayed packet, dropping it");
			handle.setStatus(CalloutHandle::NEXT_STEP_DROP);
		}

		// Initialize a discovery object
		DiscoveryBuilderFFI *discovery = discovery_allocate();

		/*
		 * Extract the vendor class, which has some interesting bits
		 * like HTTPClient / PXEClient
		 *
		 * TODO(ajf): find out where this option format is documented
		 * at all so maybe we can build a type around it.
		 */
		boost::shared_ptr<OptionString> vendor_class =
			boost::dynamic_pointer_cast<OptionString>(query4_ptr->getOption(DHO_VENDOR_CLASS_IDENTIFIER));
		if (vendor_class) {
			discovery_set_vendor_class(discovery, vendor_class->getValue().c_str());
		} else {
			LOG_ERROR(logger, isc::log::LOG_CARBIDE_GENERIC).arg("Missing DHO_VENDOR_CLASS_IDENTIFIER (option 60) in packet");
		}

		/*
		 * Extract the "client architecture" - DHCP option 93 from the
		 * packet, which will tell us what the booting architecture is
		 * in order to figure out which filname to give back
		 */
		boost::shared_ptr<OptionUint16> client_system = 
			boost::static_pointer_cast<OptionUint16>(query4_ptr->getOption(DHO_SYSTEM));
		if (client_system) {
			LOG_INFO(logger, isc::log::LOG_CARBIDE_GENERIC).arg(client_system->toText());
			discovery_set_client_system(discovery, client_system->getValue());
		} else {
			LOG_ERROR(logger, isc::log::LOG_CARBIDE_GENERIC).arg("Missing DHO_SYSTEM (option 93) in packet");
		}

		/*
		 * There's helper functions for the basic stuff like mac
		 * address and relay address
		 */
		discovery_set_relay(discovery, query4_ptr->getGiaddr().toUint32());

		auto mac = query4_ptr->getHWAddr()->hwaddr_;
		discovery_set_mac_address(discovery, mac.data(), mac.size());

		/*
		 * We've been building up a object for the dhcp client options
		 * we care about, so now we call the function to turn that
		 * object into a dhcp machine object from the carbide API.  The
		 * discovery object is unusable after this point.  The rust
		 * code will free the discovery pointer during this call.
		 */
		Machine *machine = discovery_fetch_machine(discovery);

		/*
		 * If there was an error fetching the machine (i.e. returned
		 * null), then we just drop the request and hopefully the cause
		 * of the error got logged before we got here.
		 */
		if (!machine) {
			LOG_ERROR(logger, isc::log::LOG_CARBIDE_PKT4_RECEIVE).arg("error in discovery_fetch_machine");
			handle.setStatus(CalloutHandle::NEXT_STEP_DROP);
			return 1;
		} else {
			// On success, we set the pointer to the machine in the request context to be retrieved later	
			handle.setContext("machine", machine);
			return 0;
		}
	}

	int pkt4_send(CalloutHandle &handle) {
		Pkt4Ptr query4_ptr, response4_ptr;

		handle.getArgument("query4", query4_ptr);
		handle.getArgument("response4", response4_ptr);

		/*
		 * Load the machine from the context.  It should have been set in pkt4_receive.
		 */
		Machine *machine;
		handle.getContext("machine", machine);
		if (!machine) {
			LOG_ERROR(logger, isc::log::LOG_CARBIDE_PKT4_SEND).arg("Missing machine object from handle context");
			handle.setStatus(CalloutHandle::NEXT_STEP_DROP);
			return 1;
		}

		/*
		 * Fetch the interface address for this machine (i.e. this is the address assigned to the DHCP-ing host.
		 */
		response4_ptr->setYiaddr(isc::asiolink::IOAddress(machine_get_interface_address(machine)));

		// Router Address
		OptionPtr option_routers = response4_ptr->getOption(DHO_ROUTERS);
		if(option_routers) {
			response4_ptr->delOption(DHO_ROUTERS);
		}
		response4_ptr->addOption(OptionPtr(new Option4AddrLst(DHO_ROUTERS, isc::asiolink::IOAddress(machine_get_interface_router(machine)))));

		// DNS servers
		OptionPtr option_dns = response4_ptr->getOption(DHO_NAME_SERVERS);
		if(option_dns) {
			response4_ptr->delOption(DHO_NAME_SERVERS);
		}
		response4_ptr->addOption(OptionPtr(new Option4AddrLst(DHO_NAME_SERVERS, isc::asiolink::IOAddress("192.168.0.1"))));

		// Set Interface MTU
		boost::shared_ptr<OptionUint16> option_mtu = 
			boost::static_pointer_cast<OptionUint16>(response4_ptr->getOption(DHO_INTERFACE_MTU));
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

		// Set broadcast address
		OptionPtr option_broadcast = response4_ptr->getOption(DHO_BROADCAST_ADDRESS);
		if (option_broadcast) {
			response4_ptr->delOption(DHO_BROADCAST_ADDRESS);
		}
		option_broadcast.reset(new OptionInt<uint32_t>(Option::V4, DHO_BROADCAST_ADDRESS, machine_get_broadcast_address(machine)));
		response4_ptr->addOption(option_broadcast);

		// Set hostname, the RFC says this is the short name, but whatever.
		OptionPtr option_hostname = response4_ptr->getOption(DHO_HOST_NAME);
		if (option_hostname) {
			response4_ptr->delOption(DHO_HOST_NAME);
		}
		char* hostname = machine_get_interface_hostname(machine);
		option_hostname.reset(new OptionString(Option::V4, DHO_HOST_NAME, hostname));
		response4_ptr->addOption(option_hostname);

		// Set next-server (Siaddr) - server address
		response4_ptr->setSiaddr(isc::asiolink::IOAddress(machine_get_next_server(machine)));

		// Set filename
		OptionPtr option_filename = response4_ptr->getOption(DHO_BOOT_FILE_NAME);
		if (option_filename) {
			response4_ptr->delOption(DHO_BOOT_FILE_NAME);
		}
		const char *filename = machine_get_filename(machine);
		if (filename) {
			option_filename.reset(new OptionString(Option::V4, DHO_BOOT_FILE_NAME, filename));
			response4_ptr->addOption(option_filename);
		}

		char *machine_client_type = machine_get_client_type(machine);
		if (strlen(machine_client_type) > 0) {
			OptionPtr option_vendor_class = response4_ptr->getOption(DHO_VENDOR_CLASS_IDENTIFIER);
			if (option_vendor_class) {
				response4_ptr->delOption(DHO_VENDOR_CLASS_IDENTIFIER);
			}

			option_vendor_class.reset(new OptionString(Option::V4, DHO_VENDOR_CLASS_IDENTIFIER, machine_client_type));
			response4_ptr->addOption(option_vendor_class);
		}
		/*
		 * Encapsulate some PXE options in the vendor encapsulated
		 */
		OptionPtr option_vendor(new Option(Option::V4, DHO_VENDOR_ENCAPSULATED_OPTIONS));
		LOG_INFO(logger, isc::log::LOG_CARBIDE_GENERIC).arg(option_vendor->toText());

		// Option 6 set to 0x8 tells iPXE not to wait for Proxy PXE since we don't care about that.
		OptionPtr vendor_option_6 = option_vendor->getOption(6);
		if (vendor_option_6) {
			option_vendor->delOption(6);
		}
		vendor_option_6.reset(new OptionInt<uint32_t>(Option::V4, 6, 0x8));

		// Option 70 we're using to set the UUID of the machine
		OptionPtr vendor_option_70 = option_vendor->getOption(70);
		if (vendor_option_70) {
			option_vendor->delOption(70);
		}
		char *machine_uuid = machine_get_uuid(machine);
        if (strlen(machine_uuid) > 0) {
            vendor_option_70.reset(new OptionString(Option::V4, 70, machine_uuid));
            option_vendor->addOption(vendor_option_6);
            option_vendor->addOption(vendor_option_70);
            response4_ptr->addOption(option_vendor);
        }

		LOG_INFO(logger, isc::log::LOG_CARBIDE_PKT4_SEND).arg(response4_ptr->toText());

		// Tell rust code to free the memory, since we can't free memory that isn't ours
		machine_free(machine);
		machine_free_fqdn(hostname);
		machine_free_client_type(machine_client_type);
		machine_free_filename(filename);
		machine_free_uuid(machine_uuid);

		return 0;
	}
}
