#include "callouts.h"

isc::log::Logger logger("kea-carbide-callouts");

void CDHCPOptionsHandler<Option>::resetOption(boost::any param) {
    switch(option) {
		case DHO_SUBNET_MASK:
	        option_val.reset(new OptionInt<uint32_t>(
	                    Option::V4, option, machine_get_interface_subnet_mask(
	                        boost::any_cast<Machine *> (param))));
		    break;
		case DHO_BROADCAST_ADDRESS:
		    option_val.reset(new OptionInt<uint32_t>(
		                Option::V4, option, machine_get_broadcast_address(
		                    boost::any_cast<Machine *>(param))));
		    break;
		case DHO_HOST_NAME:
		    {
		        char* hostname = machine_get_interface_hostname(boost::any_cast<Machine *>(param));
		        option_val.reset(new OptionString(Option::V4, option, hostname));
		        machine_free_fqdn(hostname);
		    }
		    break;
		case DHO_BOOT_FILE_NAME:
		    {
		        const char *filename = machine_get_filename(boost::any_cast<Machine *>(param));
		        if (filename) {
			        option_val.reset(new OptionString(Option::V4, option, filename));
		            machine_free_filename(filename);
		        }
		    }
		    break;
		case DHO_VENDOR_CLASS_IDENTIFIER:
			option_val.reset(new OptionString(Option::V4, DHO_VENDOR_CLASS_IDENTIFIER, boost::any_cast<char *>(param)));
			break;
		default:
		    LOG_ERROR(logger, "LOG_CARBIDE_PKT4_SEND: packet send error: Option [%1] is not implemented for reset.").arg(option);
	}

}

void CDHCPOptionsHandler<Option>::resetAndAddOption(boost::any param) {
    switch(option) {
		case DHO_ROUTERS:
		    response4_ptr->addOption(
		            OptionPtr(
		                new Option4AddrLst(
		                    option, isc::asiolink::IOAddress(
		                        machine_get_interface_router(boost::any_cast<Machine *> (param))))));
		    break;
		case DHO_NAME_SERVERS:
		    response4_ptr->addOption(
		            OptionPtr(
		                new Option4AddrLst(
		                    option, isc::asiolink::IOAddress(boost::any_cast<const char *>(param)))));
		    break;
		case DHO_SUBNET_MASK:
		case DHO_BROADCAST_ADDRESS:
		case DHO_HOST_NAME:
		case DHO_BOOT_FILE_NAME:
		case DHO_VENDOR_CLASS_IDENTIFIER:
		    resetOption(param);
		    if(option_val) {
		        response4_ptr->addOption(option_val);
		    }
		    break;
		default:
		    LOG_ERROR(logger, "LOG_CARBIDE_PKT4_SEND: packet send error: Option [%1] is not implemented for addandreset.").arg(option);
	}
}

/*
 * The main function which updates the option in response4_ptr.
 * Currntly as per implementation only Option and OptionUint16 templates are 
 * implemented.
 */
template <typename T>
void update_option(CalloutHandle &handle, Pkt4Ptr response4_ptr, const int option, boost::any param) {
	try {
        CDHCPOptionsHandler<T> option_handler(handle, response4_ptr, option);
        option_handler.resetAndAddOption(param);
	}
	catch(exception& e) {
		LOG_ERROR(logger, "LOG_CARBIDE_PKT4_SEND: packet send Exception for option [%1]. Exception: %2").arg(option).arg(e.what());
		handle.setStatus(CalloutHandle::NEXT_STEP_DROP);
	}
}

void update_discovery_parameters(DiscoveryBuilderFFI *discovery, int option, boost::shared_ptr<OptionString> option_val) {
	switch(option) {
        case DHO_VENDOR_CLASS_IDENTIFIER:
			discovery_set_vendor_class(discovery, option_val->getValue().c_str());
			break;
    }
}

void update_discovery_parameters(DiscoveryBuilderFFI *discovery, int option, boost::shared_ptr<OptionUint16> option_val) {
	switch(option) {
		case DHO_SYSTEM:
			discovery_set_client_system(discovery, option_val->getValue());
			break;
    }
}

template <typename T>
void update_discovery_parameters(Pkt4Ptr query4_ptr, DiscoveryBuilderFFI *discovery, int option) {
	boost::shared_ptr<T> option_val =
		boost::dynamic_pointer_cast<T>(query4_ptr->getOption(option));
	if (option_val) {
		LOG_INFO(logger, isc::log::LOG_CARBIDE_GENERIC).arg(option_val->toText());
		update_discovery_parameters(discovery, option, option_val);
	} else {
		LOG_ERROR(logger, "LOG_CARBIDE_PKT4_RECEIVE: Missing option [%1] in packet").arg(option_val);
	}
}

void set_options(CalloutHandle &handle, Pkt4Ptr response4_ptr, Machine *machine) {
	// Router Address
	update_option<Option>(handle, response4_ptr, DHO_ROUTERS, machine);

	// DNS servers
	update_option<Option>(handle, response4_ptr, DHO_NAME_SERVERS, "192.168.0.1");

	// Set Interface MTU
	update_option<OptionUint16>(handle, response4_ptr, DHO_INTERFACE_MTU, 1500);

	// Set subnet-mask
	update_option<Option>(handle, response4_ptr, DHO_SUBNET_MASK, machine);

	// Set broadcast address
	update_option<Option>(handle, response4_ptr, DHO_BROADCAST_ADDRESS, machine);

	// Set hostname, the RFC says this is the short name, but whatever.
	update_option<Option>(handle, response4_ptr, DHO_HOST_NAME, machine);

	// Set filename
	update_option<Option>(handle, response4_ptr, DHO_BOOT_FILE_NAME, machine);

	char *machine_client_type = machine_get_client_type(machine);
	if (strlen(machine_client_type) > 0) {
	    update_option<Option>(handle, response4_ptr, DHO_VENDOR_CLASS_IDENTIFIER, machine_client_type);
	}
	machine_free_client_type(machine_client_type);
}

void set_vendor_options(Pkt4Ptr response4_ptr, Machine *machine) {
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
	machine_free_uuid(machine_uuid);
}

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
        update_discovery_parameters<OptionString>(query4_ptr, discovery, DHO_VENDOR_CLASS_IDENTIFIER);

		/*
		 * Extract the "client architecture" - DHCP option 93 from the
		 * packet, which will tell us what the booting architecture is
		 * in order to figure out which filname to give back
		 */
        update_discovery_parameters<OptionUint16>(query4_ptr, discovery, DHO_SYSTEM);

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

        set_options(handle, response4_ptr, machine);

		// Set next-server (Siaddr) - server address
		response4_ptr->setSiaddr(isc::asiolink::IOAddress(machine_get_next_server(machine)));

		/*
		 * Encapsulate some PXE options in the vendor encapsulated
		 */
		set_vendor_options(response4_ptr, machine);

		LOG_INFO(logger, isc::log::LOG_CARBIDE_PKT4_SEND).arg(response4_ptr->toText());

		// Tell rust code to free the memory, since we can't free memory that isn't ours
		machine_free(machine);

		return 0;
	}
}
