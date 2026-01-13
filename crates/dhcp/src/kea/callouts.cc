#include "callouts.h"
#include "carbide_rust.h"

isc::log::Logger logger("carbide-callouts");

const int IPV4_ADDR_SIZEB = 4;

void CDHCPOptionsHandler<Option>::resetOption(boost::any param) {
  switch (option) {
  case DHO_SUBNET_MASK:
    option_val.reset(new OptionInt<uint32_t>(
        Option::V4, option,
        machine_get_interface_subnet_mask(boost::any_cast<Machine *>(param))));
    break;
  case DHO_BROADCAST_ADDRESS:
    option_val.reset(new OptionInt<uint32_t>(
        Option::V4, option,
        machine_get_broadcast_address(boost::any_cast<Machine *>(param))));
    break;
  case DHO_HOST_NAME: {
    char *hostname =
        machine_get_interface_hostname(boost::any_cast<Machine *>(param));
    option_val.reset(new OptionString(Option::V4, option, hostname));
    machine_free_fqdn(hostname);
  } break;
  case DHO_BOOT_FILE_NAME: {
    // if client does not support netboot we get a null pointer
    const char *filename =
        machine_get_filename(boost::any_cast<Machine *>(param));
    if (filename) {
      option_val.reset(new OptionString(Option::V4, option, filename));
      machine_free_filename(filename);
    }
  } break;
  case DHO_VENDOR_CLASS_IDENTIFIER:
    option_val.reset(new OptionString(Option::V4, DHO_VENDOR_CLASS_IDENTIFIER,
                                      boost::any_cast<char *>(param)));
    break;
  default:
    LOG_ERROR(logger, "LOG_CARBIDE_PKT4_SEND: packet send error: Option [%1] "
                      "is not implemented for reset.")
        .arg(option);
  }
}

Option4AddrLst::AddressContainer getAddresses(std::string ips) {
  std::stringstream ss(ips);
  std::vector<isc::asiolink::IOAddress> out;
  char delim = ',';

  std::string s;
  while (std::getline(ss, s, delim)) {
    out.push_back(isc::asiolink::IOAddress(s));
  }

  return out;
}

void CDHCPOptionsHandler<Option>::resetAndAddOption(boost::any param) {
  switch (option) {
  case DHO_ROUTERS:
    response4_ptr->addOption(OptionPtr(new Option4AddrLst(
        option, isc::asiolink::IOAddress(machine_get_interface_router(
                    boost::any_cast<Machine *>(param))))));
    break;
  case DHO_NAME_SERVERS:
    response4_ptr->addOption(OptionPtr(new Option4AddrLst(
        option, getAddresses(boost::any_cast<std::string>(param)))));
    break;
  case DHO_DOMAIN_NAME_SERVERS:
    response4_ptr->addOption(OptionPtr(new Option4AddrLst(
        option, getAddresses(boost::any_cast<std::string>(param)))));
    break;
  case DHO_NTP_SERVERS:
    response4_ptr->addOption(OptionPtr(new Option4AddrLst(
        option, getAddresses(boost::any_cast<std::string>(param)))));
    break;
  case DHO_MQTT_SERVER:
    response4_ptr->addOption(OptionPtr(new OptionString(
        Option::V4, option, boost::any_cast<std::string>(param))));
    break;
  case DHO_SUBNET_MASK:
  case DHO_BROADCAST_ADDRESS:
  case DHO_HOST_NAME:
  case DHO_BOOT_FILE_NAME:
  case DHO_VENDOR_CLASS_IDENTIFIER:
    resetOption(param);
    if (option_val) {
      response4_ptr->addOption(option_val);
    }
    break;
  case DHO_INTERFACE_MTU:
	response4_ptr->delOption(DHO_INTERFACE_MTU);
	response4_ptr->addOption(OptionPtr(new OptionInt<uint16_t>(Option::V4, DHO_INTERFACE_MTU, boost::any_cast<uint16_t>(param))));
	break;
  default:
    LOG_ERROR(logger, "LOG_CARBIDE_PKT4_SEND: packet send error: Option [%1] "
                      "is not implemented for addandreset.")
        .arg(option);
  }
}

/*
 * The main function which updates the option in response4_ptr.
 * Currently as per implementation only Option and OptionUint16 templates are
 * implemented.
 */
template <typename T>
void update_option(CalloutHandle &handle, Pkt4Ptr response4_ptr,
                   const int option, boost::any param) {
  try {
    CDHCPOptionsHandler<T> option_handler(handle, response4_ptr, option);
    option_handler.resetAndAddOption(param);
  } catch (exception &e) {
    LOG_ERROR(logger, "LOG_CARBIDE_PKT4_SEND: packet send Exception for option "
                      "[%1]. Exception: %2")
        .arg(option)
        .arg(e.what());
    handle.setStatus(CalloutHandle::NEXT_STEP_DROP);
  }
}

DiscoveryBuilderResult update_discovery_parameters_option82(
    DiscoveryBuilderFFI *discovery, int option,
    boost::shared_ptr<OptionCustom> option_val) {
  switch (option) {
  case RAI_OPTION_LINK_SELECTION: {
    OptionPtr link_select = option_val->getOption(RAI_OPTION_LINK_SELECTION);
    if (link_select) {
      OptionBuffer link_select_buf = link_select->getData();
      if (link_select_buf.size() == sizeof(uint32_t)) {
        uint32_t option_select =
            isc::asiolink::IOAddress::fromBytes(AF_INET, &link_select_buf[0])
                .toUint32();
        // Update link select address.
        return discovery_set_link_select(discovery, option_select);
      }
    }
    break;
  }
  case RAI_OPTION_AGENT_CIRCUIT_ID: {
    OptionPtr circuit_id_opt =
        option_val->getOption(RAI_OPTION_AGENT_CIRCUIT_ID);
    if (circuit_id_opt) {
      OptionBuffer circuit_id = circuit_id_opt->getData();
      std::string circuit_value(circuit_id.begin(), circuit_id.end());
      LOG_INFO(logger, "LOG_CARBIDE_PKT4_RECEIVE: CIRCUIT ID [%1] in packet")
          .arg(circuit_value);
      return discovery_set_circuit_id(discovery, circuit_value.c_str());
    }
    break;
  }
  case RAI_OPTION_REMOTE_ID: {
    OptionPtr remote_id_opt = option_val->getOption(RAI_OPTION_REMOTE_ID);
    if (remote_id_opt) {
      OptionBuffer remote_id = remote_id_opt->getData();
      std::string remote_value(remote_id.begin(), remote_id.end());
      LOG_INFO(logger, "LOG_CARBIDE_PKT4_RECEIVE: REMOTE ID [%1] in packet")
          .arg(remote_value);
      return discovery_set_remote_id(discovery, remote_value.c_str());
    }
    break;
  }
  }

  return DiscoveryBuilderResult::Success;
}

DiscoveryBuilderResult
update_discovery_parameters(DiscoveryBuilderFFI *discovery, int option,
                            boost::shared_ptr<OptionCustom> option_val) {

  DiscoveryBuilderResult ret_val;
  switch (option) {
  case DHO_DHCP_AGENT_OPTIONS:
    ret_val = update_discovery_parameters_option82(
        discovery, RAI_OPTION_LINK_SELECTION, option_val);
    if (ret_val != DiscoveryBuilderResult::Success) {
      LOG_ERROR(
          logger,
          "LOG_CARBIDE_PKT4_RECEIVE: Failed in handling link select address.");
      return ret_val;
    }

    ret_val = update_discovery_parameters_option82(
        discovery, RAI_OPTION_AGENT_CIRCUIT_ID, option_val);
    if (ret_val != DiscoveryBuilderResult::Success) {
      LOG_ERROR(logger,
                "LOG_CARBIDE_PKT4_RECEIVE: Failed in handling circuit_id.");
      return ret_val;
    }

    ret_val = update_discovery_parameters_option82(
        discovery, RAI_OPTION_REMOTE_ID, option_val);
    if (ret_val != DiscoveryBuilderResult::Success) {
      LOG_ERROR(logger,
                "LOG_CARBIDE_PKT4_RECEIVE: Failed in handling remote_id.");
      return ret_val;
    }
    break;
  }

  return DiscoveryBuilderResult::Success;
}

DiscoveryBuilderResult
update_discovery_parameters(DiscoveryBuilderFFI *discovery, int option,
                            boost::shared_ptr<OptionString> option_val) {
  switch (option) {
  case DHO_VENDOR_CLASS_IDENTIFIER:
    return discovery_set_vendor_class(discovery,
                                      option_val->getValue().c_str());
  }

  return DiscoveryBuilderResult::Success;
}

DiscoveryBuilderResult
update_discovery_parameters(DiscoveryBuilderFFI *discovery, int option,
                            boost::shared_ptr<OptionUint16> option_val) {
  switch (option) {
  case DHO_SYSTEM:
    return discovery_set_client_system(discovery, option_val->getValue());
  }

  return DiscoveryBuilderResult::Success;
}

template <typename T>
DiscoveryBuilderResult
update_discovery_parameters(Pkt4Ptr query4_ptr, DiscoveryBuilderFFI *discovery,
                            int option) {
  boost::shared_ptr<T> option_val =
      boost::dynamic_pointer_cast<T>(query4_ptr->getOption(option));
  if (option_val) {
    LOG_INFO(logger, isc::log::LOG_CARBIDE_GENERIC).arg(option_val->toText());
    return update_discovery_parameters(discovery, option, option_val);
  } else {
    if (option != DHO_DHCP_AGENT_OPTIONS) {
      // TODO: Does this mean we rather should return an error here?
      LOG_ERROR(logger,
                "LOG_CARBIDE_PKT4_RECEIVE: Missing option [%1] in packet")
          .arg(option);
    }
  }

  return DiscoveryBuilderResult::Success;
}

void set_options(CalloutHandle &handle, Pkt4Ptr response4_ptr,
                 Machine *machine) {
  // Router Address
  update_option<Option>(handle, response4_ptr, DHO_ROUTERS, machine);

  // DNS servers
  char *machine_nameservers = machine_get_nameservers(machine);
  std::string nameservers(machine_nameservers);
  update_option<Option>(handle, response4_ptr, DHO_NAME_SERVERS, nameservers);
  update_option<Option>(handle, response4_ptr, DHO_DOMAIN_NAME_SERVERS,
                        nameservers);
  machine_free_nameservers(machine_nameservers);

  // NTP server
  char *machine_ntpservers = machine_get_ntpservers(machine);
  std::string ntpservers(machine_ntpservers);
  update_option<Option>(handle, response4_ptr, DHO_NTP_SERVERS, ntpservers);
  machine_free_nameservers(machine_ntpservers);

  // MQTT server
  char *machine_mqtt_server = machine_get_mqtt_server(machine);
  if (machine_mqtt_server != nullptr) {
    std::string mqtt_server(machine_mqtt_server);
    update_option<Option>(handle, response4_ptr, DHO_MQTT_SERVER, mqtt_server);
    machine_free_nameservers(machine_mqtt_server);
  }

  // Set Interface MTU
  uint16_t mtu = machine_get_interface_mtu(machine);
  update_option<Option>(handle, response4_ptr, DHO_INTERFACE_MTU, mtu);

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
    update_option<Option>(handle, response4_ptr, DHO_VENDOR_CLASS_IDENTIFIER,
                          machine_client_type);
  }
  machine_free_client_type(machine_client_type);
}

void set_vendor_options(Pkt4Ptr response4_ptr, Machine *machine) {
  OptionPtr option_vendor(
      new Option(Option::V4, DHO_VENDOR_ENCAPSULATED_OPTIONS));
  LOG_INFO(logger, isc::log::LOG_CARBIDE_GENERIC).arg(option_vendor->toText());

  // Option 6 set to 0x8 tells iPXE not to wait for Proxy PXE since we don't
  // care about that.
  OptionPtr vendor_option_6 = option_vendor->getOption(6);
  if (vendor_option_6) {
    option_vendor->delOption(6);
  }
  vendor_option_6.reset(new OptionInt<uint32_t>(Option::V4, 6, 0x8));
  option_vendor->addOption(vendor_option_6);

  // Option 70 we're using to set the UUID of the machine
  OptionPtr vendor_option_70 = option_vendor->getOption(70);
  if (vendor_option_70) {
    option_vendor->delOption(70);
  }
  char *machine_uuid = machine_get_uuid(machine);
  if (strlen(machine_uuid) > 0) {
    vendor_option_70.reset(new OptionString(Option::V4, 70, machine_uuid));
    option_vendor->addOption(vendor_option_70);
  }

  response4_ptr->addOption(option_vendor);
  machine_free_uuid(machine_uuid);
}

extern "C" {
int pkt4_receive(CalloutHandle &handle) {
  Pkt4Ptr query4_ptr;

  handle.getArgument("query4", query4_ptr);

  LOG_INFO(logger, isc::log::LOG_CARBIDE_PKT4_RECEIVE)
      .arg(query4_ptr->toText());

  /*
   * Call to increment total requests counter
   */
  carbide_increment_total_requests();

  /*
   * We only work on relayed packets (i.e. we never provide DHCP
   * for the network in which this daemon is running.
   */
  if (!query4_ptr || !query4_ptr->isRelayed()) {
    LOG_ERROR(logger, isc::log::LOG_CARBIDE_PKT4_RECEIVE)
        .arg("Received a non-relayed packet, dropping it");
    handle.setStatus(CalloutHandle::NEXT_STEP_DROP);
    /*
     * Call to increment drooped requests counter
     */
    carbide_increment_dropped_requests("NonRelayedPacket");
    return 0;
  }

  LOG_INFO(logger, "LOG_CARBIDE_PKT4_RECEIVE: Packet type name: %1")
	  .arg(query4_ptr->getName());

  // Initialize a discovery builder object
  // Since the object needs to be freed using a Rust function, we wrap it in
  // a unique_ptr with a custom deleter
  std::unique_ptr<DiscoveryBuilderFFI, void (*)(DiscoveryBuilderFFI *)>
      discovery(discovery_builder_allocate(), discovery_builder_free);

  /*
   * Extract the DHO_DHCP_AGENT_OPTIONS (82) from request and check if Suboption
   * 5: RAI_OPTION_LINK_SELECTION (RFC3527) and 1: RAI_OPTION_AGENT_CIRCUIT_ID
   * (RFC3527) are present or not.
   */
  DiscoveryBuilderResult builder_result =
      update_discovery_parameters<OptionCustom>(query4_ptr, discovery.get(),
                                                DHO_DHCP_AGENT_OPTIONS);
  /*
   * Extract the vendor class, which has some interesting bits
   * like HTTPClient / PXEClient
   *
   * TODO(ajf): find out where this option format is documented
   * at all so maybe we can build a type around it.
   */
  if (builder_result == DiscoveryBuilderResult::Success) {
    builder_result = update_discovery_parameters<OptionString>(
        query4_ptr, discovery.get(), DHO_VENDOR_CLASS_IDENTIFIER);
  }

  if (builder_result == DiscoveryBuilderResult::Success) {
    OptionPtr opt = query4_ptr->getOption(DHO_DHCP_REQUESTED_ADDRESS);
    if (opt) {
      OptionBuffer buf = opt->getData();
      auto bufSize = buf.size();

      if (bufSize == IPV4_ADDR_SIZEB) {
        uint32_t temp = 0;
        memcpy(&temp, buf.data(), IPV4_ADDR_SIZEB);
        uint32_t v4 = htonl(temp);

        isc::asiolink::IOAddress addr(v4);

        auto desired = addr.toText();

        discovery_set_desired_address(discovery.get(), desired.c_str());

        LOG_INFO(logger,
                "LOG_CARBIDE_PKT4_RECEIVE: Desired Address [%1] set")
          .arg(desired);
      } else {
        LOG_ERROR(logger, "LOG_CARBIDE_PKT4_RECEIVE: Desired addr buf len wrong: [%1]")
          .arg(bufSize);
      }
    }
  }

  /*
   * Extract the "client architecture" - DHCP option 93 from the
   * packet, which will tell us what the booting architecture is
   * in order to figure out which filname to give back
   */
  if (builder_result == DiscoveryBuilderResult::Success) {
    builder_result = update_discovery_parameters<OptionUint16>(
        query4_ptr, discovery.get(), DHO_SYSTEM);
  }

  /*
   * There's helper functions for the basic stuff like mac
   * address and relay address
   */
  if (builder_result == DiscoveryBuilderResult::Success) {
    builder_result = discovery_set_relay(discovery.get(),
                                         query4_ptr->getGiaddr().toUint32());
  }

  if (builder_result == DiscoveryBuilderResult::Success) {
    auto mac = query4_ptr->getHWAddr()->hwaddr_;
    builder_result =
        discovery_set_mac_address(discovery.get(), mac.data(), mac.size());
  }

  Machine *machine = nullptr;
  if (builder_result == DiscoveryBuilderResult::Success) {
    /*
     * We've been building up a object for the dhcp client options
     * we care about, so now we call the function to turn that
     * object into a dhcp machine object from the carbide API.
     */
    builder_result = discovery_fetch_machine(discovery.get(), &machine);
  }

  if (builder_result != DiscoveryBuilderResult::Success || machine == nullptr) {
    LOG_ERROR(logger,
              "LOG_CARBIDE_PKT4_RECV: Error while executing machine discovery "
              "in discovery_fetch_machine: %1, machine_ptr=%2")
        .arg(discovery_builder_result_as_str(builder_result))
        .arg(machine);
    handle.setStatus(CalloutHandle::NEXT_STEP_DROP);
    /*
     * Call to increment drooped requests counter
     */
    carbide_increment_dropped_requests(discovery_builder_result_as_str(builder_result));
    return 1;
  }

  // On success, we set the pointer to the machine in the request context to
  // be retrieved later
  boost::shared_ptr<Machine> machinePtr(machine, [](Machine *ptr) {
    // Tell rust code to free the memory, since memory allocated in Rust can't
    // be freed with a native `delete` or `free`.
    // By wrapping this in the `shared_ptr`, we make sure KEA always releases
    // the handle when it's done with the request
    machine_free(ptr);
  });
  handle.setContext("machine", machinePtr);
  return 0;
}

int pkt4_send(CalloutHandle &handle) {
  Pkt4Ptr query4_ptr, response4_ptr;

  handle.getArgument("query4", query4_ptr);
  handle.getArgument("response4", response4_ptr);

  /*
   * Load the machine from the context.  It should have been set in
   * pkt4_receive.
   */
  boost::shared_ptr<Machine> machine;
  handle.getContext("machine", machine);
  if (!machine) {
    LOG_ERROR(logger, isc::log::LOG_CARBIDE_PKT4_SEND)
        .arg("Missing machine object from handle context");
    handle.setStatus(CalloutHandle::NEXT_STEP_DROP);
    return 1;
  }

  /*
   * Fetch the interface address for this machine (i.e. this is the address
   * assigned to the DHCP-ing host.
   */
  response4_ptr->setYiaddr(
      isc::asiolink::IOAddress(machine_get_interface_address(machine.get())));

  set_options(handle, response4_ptr, machine.get());

  // Set next-server (Siaddr) - server address
  response4_ptr->setSiaddr(
      isc::asiolink::IOAddress(machine_get_next_server(machine.get())));

  /*
   * Encapsulate some PXE options in the vendor encapsulated
   */
  set_vendor_options(response4_ptr, machine.get());

  LOG_INFO(logger, isc::log::LOG_CARBIDE_PKT4_SEND)
      .arg(response4_ptr->toText());

  return 0;
}
}
