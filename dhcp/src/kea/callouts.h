#ifndef CALLOUTS_H
#define CALLOUTS_H

#include <asiolink/io_address.h>
#include <dhcp/pkt4.h>
#include <dhcpsrv/lease.h>
#include <hooks/hooks.h>
#include <log/logger.h>
#include <log/macros.h>
#include <string>

#include <dhcp/option4_addrlst.h>
#include <dhcp/option_definition.h>
#include <dhcp/option_string.h>

#include "carbide_logger.h"
#include "carbide_rust.h"
#include <dhcp/option_custom.h>
#pragma GCC diagnostic ignored "-Wsign-compare"
#include <dhcp/option_int.h>
#pragma GCC diagnostic pop

using namespace isc::hooks;
using namespace isc::dhcp;
using namespace std;

// MQTT server currently is set in option 224.
const uint16_t DHO_MQTT_SERVER = 224;

template <typename T>
boost::shared_ptr<T> get_and_delete_option(Pkt4Ptr response4_ptr, int option) {
  boost::shared_ptr<T> option_val =
      boost::static_pointer_cast<T>(response4_ptr->getOption(option));
  if (option_val) {
    response4_ptr->delOption(option);
  }
  return option_val;
}

template <class T> class CDHCPOptionsHandler;

// Base class for Option handling.
template <class T> class CDHCPOptionsManager {
protected:
  CalloutHandle &handle;
  Pkt4Ptr response4_ptr;
  int option;
  boost::shared_ptr<T> option_val;

public:
  CDHCPOptionsManager(CalloutHandle &handle, Pkt4Ptr response4_ptr, int option)
      : handle(handle), response4_ptr(response4_ptr), option(option) {
    this->option_val = get_and_delete_option<T>(response4_ptr, option);
  }

  virtual void resetAndAddOption(boost::any param) = 0;
};

// Following are the specialized implementation of Option handlers.
// Currently only Option and OptionUint16 are supported as only these are used
// in pkt handler function.

template <>
class CDHCPOptionsHandler<OptionUint16>
    : public CDHCPOptionsManager<OptionUint16> {
public:
  CDHCPOptionsHandler(CalloutHandle &handle, Pkt4Ptr response4_ptr, int option)
      : CDHCPOptionsManager(handle, response4_ptr, option) {}

  void resetAndAddOption(boost::any param) {
    option_val.reset(new OptionInt<uint16_t>(Option::V4, option,
                                             boost::any_cast<int>(param)));
  }
};

template <>
class CDHCPOptionsHandler<Option> : public CDHCPOptionsManager<Option> {
public:
  CDHCPOptionsHandler(CalloutHandle &handle, Pkt4Ptr response4_ptr, int option)
      : CDHCPOptionsManager(handle, response4_ptr, option) {}

  void resetOption(boost::any param);
  void resetAndAddOption(boost::any param);
};

extern "C" {
int pkt4_receive(CalloutHandle &handle);
int subnet4_select(CalloutHandle &handle);
int lease4_select(CalloutHandle &handle);
int pkt4_send(CalloutHandle &handle);
}

#endif
