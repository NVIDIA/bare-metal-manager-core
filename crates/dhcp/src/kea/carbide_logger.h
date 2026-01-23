// File created from carbide_logger.mes

#ifndef CARBIDE_LOGGER_H
#define CARBIDE_LOGGER_H

#include <log/message_types.h>

namespace isc {
namespace log {

extern const isc::log::MessageID LOG_CARBIDE_GENERIC;
extern const isc::log::MessageID LOG_CARBIDE_INITIALIZATION;
extern const isc::log::MessageID LOG_CARBIDE_INVALID_HANDLE;
extern const isc::log::MessageID LOG_CARBIDE_INVALID_NEXTSERVER_IPV4;
extern const isc::log::MessageID LOG_CARBIDE_LEASE4_SELECT;
extern const isc::log::MessageID LOG_CARBIDE_PKT4_RECEIVE;
extern const isc::log::MessageID LOG_CARBIDE_PKT4_SEND;

} // namespace log
} // namespace isc

#endif // CARBIDE_LOGGER_H
