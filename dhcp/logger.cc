// File created from src/kea/logger.mes

#include <cstddef>
#include <log/message_types.h>
#include <log/message_initializer.h>

namespace isc {
namespace log {

extern const isc::log::MessageID LOG_CARBIDE_ERROR = "LOG_CARBIDE_ERROR";

} // namespace log
} // namespace isc

namespace {

const char* values[] = {
    "LOG_CARBIDE_ERROR", "umm what",
    NULL
};

const isc::log::MessageInitializer initializer(values);

} // Anonymous namespace

