#include <log/logger.h>
#include <log/macros.h>

#include "carbide_logger.h"

isc::log::Logger ffi_logger("kea-carbide-rust");

extern "C" {
	void kea_log_generic_info(char* message) {
		LOG_INFO(ffi_logger, isc::log::LOG_CARBIDE_GENERIC).arg(message);
	}
}
