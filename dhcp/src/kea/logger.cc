#include <log/logger.h>
#include <log/macros.h>

#include "carbide_logger.h"

isc::log::Logger ffi_logger("carbide-rust");

extern "C" {
	bool kea_log_is_debug_enabled(int debuglevel) {
		return ffi_logger.isDebugEnabled(debuglevel);
	}
	bool kea_log_is_info_enabled() {
		return ffi_logger.isInfoEnabled();
	}
	bool kea_log_is_warn_enabled() {
		return ffi_logger.isWarnEnabled();
	}
	bool kea_log_is_error_enabled() {
		return ffi_logger.isErrorEnabled();
	}

	void kea_log_generic_debug(int level, char* message) {
		LOG_DEBUG(ffi_logger, level, isc::log::LOG_CARBIDE_GENERIC).arg(message);
	}
	void kea_log_generic_info(char* message) {
		LOG_INFO(ffi_logger, isc::log::LOG_CARBIDE_GENERIC).arg(message);
	}
	void kea_log_generic_warn(char* message) {
		LOG_WARN(ffi_logger, isc::log::LOG_CARBIDE_GENERIC).arg(message);
	}
	void kea_log_generic_error(char* message) {
		LOG_ERROR(ffi_logger, isc::log::LOG_CARBIDE_GENERIC).arg(message);
	}
}
