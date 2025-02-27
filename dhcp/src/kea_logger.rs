/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::ffi::CString;

use libc::{c_char, c_int};
use log::{Level, Metadata, Record};

pub struct KeaLogger;

// Kea stops at level DEBUG, but splits that into 100 'debuglevel' values, so arbitrarity assign
// one to Log::Debug and one to Log::Trace.
const KEA_DEBUGLEVEL_DEBUG: c_int = 10;
const KEA_DEBUGLEVEL_TRACE: c_int = 99;

unsafe extern "C" {
    fn kea_log_is_debug_enabled(debuglevel: c_int) -> bool;
    fn kea_log_is_info_enabled() -> bool;
    fn kea_log_is_warn_enabled() -> bool;
    fn kea_log_is_error_enabled() -> bool;

    // 'level' is kea config loggers/debuglevel
    fn kea_log_generic_debug(level: c_int, _: *const c_char);
    fn kea_log_generic_info(_: *const c_char);
    fn kea_log_generic_warn(_: *const c_char);
    fn kea_log_generic_error(_: *const c_char);
}

impl log::Log for KeaLogger {
    // Delegates the question to Kea. This allows us to configure logging entirely through Kea's
    // config.
    //
    // Manually map Rust 'log' levels (log/src/lib.rs) to Kea Severity (logger_level.h) because
    // the enum int values don't match and run in different directions.
    fn enabled(&self, metadata: &Metadata) -> bool {
        unsafe {
            use Level::*;
            match metadata.level() {
                Trace => kea_log_is_debug_enabled(KEA_DEBUGLEVEL_TRACE),
                Debug => kea_log_is_debug_enabled(KEA_DEBUGLEVEL_DEBUG),
                Info => kea_log_is_info_enabled(),
                Warn => kea_log_is_warn_enabled(),
                Error => kea_log_is_error_enabled(),
            }
        }
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let text = CString::new(format!(
                "{}:{}:{} - {}",
                record.file().unwrap_or("<no file>"),
                record.line().unwrap_or(0),
                record.target(),
                record.args()
            ))
            .unwrap();

            unsafe {
                use Level::*;
                match record.metadata().level() {
                    Trace => kea_log_generic_debug(KEA_DEBUGLEVEL_TRACE, text.into_raw()),
                    Debug => kea_log_generic_debug(KEA_DEBUGLEVEL_DEBUG, text.into_raw()),
                    Info => kea_log_generic_info(text.into_raw()),
                    Warn => kea_log_generic_warn(text.into_raw()),
                    Error => kea_log_generic_error(text.into_raw()),
                }
            }
        }
    }

    fn flush(&self) {}
}
