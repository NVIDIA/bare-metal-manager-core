/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

use libc::c_char;
use log::{Level, Metadata, Record};

pub struct KeaLogger;

extern "C" {
    fn kea_log_generic_info(_: *const c_char);
}

impl log::Log for KeaLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Info
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

            unsafe { kea_log_generic_info(text.into_raw()) };
        }
    }

    fn flush(&self) {}
}
