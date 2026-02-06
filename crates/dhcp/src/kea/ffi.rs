/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
use log::LevelFilter;

unsafe extern "C" {
    pub fn shim_version() -> libc::c_int;
    pub fn shim_load(_: *mut libc::c_void) -> libc::c_int;
    pub fn shim_unload() -> libc::c_int;
    pub fn shim_multi_threading_compatible() -> libc::c_int;
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn version() -> libc::c_int {
    unsafe { shim_version() }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn load(a: *mut libc::c_void) -> libc::c_int {
    match log::set_logger(&crate::LOGGER).map(|()| log::set_max_level(LevelFilter::Trace)) {
        Ok(_) => log::info!("Initialized Logger"),
        Err(err) => {
            eprintln!("Unable to initialize logger: {err}");
            return 1;
        }
    };

    unsafe { shim_load(a) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn unload() -> libc::c_int {
    unsafe { shim_unload() }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn multi_threading_compatible() -> libc::c_int {
    unsafe { shim_multi_threading_compatible() }
}
