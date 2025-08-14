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
