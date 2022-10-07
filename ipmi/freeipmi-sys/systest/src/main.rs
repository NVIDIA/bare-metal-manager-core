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
#![allow(bad_style, improper_ctypes)]


extern crate freeipmi_sys;
extern crate getopts;
extern crate libc;

use freeipmi_sys::{auth_type, cipher_suite, ipmi_interface, power_control, privilege_level};
use freeipmi_sys::auth_type::{IPMI_AUTHENTICATION_TYPE_MD2, IPMI_AUTHENTICATION_TYPE_MD5, IPMI_AUTHENTICATION_TYPE_NONE, IPMI_AUTHENTICATION_TYPE_OEM_PROP, IPMI_AUTHENTICATION_TYPE_STRAIGHT_PASSWORD_KEY};
use freeipmi_sys::cipher_suite::{IPMI_CIPHER_HMAC_MD5_AES_CBC_128, IPMI_CIPHER_HMAC_SHA1_AES_CBC_128, IPMI_CIPHER_HMAC_SHA256_AES_CBC_128};
use freeipmi_sys::ipmi::*;
use freeipmi_sys::ipmi_interface::{IPMI_DEVICE_KCS, IPMI_DEVICE_LAN, IPMI_DEVICE_LAN_2_0};
use freeipmi_sys::power_control::{IPMI_CHASSIS_CONTROL_HARD_RESET, IPMI_CHASSIS_CONTROL_INITIATE_SOFT_SHUTDOWN, IPMI_CHASSIS_CONTROL_POWER_CYCLE, IPMI_CHASSIS_CONTROL_POWER_DOWN, IPMI_CHASSIS_CONTROL_POWER_UP, IPMI_CHASSIS_CONTROL_PULSE_DIAGNOSTIC_INTERRUPT};
use freeipmi_sys::privilege_level::IPMI_PRIVILEGE_LEVEL_ADMIN;

fn main() -> Result<(), String> {
    let mut hostname: String = "".to_string();
    let mut username: String = "".to_string();
    let mut password: String = "".to_string();
    let mut intf: ipmi_interface = IPMI_DEVICE_LAN_2_0;
    let mut cipher: cipher_suite = IPMI_CIPHER_HMAC_SHA256_AES_CBC_128;
    let mut auth: auth_type = IPMI_AUTHENTICATION_TYPE_MD5;
    let mode: privilege_level = IPMI_PRIVILEGE_LEVEL_ADMIN;
    let mut action: power_control = IPMI_CHASSIS_CONTROL_PULSE_DIAGNOSTIC_INTERRUPT;
    let args: Vec<String> = std::env::args().collect();
    let mut opts = getopts::Options::new();
    let mut status_cmd = false;
    let mut error_msg: String = "".to_string();
    opts.optopt("H", "hostname", "specify hostname or IP address", "HOST");
    opts.optopt("U", "username", "specify authentication username", "USER");
    opts.optopt("P", "password", "specify authentication password", "PASS");
    opts.optopt("I", "interface", "specify interface, either lan or lanplus or local", "INTF");
    opts.optopt("C", "cipher", "specify cipher suite value to use (only for lanplus)", "CIPHER");
    opts.optopt("A", "auth", "specify auth type NONE/PASSWORD/MD2/MD5/OEM to use (only for lan)", "AUTH");
    opts.optopt("c", "cmd", "specify the command to run: off/on/cycle/reset/shutdown/status", "CMD");

    let args_given = opts.parse(&args[1..]).unwrap();
    if args_given.opt_present("H") {
        hostname = args_given.opt_str("H").unwrap();
    }
    if args_given.opt_present("U") {
        username = args_given.opt_str("U").unwrap();
    }
    if args_given.opt_present("P") {
        password = args_given.opt_str("P").unwrap();
    }
    if args_given.opt_present("I") {
        match args_given.opt_str("I").unwrap().as_str() {
            "lan" => {
                intf = IPMI_DEVICE_LAN;
            }
            "lanplus" => {
                intf = IPMI_DEVICE_LAN_2_0;
            }
            "local" => {
                intf = IPMI_DEVICE_KCS;
            }
            _ => {
                error_msg = format!("Invalid interface argument given {}", args_given.opt_str("I").unwrap());
            }
        }
    }
    if !error_msg.is_empty() {
        return Err(error_msg);
    }

    if args_given.opt_present("A") {
        match args_given.opt_str("A").unwrap().as_str() {
            "NONE" => {
                auth = IPMI_AUTHENTICATION_TYPE_NONE;
            }
            "PASSWORD" => {
                auth = IPMI_AUTHENTICATION_TYPE_STRAIGHT_PASSWORD_KEY;
            }
            "MD2" => {
                auth = IPMI_AUTHENTICATION_TYPE_MD2;
            }
            "MD5" => {
                auth = IPMI_AUTHENTICATION_TYPE_MD5;
            }
            "OEM" => {
                auth = IPMI_AUTHENTICATION_TYPE_OEM_PROP;
            }
            _ => {
                error_msg = format!("Invalid auth argument given {}", args_given.opt_str("A").unwrap());
            }
        }
    }
    if !error_msg.is_empty() {
        return Err(error_msg);
    }

    if args_given.opt_present("C") {
        match args_given.opt_str("C").unwrap().as_str() {
            "3" => {
                cipher = IPMI_CIPHER_HMAC_SHA1_AES_CBC_128;
            }
            "8" => {
                cipher = IPMI_CIPHER_HMAC_MD5_AES_CBC_128;
            }
            "17" => {
                cipher = IPMI_CIPHER_HMAC_SHA256_AES_CBC_128;
            }
            _ => {
                error_msg = format!("Unsupported cipher specified {}", args_given.opt_str("C").unwrap());
            }
        }
    }
    if !error_msg.is_empty() {
        return Err(error_msg);
    }

    if args_given.opt_present("c") {
        match args_given.opt_str("c").unwrap().as_str() {
            "off" => {
                action = IPMI_CHASSIS_CONTROL_POWER_DOWN;
            }
            "on" => {
                action = IPMI_CHASSIS_CONTROL_POWER_UP;
            }
            "cycle" => {
                action = IPMI_CHASSIS_CONTROL_POWER_CYCLE;
            }
            "reset" => {
                action = IPMI_CHASSIS_CONTROL_HARD_RESET;
            }
            "shutdown" => {
                action = IPMI_CHASSIS_CONTROL_INITIATE_SOFT_SHUTDOWN;
            }
            "status" => {
                status_cmd = true;
            }
            _ => {
                error_msg = format!("Unsupported command specified {}", args_given.opt_str("c").unwrap());
            }
        }
    }
    if !error_msg.is_empty() {
        return Err(error_msg);
    }

    if intf as u8 != IPMI_DEVICE_KCS as u8 {
        if hostname.is_empty() || username.is_empty() || password.is_empty() {
            return Err(format!("Hostname or Username or Password not specified for lan connection"));
        }
    }

    if action as u8 == IPMI_CHASSIS_CONTROL_PULSE_DIAGNOSTIC_INTERRUPT as u8 && status_cmd == false {
        return Err(format!("cmd -c not specified"));
    }

    let mut ctx = ipmi_ctx::new(hostname, username, password,
                                Option::from(intf), Option::from(cipher),
                                Option::from(mode), Option::from(auth));

    if ctx.connect().is_ok() {
        if status_cmd == true {
            match ctx.chassis_status() {
                Ok(status) => {
                    println!("Status:\n");
                    let items = status.iter();
                    for item in items {
                        println!("{}", item);
                    }
                }
                Err(e) => {
                    let error_msg = format!("Failed to run chassis status command {}", e);
                    println!("{}", error_msg);
                }
            }
        } else {
            match ctx.power_control(action) {
                Ok(()) => {
                    println!("Successfully ran power control command");
                }
                Err(e) => {
                    let error_msg = format!("Failed to run power control command {}", e);
                    println!("{}", error_msg);
                }
            }
        }
    } else {
        println!("Failed to connect");
    }
    if ctx.disconnect().is_err() {
        println!("Error disconnecting");
    }
    ctx.destroy();
    Ok(())
}
