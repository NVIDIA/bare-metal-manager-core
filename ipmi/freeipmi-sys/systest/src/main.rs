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

extern crate freeipmi_sys;
extern crate getopts;
extern crate libc;

use freeipmi_sys::{IpmiAuthenticationType, IpmiCipherSuite, IpmiDevice, IpmiPrivilegeLevel, IpmiChassisControl};
use freeipmi_sys::ipmi::*;

fn main() -> Result<(), String> {
    let mut hostname: String = "".to_string();
    let mut username: String = "".to_string();
    let mut password: String = "".to_string();
    let mut intf: IpmiDevice = IpmiDevice::Lan2_0;
    let mut cipher: IpmiCipherSuite = IpmiCipherSuite::HmacMd5AesCbc128;
    let mut auth: IpmiAuthenticationType = IpmiAuthenticationType::None;
    let mode: IpmiPrivilegeLevel = IpmiPrivilegeLevel::Admin;
    let mut action: IpmiChassisControl = IpmiChassisControl::PulseDiagnosticInterrupt;
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
                intf = IpmiDevice::Lan;
            }
            "lanplus" => {
                intf = IpmiDevice::Lan2_0;
            }
            "local" => {
                intf = IpmiDevice::Kcs;
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
                auth = IpmiAuthenticationType::None;
            }
            "PASSWORD" => {
                auth = IpmiAuthenticationType::StraightPasswordKey;
            }
            "MD2" => {
                auth = IpmiAuthenticationType::Md2;
            }
            "MD5" => {
                auth = IpmiAuthenticationType::Md5;
            }
            "OEM" => {
                auth = IpmiAuthenticationType::OemProp;
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
                cipher = IpmiCipherSuite::HmacSha1AesCbc128;
            }
            "8" => {
                cipher = IpmiCipherSuite::HmacMd5AesCbc128;
            }
            "17" => {
                cipher = IpmiCipherSuite::HmacSha256AesCbc128;
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
                action = IpmiChassisControl::PowerDown;
            }
            "on" => {
                action = IpmiChassisControl::PowerUp;
            }
            "cycle" => {
                action = IpmiChassisControl::PowerCycle;
            }
            "reset" => {
                action = IpmiChassisControl::HardReset;
            }
            "shutdown" => {
                action = IpmiChassisControl::InitiateSoftShutdown;
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

    if intf as u8 != IpmiDevice::Kcs as u8 &&
        hostname.is_empty() || username.is_empty() || password.is_empty() {
            return Err(format!("Hostname or Username or Password not specified for lan connection".to_string()));

    }

    if action as u8 == IpmiChassisControl::PulseDiagnosticInterrupt as u8 && !status_cmd {
        return Err(format!("cmd -c not specified").to_string());
    }

    let mut ctx = IpmiContext::new(hostname, username, password,
                                Option::from(intf), Option::from(cipher),
                                Option::from(mode), Option::from(auth));

    if ctx.connect().is_ok() {
        if status_cmd {
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
