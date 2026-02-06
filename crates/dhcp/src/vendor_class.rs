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
use std::fmt::Display;
use std::str::FromStr;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum MachineArchitecture {
    BiosX86,
    EfiX64,
    Arm64,
    Unknown,
}

// DHCP Option 60 vendor-class-identifier
#[derive(Debug, Clone)]
pub struct VendorClass {
    pub id: String,
    pub arch: MachineArchitecture,
}

#[derive(Debug)]
pub enum VendorClassParseError {
    InvalidFormat,
    UnsupportedClientType,
    UnsupportedArchitecture,
}

impl FromStr for MachineArchitecture {
    type Err = VendorClassParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            // When a DPU (and presumably other hardware) has an OS
            // the vendor class no longer is a UEFI vendor
            "aarch64" => Ok(MachineArchitecture::Arm64),
            _ => {
                match s.parse() {
                    // This is base 10 represented by the long vendor class
                    Ok(0) => Ok(MachineArchitecture::BiosX86),
                    Ok(7) => Ok(MachineArchitecture::EfiX64),
                    Ok(11) => Ok(MachineArchitecture::Arm64),
                    Ok(16) => Ok(MachineArchitecture::EfiX64), // HTTP version
                    Ok(19) => Ok(MachineArchitecture::Arm64),  // HTTP version
                    Ok(_) => Ok(MachineArchitecture::Unknown), // Unknown
                    Err(_) => Ok(MachineArchitecture::Unknown), // No Errors, we always vend ips
                }
            }
        }
    }
}

impl Display for VendorClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} ({})",
            self.arch,
            if self.is_netboot() {
                "netboot"
            } else {
                "basic"
            }
        )
    }
}

impl Display for MachineArchitecture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Arm64 => "ARM 64-bit UEFI",
                Self::EfiX64 => "x64 UEFI",
                Self::BiosX86 => "x86 BIOS",
                Self::Unknown => "Unknown",
            }
        )
    }
}

///
/// Convert a string of the form A:B:C:D... to Self
///
impl FromStr for VendorClass {
    type Err = VendorClassParseError;

    fn from_str(vendor_class: &str) -> Result<Self, Self::Err> {
        match vendor_class {
            // this is the UEFI version
            colon if colon.contains(':') => {
                let parts: Vec<&str> = vendor_class.split(':').collect();
                match parts.len() {
                    5 => Ok(VendorClass {
                        id: parts[0].to_string(),
                        arch: parts[2].parse()?,
                    }),
                    _ => Ok(VendorClass {
                        id: format!("unknown: '{colon}'"),
                        arch: MachineArchitecture::Unknown,
                    }),
                }
            }
            // This is the OS (bluefield so far, maybe host OS's too)
            space if space.contains(' ') => {
                let parts: Vec<&str> = vendor_class.split(' ').collect();
                match parts.len() {
                    2 => Ok(VendorClass {
                        id: parts[0].to_string(),
                        arch: parts[1].parse()?,
                    }),
                    _ => Ok(VendorClass {
                        id: format!("unknown: '{space}'"),
                        arch: MachineArchitecture::Unknown,
                    }),
                }
            }
            // BF2Client is older BF2 cards, PXEClient without colon is iPxe response
            vc @ ("NVIDIA/BF/OOB" | "BF2Client" | "PXEClient" | "NVIDIA/BF/BMC") => {
                Ok(VendorClass {
                    id: vc.to_string(),
                    arch: MachineArchitecture::Arm64,
                })
            }
            // x86 DELL BMC OR x86 HP iLo BMC
            vc @ ("iDRAC" | "CPQRIB3") => Ok(VendorClass {
                id: vc.to_string(),
                arch: MachineArchitecture::EfiX64,
            }),
            vc => Ok(VendorClass {
                id: format!("unknown: '{vc}'"),
                arch: MachineArchitecture::Unknown,
            }),
        }
    }
}

impl VendorClass {
    // Currently only HTTPClient vendor class uses HTTP netboot
    pub fn is_netboot(&self) -> bool {
        self.id == "HTTPClient"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl VendorClass {
        pub fn arm(&self) -> bool {
            self.arch == MachineArchitecture::Arm64
        }

        pub fn x64(&self) -> bool {
            self.arch == MachineArchitecture::EfiX64
        }

        pub fn is_it_modern(&self) -> bool {
            self.is_netboot() && self.arm()
        }
    }

    #[test]
    fn it_is_pxe_capable() {
        let vc: VendorClass = "PXEClient:Arch:00007:UNDI:003000".parse().unwrap();
        assert!(!vc.is_netboot());

        let vc: VendorClass = "iDRAC".parse().unwrap();
        assert!(!vc.is_netboot());

        let vc: VendorClass = "PXEClient".parse().unwrap();
        assert!(!vc.is_netboot());
    }

    #[test]
    fn is_it_arm_non_uefi() {
        let vc: VendorClass = "nvidia-bluefield-dpu aarch64".parse().unwrap();
        assert!(vc.arm());

        let vc: VendorClass = "BF2Client".parse().unwrap();
        assert!(vc.arm());
    }

    #[test]
    fn is_it_arm() {
        let vc: VendorClass = "PXEClient:Arch:00011:UNDI:003000".parse().unwrap();
        assert!(vc.arm());
    }

    #[test]
    fn is_it_not_modern() {
        let vc: VendorClass = "PXEClient:Arch:00007:UNDI:003000".parse().unwrap();
        assert!(!vc.is_it_modern());
    }

    #[test]
    fn is_it_modern() {
        let vc: VendorClass = "HTTPClient:Arch:00011:UNDI:003000".parse().unwrap();
        assert!(vc.is_it_modern());
    }

    #[test]
    fn it_is_netboot_capable() {
        let vc: VendorClass = "HTTPClient:Arch:00016:UNDI:003001".parse().unwrap();
        assert!(vc.is_netboot());
    }

    #[test]
    fn it_is_netboot_and_not_arm() {
        let vc: VendorClass = "HTTPClient:Arch:00016:UNDI:003001".parse().unwrap();
        assert!(vc.is_netboot());
        assert!(vc.x64());
    }

    #[test]
    fn it_handles_basic_for_all_clients() {
        let vc: Result<VendorClass, VendorClassParseError> =
            "NothingClient:Arch:00011:UNDI:X".parse();
        assert_eq!(vc.unwrap().to_string(), "ARM 64-bit UEFI (basic)");
    }

    #[test]
    fn it_formats_the_parser_armuefi_netboot() {
        let vc: VendorClass = "HTTPClient:Arch:00011:UNDI:003000".parse().unwrap();
        assert_eq!(vc.to_string(), "ARM 64-bit UEFI (netboot)");
    }

    #[test]
    fn it_detects_nvidia_bf_oob_as_arm() {
        let vc: VendorClass = "NVIDIA/BF/OOB".parse().unwrap();
        assert_eq!(vc.to_string(), "ARM 64-bit UEFI (basic)");
    }

    #[test]
    fn it_detects_nvidia_bf_bmc_as_arm() {
        let vc: VendorClass = "NVIDIA/BF/BMC".parse().unwrap();
        assert_eq!(vc.to_string(), "ARM 64-bit UEFI (basic)");
    }

    #[test]
    fn it_formats_the_parser_legacypxe() {
        let vc: VendorClass = "PXEClient:Arch:00000:UNDI:003000".parse().unwrap();
        assert_eq!(vc.to_string(), "x86 BIOS (basic)");
    }
}
