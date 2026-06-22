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
pub enum VendorClassParseError {}

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
    use carbide_test_support::Outcome::*;
    use carbide_test_support::{Case, check_cases, value_scenarios};

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

    /// The full boot-relevant classification a parsed vendor class resolves to:
    /// architecture (`arm`/`x64`), whether it asks for HTTP `netboot`, and whether
    /// it is a `modern` (netboot ARM-UEFI) client.
    #[derive(Debug, PartialEq)]
    struct Classification {
        arm: bool,
        x64: bool,
        netboot: bool,
        modern: bool,
    }

    impl Classification {
        fn of(vc: &VendorClass) -> Self {
            Self {
                arm: vc.arm(),
                x64: vc.x64(),
                netboot: vc.is_netboot(),
                modern: vc.is_it_modern(),
            }
        }
    }

    /// Every vendor-class string we recognize, pinned to its full classification.
    /// One row per input -- a `PXEClient` x64 UEFI, an OS-form `aarch64` DPU, an
    /// `HTTPClient` netboot, a bare BMC id -- so a parse covers all four predicates
    /// at once instead of one assertion apiece.
    #[test]
    fn classifies_each_vendor_class() {
        check_cases(
            [
                Case {
                    scenario: "x64 UEFI PXEClient",
                    input: "PXEClient:Arch:00007:UNDI:003000",
                    expect: Yields(Classification {
                        arm: false,
                        x64: true,
                        netboot: false,
                        modern: false,
                    }),
                },
                Case {
                    scenario: "Dell iDRAC BMC (x64)",
                    input: "iDRAC",
                    expect: Yields(Classification {
                        arm: false,
                        x64: true,
                        netboot: false,
                        modern: false,
                    }),
                },
                Case {
                    scenario: "bare PXEClient iPXE response (arm)",
                    input: "PXEClient",
                    expect: Yields(Classification {
                        arm: true,
                        x64: false,
                        netboot: false,
                        modern: false,
                    }),
                },
                Case {
                    scenario: "OS-form aarch64 DPU",
                    input: "nvidia-bluefield-dpu aarch64",
                    expect: Yields(Classification {
                        arm: true,
                        x64: false,
                        netboot: false,
                        modern: false,
                    }),
                },
                Case {
                    scenario: "legacy BF2 card",
                    input: "BF2Client",
                    expect: Yields(Classification {
                        arm: true,
                        x64: false,
                        netboot: false,
                        modern: false,
                    }),
                },
                Case {
                    scenario: "ARM UEFI PXEClient (not netboot)",
                    input: "PXEClient:Arch:00011:UNDI:003000",
                    expect: Yields(Classification {
                        arm: true,
                        x64: false,
                        netboot: false,
                        modern: false,
                    }),
                },
                Case {
                    scenario: "ARM UEFI HTTPClient is modern netboot",
                    input: "HTTPClient:Arch:00011:UNDI:003000",
                    expect: Yields(Classification {
                        arm: true,
                        x64: false,
                        netboot: true,
                        modern: true,
                    }),
                },
                Case {
                    scenario: "x64 HTTPClient netboots but is not modern",
                    input: "HTTPClient:Arch:00016:UNDI:003001",
                    expect: Yields(Classification {
                        arm: false,
                        x64: true,
                        netboot: true,
                        modern: false,
                    }),
                },
            ],
            |input| {
                input
                    .parse::<VendorClass>()
                    .map(|vc| Classification::of(&vc))
                    .map_err(|_| "parse failed")
            },
        );
    }

    /// The human-readable `VendorClass` `Display`: `"<arch> (<netboot|basic>)"`.
    #[test]
    fn formats_vendor_class_display() {
        value_scenarios!(run = |input: &str| input.parse::<VendorClass>().unwrap().to_string();
            "basic (non-netboot) clients" {
                "NothingClient:Arch:00011:UNDI:X" => "ARM 64-bit UEFI (basic)".to_string(),
                "NVIDIA/BF/OOB" => "ARM 64-bit UEFI (basic)".to_string(),
                "NVIDIA/BF/BMC" => "ARM 64-bit UEFI (basic)".to_string(),
                "PXEClient:Arch:00000:UNDI:003000" => "x86 BIOS (basic)".to_string(),
            }

            "netboot clients" {
                "HTTPClient:Arch:00011:UNDI:003000" => "ARM 64-bit UEFI (netboot)".to_string(),
            }
        );
    }

    /// `MachineArchitecture::from_str` maps DHCP option-93 architecture codes (base
    /// 10, as the long vendor class spells them) to an architecture. It never errors
    /// -- an unrecognized or non-numeric code resolves to `Unknown` so we still vend
    /// an address. Exercised directly here rather than only through `VendorClass`.
    #[test]
    fn maps_architecture_codes() {
        value_scenarios!(run = |input: &str| MachineArchitecture::from_str(input).unwrap();
            "x86 BIOS" {
                "00000" => MachineArchitecture::BiosX86,
            }

            "x64 UEFI" {
                "00007" => MachineArchitecture::EfiX64,
                "00016" => MachineArchitecture::EfiX64,
            }

            "ARM 64-bit" {
                "00011" => MachineArchitecture::Arm64,
                "00019" => MachineArchitecture::Arm64,
                "aarch64" => MachineArchitecture::Arm64,
            }

            "unknown" {
                "00042" => MachineArchitecture::Unknown,
                "not-a-number" => MachineArchitecture::Unknown,
            }
        );
    }

    /// The `MachineArchitecture` `Display` strings, which the `VendorClass` `Display`
    /// is built from.
    #[test]
    fn formats_architecture_display() {
        value_scenarios!(run = |arch: MachineArchitecture| arch.to_string();
            "architecture labels" {
                MachineArchitecture::Arm64 => "ARM 64-bit UEFI".to_string(),
                MachineArchitecture::EfiX64 => "x64 UEFI".to_string(),
                MachineArchitecture::BiosX86 => "x86 BIOS".to_string(),
                MachineArchitecture::Unknown => "Unknown".to_string(),
            }
        );
    }
}
