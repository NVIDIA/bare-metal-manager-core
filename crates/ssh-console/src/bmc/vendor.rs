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

use std::borrow::Cow;

use bmc_vendor::BMCVendor;
use carbide_uuid::machine::MachineId;
use serde::{Deserialize, Deserializer, Serialize};

/// The escape sequence for IPMI is vendor-independent since it's specific to ipmitool.
pub static IPMITOOL_ESCAPE_SEQUENCE: EscapeSequence =
    EscapeSequence::Pair((b'~', &[b'.', b'B', b'?', 0x1a, 0x18]));

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum BmcVendor {
    Ssh(SshBmcVendor),
    Ipmi(IpmiBmcVendor),
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum IpmiBmcVendor {
    Supermicro,
    NvidiaViking,
}

impl IpmiBmcVendor {
    pub fn config_string(&self) -> &'static str {
        match self {
            IpmiBmcVendor::Supermicro => "supermicro",
            IpmiBmcVendor::NvidiaViking => "nvidia_viking",
        }
    }
}

/// BMC vendor-specific behavior around how to handle SSH connections:
/// - What prompt string is expected when at the BMC prompt
/// - The command to activate the serial console
/// - The escape sequence needed to exit the serial console
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum SshBmcVendor {
    /// Dell iDRAC - uses "connect com2" command and Ctrl+\ escape sequence
    Dell,
    /// Lenovo XClarity - uses "console kill 1\nconsole 1" command and ESC ( escape sequence
    Lenovo,
    /// Lenovo AMI - SSH login opens the console directly.
    LenovoAmi,
    /// HPE iLO - uses "vsp" command and ESC ( escape sequence
    Hpe,
    /// DPU, no commands needed, we just connect to port 2200 and get a console immediately.
    Dpu,
}

impl BmcVendor {
    pub fn detect_from_api_vendor(
        vendor_string: &str,
        machine_id: &MachineId,
    ) -> Result<Self, BmcVendorDetectionError> {
        if machine_id.machine_type().is_dpu() {
            return Ok(BmcVendor::Ssh(SshBmcVendor::Dpu));
        }

        Ok(match bmc_vendor::BMCVendor::from(vendor_string) {
            BMCVendor::Lenovo => BmcVendor::Ssh(SshBmcVendor::Lenovo),
            BMCVendor::LenovoAMI => BmcVendor::Ssh(SshBmcVendor::LenovoAmi),
            BMCVendor::Dell => BmcVendor::Ssh(SshBmcVendor::Dell),
            BMCVendor::Supermicro => BmcVendor::Ipmi(IpmiBmcVendor::Supermicro),
            BMCVendor::Hpe => BmcVendor::Ssh(SshBmcVendor::Hpe),
            BMCVendor::Nvidia => BmcVendor::Ipmi(IpmiBmcVendor::NvidiaViking),
            // Intentionally not doing a default `_` case so we get compiler errors (and can add more cases) later.
            // TODO: figure out what kind of connection power shelves use.
            BMCVendor::Liteon | BMCVendor::Delta | BMCVendor::Unknown => {
                return Err(BmcVendorDetectionError::UnknownSysVendor {
                    sys_vendor: vendor_string.to_owned(),
                });
            }
        })
    }

    pub fn from_config_string(s: &str) -> Option<Self> {
        if s == SshBmcVendor::Dell.config_string() {
            Some(BmcVendor::Ssh(SshBmcVendor::Dell))
        } else if s == SshBmcVendor::Lenovo.config_string() {
            Some(BmcVendor::Ssh(SshBmcVendor::Lenovo))
        } else if s == SshBmcVendor::LenovoAmi.config_string() {
            Some(BmcVendor::Ssh(SshBmcVendor::LenovoAmi))
        } else if s == SshBmcVendor::Hpe.config_string() {
            Some(BmcVendor::Ssh(SshBmcVendor::Hpe))
        } else if s == SshBmcVendor::Dpu.config_string() {
            Some(BmcVendor::Ssh(SshBmcVendor::Dpu))
        } else if s == IpmiBmcVendor::Supermicro.config_string() {
            Some(BmcVendor::Ipmi(IpmiBmcVendor::Supermicro))
        } else if s == IpmiBmcVendor::NvidiaViking.config_string() {
            Some(BmcVendor::Ipmi(IpmiBmcVendor::NvidiaViking))
        } else {
            None
        }
    }

    pub fn config_string(&self) -> &'static str {
        match self {
            BmcVendor::Ssh(v) => v.config_string(),
            BmcVendor::Ipmi(i) => i.config_string(),
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum BmcVendorDetectionError {
    #[error("Machine has no DMI data")]
    MissingDmiData,
    #[error("Unknown or unsupported sys_vendor string: {sys_vendor}")]
    UnknownSysVendor { sys_vendor: String },
}

impl Serialize for BmcVendor {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.config_string())
    }
}

impl<'de> Deserialize<'de> for BmcVendor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;

        let str_value = String::deserialize(deserializer)?;
        let Some(bmc_vendor) = Self::from_config_string(&str_value) else {
            return Err(Error::custom(format!("Invalid BMC vendor: {str_value}")));
        };
        Ok(bmc_vendor)
    }
}

impl SshBmcVendor {
    pub fn serial_activate_command(&self) -> Option<&'static [u8]> {
        match self {
            SshBmcVendor::Dell => Some(b"connect com2"),
            SshBmcVendor::Lenovo => Some(b"console kill 1\nconsole 1"),
            SshBmcVendor::LenovoAmi => None,
            SshBmcVendor::Hpe => Some(b"vsp"),
            SshBmcVendor::Dpu => None,
        }
    }

    pub fn bmc_prompt(&self) -> Option<&'static [u8]> {
        match self {
            SshBmcVendor::Dell => Some(b"\nracadm>>"),
            SshBmcVendor::Lenovo => Some(b"\nsystem>"),
            SshBmcVendor::LenovoAmi => None,
            SshBmcVendor::Hpe => Some(b"\n</>hpiLO->"),
            SshBmcVendor::Dpu => None,
        }
    }

    pub fn filter_escape_sequences<'a>(
        &self,
        input: &'a [u8],
        prev_pending: bool,
    ) -> (Cow<'a, [u8]>, bool) {
        self.escape_sequence()
            .map(|seq| seq.filter_escape_sequences(input, prev_pending))
            .unwrap_or((Cow::Borrowed(input), false))
    }

    fn escape_sequence(&self) -> Option<EscapeSequence> {
        match self {
            SshBmcVendor::Dell => Some(EscapeSequence::Single(0x1c)), // ctrl+\
            SshBmcVendor::Lenovo => Some(EscapeSequence::Pair((0x1b, &[0x28]))), // ESC (
            SshBmcVendor::LenovoAmi => None,
            SshBmcVendor::Hpe => Some(EscapeSequence::Pair((0x1b, &[0x28]))), // ESC (
            SshBmcVendor::Dpu => None,
        }
    }

    pub fn config_string(&self) -> &'static str {
        match self {
            SshBmcVendor::Dell => "dell",
            SshBmcVendor::Lenovo => "lenovo",
            SshBmcVendor::LenovoAmi => "lenovo_ami",
            SshBmcVendor::Hpe => "hpe",
            SshBmcVendor::Dpu => "dpu",
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
pub enum EscapeSequence {
    // A single one-byte escape (ie. ctrl+\)
    Single(u8),
    // A two-byte escape sequence, the latter of which can be one of several values.
    Pair((u8, &'static [u8])),
}

impl EscapeSequence {
    /// Scan `input`, remove any escape sequences (either 1-byte or 2-byte), and track whether the
    /// last byte was the start of a 2-byte escape.
    ///
    /// Each BMC vendor uses different escape sequences:
    // - Dell: Ctrl+\ (0x1c)
    // - Lenovo/HPE: ESC ( (0x1b 0x28)
    pub fn filter_escape_sequences<'a>(
        &self,
        input: &'a [u8],
        mut prev_pending: bool,
    ) -> (Cow<'a, [u8]>, bool) {
        // Helper to lazily get &mut Vec<u8>
        fn get_buf<'b>(out: &'b mut Option<Vec<u8>>, input: &[u8], idx: usize) -> &'b mut Vec<u8> {
            out.get_or_insert_with(|| {
                let mut v = Vec::with_capacity(input.len());
                v.extend_from_slice(&input[..idx]);
                v
            })
        }

        match self {
            EscapeSequence::Single(esc) => {
                // fast path: don't allocate if the whole string is clean.
                if !input.contains(esc) {
                    return (Cow::Borrowed(input), false);
                }
                // allocate once and filter
                let mut buf = Vec::with_capacity(input.len());
                for b in input {
                    if b != esc {
                        buf.push(*b);
                    }
                }
                (Cow::Owned(buf), false)
            }
            EscapeSequence::Pair((lead, trail)) => {
                let mut out: Option<Vec<u8>> = None;
                let mut i = 0;

                // handle pending from previous slice
                if prev_pending {
                    if let Some(b0) = input.first() {
                        if trail.contains(b0) {
                            // drop sequence
                            get_buf(&mut out, input, 0);
                            i = 1;
                        } else {
                            // false alarm: emit the lead
                            let buf = get_buf(&mut out, input, 0);
                            buf.push(*lead);
                        }
                    } else {
                        return (Cow::Borrowed(input), true);
                    }
                    prev_pending = false;
                }

                while i < input.len() {
                    // catch new adjacent escape windows in output
                    if let Some(buf) = &mut out {
                        // if this byte would create a lead+trail pair in the filtered output, drop it
                        if trail.contains(&input[i]) && buf.last() == Some(lead) {
                            prev_pending = true;
                            i += 1;
                            continue;
                        }
                    }
                    let b = input[i];
                    if b == *lead {
                        if i + 1 < input.len() {
                            if trail.contains(&input[i + 1]) {
                                // matched: drop both
                                get_buf(&mut out, input, i);
                                i += 2;
                                continue;
                            } else {
                                // not an escape: emit lead
                                let buf = get_buf(&mut out, input, i);
                                buf.push(b);
                                i += 1;
                                continue;
                            }
                        } else {
                            // lead at end: defer
                            get_buf(&mut out, input, i);
                            prev_pending = true;
                            break;
                        }
                    }
                    // normal byte
                    if let Some(buf) = &mut out {
                        buf.push(b);
                    }
                    i += 1;
                }

                if let Some(buf) = out {
                    (Cow::Owned(buf), prev_pending)
                } else {
                    (Cow::Borrowed(input), false)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use carbide_test_support::Outcome::*;
    use carbide_test_support::{scenarios, value_scenarios};

    use super::*;

    /// One row of the escape-sequence filtering table: which vendor escape to
    /// apply, the input bytes, and whether the previous slice ended mid-escape.
    struct FilterCase {
        escape: EscapeSequence,
        input: &'static [u8],
        prev_pending: bool,
    }

    /// The Lenovo/HPE two-byte escape (`ESC (`), used by most filtering rows.
    const ESC_PAREN: EscapeSequence = EscapeSequence::Pair((0x1b, &[0x28]));

    #[test]
    fn filter_escape_sequences_removes_escapes_and_tracks_pending() {
        // Each row runs `filter_escape_sequences`, projecting the borrowed/owned
        // `Cow` to an owned `Vec<u8>` so the asserted output and the pending flag
        // both stay visible per case.
        scenarios!(
            run = |FilterCase { escape, input, prev_pending }| {
                let (output, pending) = escape.filter_escape_sequences(input, prev_pending);
                Ok::<_, ()>((output.into_owned(), pending))
            };

            "ESC ( pass-through and pending lead" {
                FilterCase { escape: ESC_PAREN, input: b"hello world", prev_pending: false } => Yields((b"hello world".to_vec(), false)),
                FilterCase { escape: ESC_PAREN, input: b"hello world\x1b", prev_pending: false } => Yields((b"hello world".to_vec(), true)),
                FilterCase { escape: ESC_PAREN, input: b"\x1b", prev_pending: false } => Yields((b"".to_vec(), true)),
                FilterCase { escape: ESC_PAREN, input: b"hello world\x1b!", prev_pending: false } => Yields((b"hello world\x1b!".to_vec(), false)),
            }

            "ESC ( escape removed mid-stream" {
                FilterCase { escape: ESC_PAREN, input: b"hello \x1b\x28 world", prev_pending: false } => Yields((b"hello  world".to_vec(), false)),
                FilterCase { escape: ESC_PAREN, input: b"hello world\x1b\x28", prev_pending: false } => Yields((b"hello world".to_vec(), false)),
            }

            "ESC ( with a pending lead from the previous slice" {
                FilterCase { escape: ESC_PAREN, input: b"\x28", prev_pending: true } => Yields((b"".to_vec(), false)),
                FilterCase { escape: ESC_PAREN, input: b"Z", prev_pending: true } => Yields((b"\x1bZ".to_vec(), false)),
                FilterCase { escape: ESC_PAREN, input: b"hello world", prev_pending: true } => Yields((b"\x1bhello world".to_vec(), false)),
                FilterCase { escape: ESC_PAREN, input: b"\x28hello world", prev_pending: true } => Yields((b"hello world".to_vec(), false)),
                FilterCase { escape: ESC_PAREN, input: b"\x28hello world\x1b", prev_pending: true } => Yields((b"hello world".to_vec(), true)),
            }

            "single-byte (Dell ctrl+\\) escape removed" {
                FilterCase { escape: EscapeSequence::Single(0x1b), input: b"hello world", prev_pending: false } => Yields((b"hello world".to_vec(), false)),
                FilterCase { escape: EscapeSequence::Single(0x1c), input: b"hello \x1c world", prev_pending: false } => Yields((b"hello  world".to_vec(), false)),
                FilterCase { escape: EscapeSequence::Single(0x1c), input: b"hello world\x1c", prev_pending: false } => Yields((b"hello world".to_vec(), false)),
                FilterCase { escape: EscapeSequence::Single(0x1c), input: b"\x1chello world", prev_pending: false } => Yields((b"hello world".to_vec(), false)),
                FilterCase { escape: EscapeSequence::Single(0x1c), input: b"\x1c", prev_pending: false } => Yields((b"".to_vec(), false)),
            }

            "ipmitool multi-trail escape" {
                FilterCase { escape: IPMITOOL_ESCAPE_SEQUENCE, input: b"~~", prev_pending: false } => Yields((b"~".to_vec(), true)),
                FilterCase { escape: IPMITOOL_ESCAPE_SEQUENCE, input: b"~~~", prev_pending: false } => Yields((b"~~".to_vec(), true)),
                FilterCase { escape: IPMITOOL_ESCAPE_SEQUENCE, input: b"~~.", prev_pending: false } => Yields((b"~".to_vec(), false)),
                FilterCase { escape: IPMITOOL_ESCAPE_SEQUENCE, input: b"~.", prev_pending: false } => Yields((b"".to_vec(), false)),
                FilterCase { escape: IPMITOOL_ESCAPE_SEQUENCE, input: b"~B", prev_pending: false } => Yields((b"".to_vec(), false)),
                FilterCase { escape: IPMITOOL_ESCAPE_SEQUENCE, input: &[b'~', 0x1a], prev_pending: false } => Yields((b"".to_vec(), false)),
                FilterCase { escape: IPMITOOL_ESCAPE_SEQUENCE, input: &[b'~', 0x18], prev_pending: false } => Yields((b"".to_vec(), false)),
            }
        );

        // A clean stream is returned borrowed, with no allocation. This asserts a
        // structural property (the `Cow` variant) that the value table above can't
        // express, so it stays a hand-written check.
        assert!(matches!(
            ESC_PAREN.filter_escape_sequences(b"hello world", false).0,
            Cow::Borrowed(_)
        ));
        assert!(matches!(
            EscapeSequence::Single(0x1b)
                .filter_escape_sequences(b"hello world", false)
                .0,
            Cow::Borrowed(_)
        ));

        // Adjacent escapes must not leave a reconstructable `ESC (` pair in the
        // output; assert that absence directly rather than the exact bytes.
        assert!(
            !ESC_PAREN
                .filter_escape_sequences(&[0x1b, 0x1b, 0x28, 0x28], false)
                .0
                .windows(2)
                .any(|w| w[0] == 0x1b && w[1] == 0x28)
        );
        assert!(
            !ESC_PAREN
                .filter_escape_sequences(&[0x1b, 0x28, 0x28], true)
                .0
                .windows(2)
                .any(|w| w[0] == 0x1b && w[1] == 0x28)
        );
    }

    /// Wraps a [`BmcVendor`] in a struct field so its custom serde is exercised
    /// through a real (de)serializer; the field is a plain TOML string.
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Wrap {
        vendor: BmcVendor,
    }

    const ALL_VENDORS: [(BmcVendor, &str); 7] = [
        (BmcVendor::Ssh(SshBmcVendor::Dell), "dell"),
        (BmcVendor::Ssh(SshBmcVendor::Lenovo), "lenovo"),
        (BmcVendor::Ssh(SshBmcVendor::LenovoAmi), "lenovo_ami"),
        (BmcVendor::Ssh(SshBmcVendor::Hpe), "hpe"),
        (BmcVendor::Ssh(SshBmcVendor::Dpu), "dpu"),
        (BmcVendor::Ipmi(IpmiBmcVendor::Supermicro), "supermicro"),
        (
            BmcVendor::Ipmi(IpmiBmcVendor::NvidiaViking),
            "nvidia_viking",
        ),
    ];

    #[test]
    fn bmc_vendor_config_string_names_each_variant() {
        // Driven from `ALL_VENDORS` so a new variant is covered by adding one row there.
        for (vendor, config_string) in ALL_VENDORS {
            assert_eq!(vendor.config_string(), config_string, "{vendor:?}");
        }
    }

    #[test]
    fn bmc_vendor_from_config_string_parses_each_variant() {
        // Driven from `ALL_VENDORS` so a new variant is covered by adding one row there.
        for (vendor, config_string) in ALL_VENDORS {
            assert_eq!(
                BmcVendor::from_config_string(config_string),
                Some(vendor),
                "{config_string:?}",
            );
        }

        value_scenarios!(
            run = |s: &str| BmcVendor::from_config_string(s);

            "an unknown string has no vendor" {
                "" => None,
                "bogus" => None,
            }
        );
    }

    #[test]
    fn bmc_vendor_config_string_round_trips() {
        // config_string -> from_config_string returns the same vendor for every variant.
        for (vendor, _) in ALL_VENDORS {
            assert_eq!(
                BmcVendor::from_config_string(vendor.config_string()),
                Some(vendor),
                "{vendor:?}",
            );
        }
    }

    #[test]
    fn bmc_vendor_serde_round_trips_through_toml() {
        // The custom Serialize/Deserialize go through a real TOML (de)serializer.
        for (vendor, config_string) in ALL_VENDORS {
            let label = format!("{vendor:?}");
            let wrap = Wrap { vendor };
            let serialized = toml::to_string(&wrap).expect("serialize");
            assert_eq!(
                serialized,
                format!("vendor = \"{config_string}\"\n"),
                "{label}"
            );
            let deserialized: Wrap = toml::from_str(&serialized).expect("deserialize");
            assert_eq!(deserialized, wrap, "{label}");
        }
    }

    #[test]
    fn bmc_vendor_deserialize_rejects_an_unknown_string() {
        scenarios!(
            run = |s: &str| toml::from_str::<Wrap>(&format!("vendor = \"{s}\"")).map_err(|e| e.to_string());

            "valid config strings deserialize" {
                "dell" => Yields(Wrap { vendor: BmcVendor::Ssh(SshBmcVendor::Dell) }),
                "nvidia_viking" => Yields(Wrap { vendor: BmcVendor::Ipmi(IpmiBmcVendor::NvidiaViking) }),
            }

            "an unknown string is rejected" {
                "bogus" => Fails,
            }
        );
    }
}
