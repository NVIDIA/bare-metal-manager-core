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

use rpc::forge;
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
    /// HPE iLO - uses "vsp" command and ESC ( escape sequence
    Hpe,
    /// DPU, no commands needed, we just connect to port 2200 and get a console immediately.
    Dpu,
}

impl BmcVendor {
    pub fn detect_from_api_machine(
        machine: &forge::Machine,
    ) -> Result<Self, BmcVendorDetectionError> {
        let Some(dmi_data) = machine
            .discovery_info
            .as_ref()
            .and_then(|d| d.dmi_data.as_ref())
        else {
            return Err(BmcVendorDetectionError::MissingDmiData);
        };

        let sys_vendor = &dmi_data.sys_vendor;

        // Vendor string data here ultimately comes from DMI data, via the `sys_vendor` field.
        let vendor = if sys_vendor.contains("Dell") {
            BmcVendor::Ssh(SshBmcVendor::Dell)
        } else if sys_vendor.contains("Lenovo") {
            BmcVendor::Ssh(SshBmcVendor::Lenovo)
        } else if sys_vendor.contains("HPE") || sys_vendor.contains("Hewlett") {
            BmcVendor::Ssh(SshBmcVendor::Hpe)
        } else if sys_vendor.contains("Supermicro") {
            BmcVendor::Ipmi(IpmiBmcVendor::Supermicro)
        } else if sys_vendor.contains("NVIDIA") {
            if dmi_data.product_name.contains("DGX") {
                BmcVendor::Ipmi(IpmiBmcVendor::NvidiaViking)
            } else {
                BmcVendor::Ssh(SshBmcVendor::Dpu)
            }
        } else {
            return Err(BmcVendorDetectionError::UnknownSysVendor {
                sys_vendor: sys_vendor.to_owned(),
            });
        };

        Ok(vendor)
    }

    pub fn from_config_string(s: &str) -> Option<Self> {
        if s == SshBmcVendor::Dell.config_string() {
            Some(BmcVendor::Ssh(SshBmcVendor::Dell))
        } else if s == SshBmcVendor::Lenovo.config_string() {
            Some(BmcVendor::Ssh(SshBmcVendor::Lenovo))
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
            SshBmcVendor::Hpe => Some(b"vsp"),
            SshBmcVendor::Dpu => None,
        }
    }

    pub fn bmc_prompt(&self) -> Option<&'static [u8]> {
        match self {
            SshBmcVendor::Dell => Some(b"\nracadm>>"),
            SshBmcVendor::Lenovo => Some(b"\nsystem>"),
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
            SshBmcVendor::Hpe => Some(EscapeSequence::Pair((0x1b, &[0x28]))), // ESC (
            SshBmcVendor::Dpu => None,
        }
    }

    pub fn config_string(&self) -> &'static str {
        match self {
            SshBmcVendor::Dell => "dell",
            SshBmcVendor::Lenovo => "lenovo",
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
            if out.is_none() {
                let mut v = Vec::with_capacity(input.len());
                v.extend_from_slice(&input[..idx]);
                *out = Some(v);
            }
            out.as_mut().unwrap()
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

#[test]
fn test_filter_escape_sequence() {
    // Pass-through: no escapes
    {
        let result =
            EscapeSequence::Pair((0x1b, &[0x28])).filter_escape_sequences(b"hello world", false);
        assert_eq!(result, (Cow::Borrowed(b"hello world".as_slice()), false));
        // Make sure we don't allocate
        assert!(matches!(result.0, Cow::Borrowed(_)));
    }

    // Only a trailing pending escape byte
    assert_eq!(
        EscapeSequence::Pair((0x1b, &[0x28])).filter_escape_sequences(b"hello world\x1b", false),
        (Cow::Borrowed(b"hello world".as_slice()), true)
    );

    assert_eq!(
        EscapeSequence::Pair((0x1b, &[0x28])).filter_escape_sequences(b"\x28", true),
        (Cow::Borrowed(b"".as_slice()), false)
    );

    assert!(
        !EscapeSequence::Pair((0x1b, &[0x28]))
            .filter_escape_sequences(&[0x1b, 0x1b, 0x28, 0x28], false)
            .0
            .windows(2)
            .any(|w| w[0] == 0x1b && w[1] == 0x28)
    );

    assert!(
        !EscapeSequence::Pair((0x1b, &[0x28]))
            .filter_escape_sequences(&[0x1b, 0x28, 0x28], true)
            .0
            .windows(2)
            .any(|w| w[0] == 0x1b && w[1] == 0x28)
    );

    assert_eq!(
        EscapeSequence::Pair((0x1b, &[0x28])).filter_escape_sequences(b"\x1b", false),
        (Cow::Borrowed(b"".as_slice()), true)
    );

    assert_eq!(
        EscapeSequence::Pair((0x1b, &[0x28])).filter_escape_sequences(b"hello world\x1b!", false),
        (Cow::Borrowed(b"hello world\x1b!".as_slice()), false)
    );

    assert_eq!(
        EscapeSequence::Pair((0x1b, &[0x28]))
            .filter_escape_sequences(b"hello \x1b\x28 world", false),
        (Cow::Borrowed(b"hello  world".as_slice()), false)
    );

    assert_eq!(
        EscapeSequence::Pair((0x1b, &[0x28]))
            .filter_escape_sequences(b"hello world\x1b\x28", false),
        (Cow::Borrowed(b"hello world".as_slice()), false)
    );

    assert_eq!(
        EscapeSequence::Pair((0x1b, &[0x28])).filter_escape_sequences(b"Z", true),
        (Cow::Borrowed(b"\x1bZ".as_slice()), false)
    );

    assert_eq!(
        EscapeSequence::Pair((0x1b, &[0x28])).filter_escape_sequences(b"hello world", true),
        (Cow::Borrowed(b"\x1bhello world".as_slice()), false)
    );

    assert_eq!(
        EscapeSequence::Pair((0x1b, &[0x28])).filter_escape_sequences(b"\x28hello world", true),
        (Cow::Borrowed(b"hello world".as_slice()), false)
    );

    assert_eq!(
        EscapeSequence::Pair((0x1b, &[0x28])).filter_escape_sequences(b"\x28hello world\x1b", true),
        (Cow::Borrowed(b"hello world".as_slice()), true)
    );

    {
        let result = EscapeSequence::Single(0x1b).filter_escape_sequences(b"hello world", false);
        assert_eq!(result, (Cow::Borrowed(b"hello world".as_slice()), false));
        // Make sure we don't allocate if there's no sequence
        assert!(matches!(result.0, Cow::Borrowed(_)))
    }

    assert_eq!(
        EscapeSequence::Single(0x1c).filter_escape_sequences(b"hello \x1c world", false),
        (Cow::Borrowed(b"hello  world".as_slice()), false)
    );

    assert_eq!(
        EscapeSequence::Single(0x1c).filter_escape_sequences(b"hello world\x1c", false),
        (Cow::Borrowed(b"hello world".as_slice()), false)
    );

    assert_eq!(
        EscapeSequence::Single(0x1c).filter_escape_sequences(b"\x1chello world", false),
        (Cow::Borrowed(b"hello world".as_slice()), false)
    );

    assert_eq!(
        EscapeSequence::Single(0x1c).filter_escape_sequences(b"\x1c", false),
        (Cow::Borrowed(b"".as_slice()), false)
    );

    let ipmitool_escape_sequence = IPMITOOL_ESCAPE_SEQUENCE;
    assert_eq!(
        ipmitool_escape_sequence.filter_escape_sequences(b"~~", false),
        (Cow::Borrowed(b"~".as_slice()), true)
    );

    assert_eq!(
        ipmitool_escape_sequence.filter_escape_sequences(b"~~~", false),
        (Cow::Borrowed(b"~~".as_slice()), true)
    );

    assert_eq!(
        ipmitool_escape_sequence.filter_escape_sequences(b"~~.", false),
        (Cow::Borrowed(b"~".as_slice()), false)
    );

    assert_eq!(
        ipmitool_escape_sequence.filter_escape_sequences(b"~.", false),
        (Cow::Borrowed(b"".as_slice()), false)
    );

    assert_eq!(
        ipmitool_escape_sequence.filter_escape_sequences(b"~B", false),
        (Cow::Borrowed(b"".as_slice()), false)
    );

    assert_eq!(
        ipmitool_escape_sequence.filter_escape_sequences(&[b'~', 0x1a], false),
        (Cow::Borrowed(b"".as_slice()), false)
    );

    assert_eq!(
        ipmitool_escape_sequence.filter_escape_sequences(&[b'~', 0x18], false),
        (Cow::Borrowed(b"".as_slice()), false)
    );
}
