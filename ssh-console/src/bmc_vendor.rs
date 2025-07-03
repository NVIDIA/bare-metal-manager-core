/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::str::FromStr;

#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq)]
// TODO: IPMI serial support. Currently only supports vendors which can be SSH'd into.
/// BMC vendor-specific behavior around:
/// - What prompt string is expected when at the BMC prompt
/// - The command to activate the serial console
/// - The escape sequence needed to exit the serial console
pub enum BmcVendor {
    /// Dell iDRAC - uses "connect com2" command and Ctrl+\ escape sequence
    Dell,
    /// Lenovo XClarity - uses "console kill 1\nconsole 1" command and ESC ( escape sequence
    Lenovo,
    /// HPE iLO - uses "vsp" command and ESC ( escape sequence
    Hpe,
}

impl FromStr for BmcVendor {
    type Err = eyre::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Vendor string data here ultimately comes from DMI data, via the `sys_vendor` field.
        if s.contains("Dell") {
            Ok(BmcVendor::Dell)
        } else if s.contains("Lenovo") {
            Ok(BmcVendor::Lenovo)
        } else if s.contains("HPE") || s.contains("Hewlett") {
            Ok(BmcVendor::Hpe)
        } else {
            Err(eyre::format_err!("Unknown vendor string: {s:?}"))
        }
    }
}

impl BmcVendor {
    pub fn serial_activate_command(&self) -> &'static [u8] {
        match self {
            BmcVendor::Dell => b"connect com2",
            BmcVendor::Lenovo => b"console kill 1\nconsole 1",
            BmcVendor::Hpe => b"vsp",
        }
    }

    pub fn bmc_prompt(&self) -> &'static [u8] {
        match self {
            BmcVendor::Dell => b"\nracadm>>",
            BmcVendor::Lenovo => b"\nsystem>",
            BmcVendor::Hpe => b"\nhpiLO->",
        }
    }

    pub fn filter_escape_sequences<'a>(
        &self,
        input: &'a [u8],
        prev_pending: bool,
    ) -> (Cow<'a, [u8]>, bool) {
        self.escape_sequence()
            .filter_escape_sequences(input, prev_pending)
    }

    fn escape_sequence(&self) -> EscapeSequence {
        match self {
            BmcVendor::Dell => EscapeSequence::Single(0x1c), // ctrl+\
            BmcVendor::Lenovo => EscapeSequence::Pair((0x1b, 0x28)), // ESC (
            BmcVendor::Hpe => EscapeSequence::Pair((0x1b, 0x28)), // ESC (
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
pub enum EscapeSequence {
    Single(u8),
    Pair((u8, u8)),
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

        match *self {
            EscapeSequence::Single(esc) => {
                // fast path: don't allocate if the whole string is clean.
                if !input.contains(&esc) {
                    return (Cow::Borrowed(input), false);
                }
                // allocate once and filter
                let mut buf = Vec::with_capacity(input.len());
                for &b in input {
                    if b != esc {
                        buf.push(b);
                    }
                }
                (Cow::Owned(buf), false)
            }
            EscapeSequence::Pair((lead, trail)) => {
                let mut out: Option<Vec<u8>> = None;
                let mut i = 0;

                // handle pending from previous slice
                if prev_pending {
                    if let Some(&b0) = input.first() {
                        if b0 == trail {
                            // drop sequence
                            get_buf(&mut out, input, 0);
                            i = 1;
                        } else {
                            // false alarm: emit the lead
                            let buf = get_buf(&mut out, input, 0);
                            buf.push(lead);
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
                        if input[i] == trail && buf.last() == Some(&lead) {
                            prev_pending = true;
                            i += 1;
                            continue;
                        }
                    }
                    let b = input[i];
                    if b == lead {
                        if i + 1 < input.len() {
                            if input[i + 1] == trail {
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
            EscapeSequence::Pair((0x1b, 0x28)).filter_escape_sequences(b"hello world", false);
        assert_eq!(result, (Cow::Borrowed(b"hello world".as_slice()), false));
        // Make sure we don't allocate
        assert!(matches!(result.0, Cow::Borrowed(_)));
    }

    // Only a trailing pending escape byte
    assert_eq!(
        EscapeSequence::Pair((0x1b, 0x28)).filter_escape_sequences(b"hello world\x1b", false),
        (Cow::Borrowed(b"hello world".as_slice()), true)
    );

    assert_eq!(
        EscapeSequence::Pair((0x1b, 0x28)).filter_escape_sequences(b"\x28", true),
        (Cow::Borrowed(b"".as_slice()), false)
    );

    assert!(
        !EscapeSequence::Pair((0x1b, 0x28))
            .filter_escape_sequences(&[0x1b, 0x1b, 0x28, 0x28], false)
            .0
            .windows(2)
            .any(|w| w[0] == 0x1b && w[1] == 0x28)
    );

    assert!(
        !EscapeSequence::Pair((0x1b, 0x28))
            .filter_escape_sequences(&[0x1b, 0x28, 0x28], true)
            .0
            .windows(2)
            .any(|w| w[0] == 0x1b && w[1] == 0x28)
    );

    assert_eq!(
        EscapeSequence::Pair((0x1b, 0x28)).filter_escape_sequences(b"\x1b", false),
        (Cow::Borrowed(b"".as_slice()), true)
    );

    assert_eq!(
        EscapeSequence::Pair((0x1b, 0x28)).filter_escape_sequences(b"hello world\x1b!", false),
        (Cow::Borrowed(b"hello world\x1b!".as_slice()), false)
    );

    assert_eq!(
        EscapeSequence::Pair((0x1b, 0x28)).filter_escape_sequences(b"hello \x1b\x28 world", false),
        (Cow::Borrowed(b"hello  world".as_slice()), false)
    );

    assert_eq!(
        EscapeSequence::Pair((0x1b, 0x28)).filter_escape_sequences(b"hello world\x1b\x28", false),
        (Cow::Borrowed(b"hello world".as_slice()), false)
    );

    assert_eq!(
        EscapeSequence::Pair((0x1b, 0x28)).filter_escape_sequences(b"Z", true),
        (Cow::Borrowed(b"\x1bZ".as_slice()), false)
    );

    assert_eq!(
        EscapeSequence::Pair((0x1b, 0x28)).filter_escape_sequences(b"hello world", true),
        (Cow::Borrowed(b"\x1bhello world".as_slice()), false)
    );

    assert_eq!(
        EscapeSequence::Pair((0x1b, 0x28)).filter_escape_sequences(b"\x28hello world", true),
        (Cow::Borrowed(b"hello world".as_slice()), false)
    );

    assert_eq!(
        EscapeSequence::Pair((0x1b, 0x28)).filter_escape_sequences(b"\x28hello world\x1b", true),
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
}
