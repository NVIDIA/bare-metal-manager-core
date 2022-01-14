use crate::ByteUnit;

macro_rules! parse_suffix_fn {
    ($($suffix:ident),*) => (
        parse_suffix_fn!($($suffix, stringify!($suffix)),*);
    );
    ($($suffix:ident, $string:expr),*) => (
        fn parse_suffix(string: &str) -> Option<ByteUnit> {
            $(if string.eq_ignore_ascii_case($string) {
                return Some(ByteUnit::$suffix);
            })*

            None
        }
    );
}

parse_suffix_fn!(B, kB, KiB, MB, MiB, GB, GiB, TB, TiB, PB, PiB, EB, EiB);

fn is_suffix_char(c: char) -> bool {
    "begikmpt ".contains(c.to_ascii_lowercase())
}

/// Parsing error, as returned by
/// [`ByteUnit::from_str()`](struct.ByteUnit.html#impl-FromStr).
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum Error {
    /// The input was empty.
    Empty,
    /// Found unexpected character `.1` at byte index `.0`.
    Unexpected(usize, char),
    /// A [`ByteUnit::B`] contained a fractional component.
    FractionalByte,
    /// The parsed byte unit suffix is unknown.
    BadSuffix,
    /// The whole part of the the number (`{whole}.{frac}`) was invalid.
    BadWhole(core::num::ParseIntError),
    /// The fractional part of the the number (`{whole}.{frac}`) was invalid.
    BadFractional(core::num::ParseIntError),
}

impl core::str::FromStr for ByteUnit {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() { return Err(Error::Empty); }
        let (mut dot, mut suffix) = (None, None);
        for (i, c) in s.chars().enumerate() {
            match c {
                c if c.is_ascii_digit() && suffix.is_none() => continue,
                '.' if dot.is_none() && suffix.is_none() => dot = Some(i),
                c if is_suffix_char(c) && suffix.is_none() => suffix = Some(i),
                c if is_suffix_char(c) => continue,
                _ => Err(Error::Unexpected(i, c))?
            }
        }

        // We can't start with `.` or a suffix character.
        if dot.map(|i| i == 0).unwrap_or(false) || suffix.map(|i| i == 0).unwrap_or(false) {
            return Err(Error::Unexpected(0, s.as_bytes()[0] as char));
        }

        // Parse the suffix. A fractional doesn't make sense for bytes.
        let suffix_str = suffix.map(|i| s[i..].trim_start()).unwrap_or("b");
        let unit = parse_suffix(suffix_str).ok_or(Error::BadSuffix)?;
        if unit == ByteUnit::B && dot.is_some() {
            return Err(Error::FractionalByte);
        }

        let num_end = suffix.unwrap_or(s.len());
        match dot {
            Some(i) => {
                let frac_str = &s[(i + 1)..num_end];
                let whole: u64 = s[..i].parse().map_err(Error::BadWhole)?;
                let frac: u32 = frac_str.parse().map_err(Error::BadFractional)?;
                let frac_part = frac as f64 / 10u64.pow(frac_str.len() as u32) as f64;
                let frac_unit = (frac_part * unit.as_u64() as f64) as u64;
                Ok(whole * unit + frac_unit)
            }
            None => {
                let whole: u64 = s[..num_end].parse().map_err(Error::BadWhole)?;
                Ok(whole * unit)
            }
        }
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use Error::*;
        match self {
            Empty => write!(f, "the input was empty"),
            Unexpected(i, c) => write!(f, "unexpected character {:?} at index `{}`", c, i),
            FractionalByte => write!(f, "unit `B` cannot have a fractional component"),
            BadSuffix => write!(f, "unknown or malformed byte unit suffix"),
            BadWhole(e) => write!(f, "whole part failed to parse: {}", e),
            BadFractional(e) => write!(f, "fractional part failed to parse: {}", e),
        }
    }
}

#[cfg(test)]
mod parse_tests {
    use core::str::FromStr;
    use crate::{ByteUnit, ToByteUnit};

    macro_rules! assert_reject {
        ($($s:expr),* $(,)?) => ($(
            let result = ByteUnit::from_str($s);
            assert!(result.is_err(), "{:?} parsed as {}", $s, result.unwrap());
        )*)
    }

    macro_rules! assert_parses {
        ($($s:expr => $b:expr),* $(,)?) => ($(
            let result = ByteUnit::from_str($s);
            assert!(result.is_ok(), "{:?} failed to parse: {}", $s, result.unwrap_err());
            let actual = result.unwrap();
            assert_eq!(actual, $b, "expected {}, got {}", $b, actual);
        )*)
    }

    #[test]
    fn reject() {
        assert_reject!["", "a", "amb", "1.2", ".", ".23KiB", "1.2.3mb", "1.23bcc"];
        assert_reject!["?mb", "1.2mb.", ".2mb", "99k", "99bk", "1 k b"];
        assert_reject!["1.2mkb", "1kb2", "1MB ", " 1MB"];
        assert_reject!["287423890740938348498349344"];
        assert_reject!["1.kb", "1.", "1. ", "2. kb"];
    }

    #[test]
    fn accept() {
        assert_parses! {
            "1" => 1.bytes(),
            "123" => 123.bytes(),
            "99" => 99.bytes(),
            "2394394" => 2394394.bytes(),
            "2874238907409384" => 2874238907409384u64.bytes(),
        }

        assert_parses! {
            "1 b" => 1.bytes(),
            "1 B" => 1.bytes(),
            "1B" => 1.bytes(),
            "1b" => 1.bytes(),
            "1 mb" => 1.megabytes(),
            "1 mib" => 1.mebibytes(),
            "1mib" => 1.mebibytes(),
            "1 kb" => 1.kilobytes(),
            "1 kB" => 1.kilobytes(),
            "1 kib" => 1.kibibytes(),
            "1kib" => 1.kibibytes(),
            "1KiB" => 1.kibibytes(),
            "1GB" => 1.gigabytes(),

            "349 b" => 349.bytes(),
            "13489 mb" => 13489.megabytes(),
            "349b" => 349.bytes(),
            "13489mb" => 13489.megabytes(),
        }

        assert_parses! {
            "0.5KiB" => 512.bytes(),
            "0.5KB" => 500.bytes(),
        }

        assert_parses! {
            "323kB" => 323.kilobytes(),
            "3MB" => 3.megabytes(),
            "3MiB" => 3.mebibytes(),
            "8GiB" => 8.gibibytes(),

            "5MiB" => 3.mebibytes() + 2.mebibytes(),
            "7.06GB" => 7.gigabytes() + 60.megabytes(),
            "7.25GB" => 7.gigabytes() + 250.megabytes(),

            "01MB" => 1.megabytes(),
            "0001MiB" => 1.mebibytes(),
        }
    }
}
