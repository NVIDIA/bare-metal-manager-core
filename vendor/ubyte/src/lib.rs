#![no_std]

//! A simple, complete, `const`-everything, saturating, human-friendly,
//! `#![no_std]` library for byte units.
//!
//! ```rust
//! use ubyte::{ByteUnit, ToByteUnit};
//!
//! // Constructors and associated units for all SI units up to exbibyte.
//! let half_mb = 500.kilobytes();
//! let half_mb = ByteUnit::Kilobyte(500);
//! let half_mb = 500 * ByteUnit::kB;
//!
//! // All arithmetic operations and conversions saturate.
//! let exbibyte_too_large_a = 1024 * ByteUnit::EiB;
//! let exbibyte_too_large_b = ByteUnit::Exbibyte(1024);
//! let exbibyte_too_large_c = 1024.exbibytes();
//! assert_eq!(exbibyte_too_large_a, ByteUnit::max_value());
//! assert_eq!(exbibyte_too_large_b, ByteUnit::max_value());
//! assert_eq!(exbibyte_too_large_c, ByteUnit::max_value());
//!
//! // Printing is human-friendly and customizeable.
//! assert_eq!(323.kilobytes().to_string(), "323kB");
//! assert_eq!(3.mebibytes().to_string(), "3MiB");
//! assert_eq!((7.gigabytes() + 58.mebibytes() + 3.kilobytes()).to_string(), "7.06GB");
//! assert_eq!(format!("{:.0}", 7.gibibytes() + 920.mebibytes()), "8GiB");
//! assert_eq!(format!("{:.3}", 7.gibibytes() + 920.mebibytes()), "7.898GiB");
//! assert_eq!(format!("{:04.2}", 999.kilobytes() + 990.bytes()), "0976.55KiB");
//! assert_eq!(format!("{:02.0}", 999.kilobytes() + 990.bytes()), "01MB");
//!
//! // Parsing is intuitive. Explicit `ByteUnit` is typically unnecessary.
//! assert_eq!("10 KiB".parse::<ByteUnit>().unwrap(), 10.kibibytes());
//! assert_eq!("10 kb".parse::<ByteUnit>().unwrap(), 10.kilobytes());
//! assert_eq!("512Kb".parse::<ByteUnit>().unwrap(), 512.kilobytes());
//! assert_eq!("99kb".parse::<ByteUnit>().unwrap(), 99.kilobytes());
//! assert_eq!("1 MiB".parse::<ByteUnit>().unwrap(), 1.mebibytes());
//! assert_eq!("1.5 MiB".parse::<ByteUnit>().unwrap(), 1.mebibytes() + 512.kibibytes());
//! assert_eq!("0.2MB".parse::<ByteUnit>().unwrap(), 200.kilobytes());
//! assert_eq!("7.25 gb".parse::<ByteUnit>().unwrap(), 7.gigabytes() + 250.megabytes());
//! ```
//!
//! # Overview
//!
//! * [`ByteUnit`] constructors -- [`ByteUnit::Byte`] and friends -- for all SI
//! units of bytes up to the exbibyte are provided; all constructors are `const`
//! and saturating. Associated constants -- [`ByteUnit::B`] and friends -- for
//! `1`-valued units are provided. Saturating arithmetic operations between
//! `ByteUnit` and all integers types are implemented. `From<{integer}> for
//! ByteUnit` for all integer types is implemented. `From<ByteUnit> for {u64,
//! u128}>` is implemented.
//!
//! * [`ToByteUnit`] provides human-friendly methods on all integer types for
//! converting into a `ByteUnit`: [`512.kilobytes()`](ToByteUnit::kilobytes).
//!
//! * The [`Display`](struct.ByteUnit.html#impl-Display) implementation displays
//! `ByteUnit`s in a human-friendly format. For truly custom printing,
//! [`ByteUnit::repr()`] splits a value into its minimal components.
//!
//! * The [`FromStr`](struct.ByteUnit.html#impl-FromStr) implementation parses
//! byte units in a case-free manner: `1B` or `1b` or `1 b` => `1.bytes()`.
//!
//! * With the `serde` feaure enabled (disabled by default), `ByteUnit`
//! implements [`Deserialize`](struct.ByteUnit.html#impl-Deserialize<%27de>)
//! from strings and all integer types as well as
//! [`Serialize`](struct.ByteUnit.html#impl-Serialize) into a `u64`.
//!
//! * All operations -- constructors, arithmetic -- saturate. Overflow,
//! underflow, divide-by-zero, and mod-by-zero are impossible.

mod arithmetic;
mod byte_unit;
mod parse;
#[cfg(feature = "serde")]
mod ser_de;

pub use byte_unit::{ByteUnit, ToByteUnit};
pub use parse::Error;
