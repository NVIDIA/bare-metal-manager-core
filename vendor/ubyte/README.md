# ubyte &thinsp; [![crates.io]][crate] [![docs.rs]][docs]

[crates.io]: https://img.shields.io/crates/v/ubyte.svg
[crate]: https://crates.io/crates/ubyte
[docs.rs]: https://docs.rs/ubyte/badge.svg
[docs]: https://docs.rs/ubyte

A simple, complete, `const`-everything, saturating, human-friendly, `#![no_std]`
Rust library for byte units.

```rust
use ubyte::{ByteUnit, ToByteUnit};

// Constructors and associated units for all SI units up to exbibyte.
let half_mb = 500.kilobytes();
let half_mb = ByteUnit::Kilobyte(500);
let half_mb = 500 * ByteUnit::kB;

// All arithmetic and conversions are saturating.
let exbibyte_too_large_a = 1024 * ByteUnit::EiB;
let exbibyte_too_large_b = ByteUnit::Exbibyte(1024);
let exbibyte_too_large_c = 1024.exbibytes();
assert_eq!(exbibyte_too_large_a, ByteUnit::max_value());
assert_eq!(exbibyte_too_large_b, ByteUnit::max_value());
assert_eq!(exbibyte_too_large_c, ByteUnit::max_value());

// Printing is human-friendly and customizeable.
assert_eq!(323.kilobytes().to_string(), "323kB");
assert_eq!(3.mebibytes().to_string(), "3MiB");
assert_eq!((7.gigabytes() + 58.mebibytes() + 3.kilobytes()).to_string(), "7.06GB");
assert_eq!(format!("{:.0}", 7.gibibytes() + 920.mebibytes()), "8GiB");
assert_eq!(format!("{:.3}", 7.gibibytes() + 920.mebibytes()), "7.898GiB");
assert_eq!(format!("{:04.2}", 999.kilobytes() + 990.bytes()), "0976.55KiB");
assert_eq!(format!("{:02.0}", 999.kilobytes() + 990.bytes()), "01MB");

// Parsing is intuitive.
assert_eq!("10 KiB".parse().unwrap(), 10.kibibytes());
assert_eq!("10kb".parse().unwrap(), 10.kilobytes());
assert_eq!("512Kb".parse().unwrap(), 512.kilobytes());
assert_eq!("0.2MB".parse().unwrap(), 200.kilobytes());
assert_eq!("1.5 MiB".parse().unwrap(), 1.mebibytes() + 512.kibibytes());
assert_eq!("7.25 gb".parse().unwrap(), 7.gigabytes() + 250.megabytes());
```

See the [documentation](http://docs.rs/ubyte) for detailed usage information.

# Usage

Add the following to your `Cargo.toml`:

```toml
[dependencies]
ubyte = "0.10"
```

For `serde` (de)serialization support, enable the `serde` feature, which is
disabled by default:

```toml
[dependencies]
ubyte = { version = "0.10", features = ["serde"] }
```

# License

`ubyte` is licensed under either of the following, at your option:

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT License ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in `ubyte` by you shall be dual licensed as above without any
additional terms or conditions.
