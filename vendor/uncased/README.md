# uncased &thinsp; [![crates.io]][crate] [![docs.rs]][docs]

[crates.io]: https://img.shields.io/crates/v/uncased.svg
[crate]: https://crates.io/crates/uncased
[docs.rs]: https://docs.rs/uncased/badge.svg
[docs]: https://docs.rs/uncased

Case-preserving, ASCII case-insensitive `no_std` string types.

An _uncased_ string is case-preserving. That is, the string itself contains
cased characters, but comparison (including ordering, equality, and hashing) is
ASCII case-insensitive.

```rust
use uncased::UncasedStr;

let x: &UncasedStr = "hello!".into();
let y: &UncasedStr = "HelLo!".into();

assert_eq!(x, y);
assert_eq!(x.as_str(), "hello!");
assert_eq!(y.as_str(), "HelLo!");
```

See the [documentation](http://docs.rs/uncased) for detailed usage information.

# Usage

Add the following to your `Cargo.toml`:

```toml
[dependencies]
uncased = "0.9"
```

This crate is `#![no_std]` compatible. By default, the `alloc` feature is
enabled, which enables the `Uncased` type but requires `alloc` support. To
disable the feature, disable this crate's default features:

```toml
[dependencies]
uncased = { version = "0.9", default-features = false }
```

**Note:** This crate _does not_ perform Unicode case-folding. For Unicode
case-folding, see [`unicase`](https://crates.io/crates/unicase).

# License

`uncased` is licensed under either of the following, at your option:

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT License ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in `uncased` by you shall be dual licensed as above without any
additional terms or conditions.
