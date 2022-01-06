# NormPath

This crate provides methods to normalize paths in the recommended way for the
operating system.

It was made to fix a recurring bug caused by using [`fs::canonicalize`] on
Windows: [#45067], [#48249], [#52440], [#55812], [#58613], [#59107], [#74327].
Normalization is usually a better choice unless you specifically need a
canonical path.

[![GitHub Build Status](https://github.com/dylni/normpath/workflows/build/badge.svg?branch=master)](https://github.com/dylni/normpath/actions?query=branch%3Amaster)

## Usage

Add the following lines to your "Cargo.toml" file:

```toml
[dependencies]
normpath = "0.3"
```

See the [documentation] for available functionality and examples.

## Rust version support

The minimum supported Rust toolchain version is currently Rust 1.41.0.

## License

Licensing terms are specified in [COPYRIGHT].

Unless you explicitly state otherwise, any contribution submitted for inclusion
in this crate, as defined in [LICENSE-APACHE], shall be licensed according to
[COPYRIGHT], without any additional terms or conditions.

### Third-party software

This crate includes copies and modifications of software developed by third
parties:

- [src/cmp.rs] and [tests/rust.rs] contain modifications of code from The Rust
  Programming Language, licensed under the MIT License or the Apache License,
  Version 2.0.

See those files for more details.

Copies of third-party licenses can be found in [LICENSE-THIRD-PARTY].

[#45067]: https://github.com/rust-lang/rust/issues/45067
[#48249]: https://github.com/rust-lang/rust/issues/48249
[#52440]: https://github.com/rust-lang/rust/issues/52440
[#55812]: https://github.com/rust-lang/rust/issues/55812
[#58613]: https://github.com/rust-lang/rust/issues/58613
[#59107]: https://github.com/rust-lang/rust/issues/59107
[#74327]: https://github.com/rust-lang/rust/issues/74327
[COPYRIGHT]: https://github.com/dylni/normpath/blob/master/COPYRIGHT
[documentation]: https://docs.rs/normpath
[`fs::canonicalize`]: https://doc.rust-lang.org/std/fs/fn.canonicalize.html
[LICENSE-APACHE]: https://github.com/dylni/normpath/blob/master/LICENSE-APACHE
[LICENSE-THIRD-PARTY]: https://github.com/dylni/normpath/blob/master/LICENSE-THIRD-PARTY
[src/cmp.rs]: https://github.com/dylni/normpath/blob/master/src/cmp.rs
[tests/rust.rs]: https://github.com/dylni/normpath/blob/master/tests/rust.rs
