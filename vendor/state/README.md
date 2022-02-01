# `state` &thinsp; [![ci.svg]][ci] [![crates.io]][crate] [![docs.rs]][docs]

[crates.io]: https://img.shields.io/crates/v/state.svg
[crate]: https://crates.io/crates/state
[docs.rs]: https://docs.rs/state/badge.svg
[docs]: https://docs.rs/state
[ci.svg]: https://github.com/SergioBenitez/state/workflows/CI/badge.svg
[ci]: https://github.com/SergioBenitez/state/actions

A Rust library for safe and effortless global and thread-local state management.

```rust
extern crate state;

static GLOBAL: state::Storage<u32> = state::Storage::new();

GLOBAL.set(42);
assert_eq!(*GLOBAL.get(), 42);
```

This library can be used to easily implement:

  * Lazier Global Statics
  * Singletons, Init-Once Values
  * Global or Thread-Local Caches, Thunks
  * Dynamically-Initialized Thread-Local Data
  * Type Maps, Type-Based Containers

See the [documentation](https://docs.rs/state) for more.

## Usage

Include `state` in your `Cargo.toml` `[dependencies]`:

```toml
[dependencies]
state = "0.5"
```

Thread-local state management is not enabled by default. You can enable it
via the `tls` feature:

```toml
[dependencies]
state = { version = "0.5", features = ["tls"] }
```

## MSRV

The minimum supported Rust version is `1.32.0` as of `state` version `0.5.2`.

## Correctness

`state` has been extensively vetted, manually and automatically, for soundness
and correctness. _All_ unsafe code, including in internal concurrency
primitives, `Container`, and `Storage` are exhaustively verified for pairwise
concurrency correctness and internal aliasing exclusion with `loom`.
Multithreading invariants, aliasing invariants, and other soundness properties
are verified with `miri`. Verification is run by the CI on every commit.

## Performance

`state` is heavily tuned to perform optimally. `Storage` is optimal for global
storage retrieval; it is _slightly faster_ than accessing global state
initialized through `lazy_static!`, more so across many threads. `LocalStorage`
incurs slight overhead due to thread lookup. However, `LocalStorage` has no
synchronization overhead, so retrieval from `LocalStorage` is faster than
through `Storage` across many threads.

Bear in mind that `state` allows global initialization at _any_ point in the
program. Other solutions, such as `lazy_static!` and `thread_local!` allow
initialization _only_ a priori. In other words, `state`'s abilities are a
superset of those provided by `lazy_static!` and `thread_local!` while being
more performant.

## Testing

Tests can be found in the `tests` directory. You can run tests with `cargo test
--all-features`. Loom verification can be run with `RUSTFLAGS="--cfg loom" cargo
test --release --test loom`.

## License

`state` is licensed under either of the following, at your option:

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT License ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
