//! Stable, `no_std` port of [`std::str::pattern`], Rust 1.52.
//!
//! [`std::str::pattern`]: https://doc.rust-lang.org/stable/std/str/pattern/index.html

#![no_std]

mod pattern;
mod split;

pub use pattern::*;
pub use split::*;
