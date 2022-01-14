//! Case-preserving, ASCII case-insensitive `no_std` string types.
//!
//! An _uncased_ string is case-preserving. That is, the string itself contains
//! cased characters, but comparison (including ordering, equality, and hashing)
//! is ASCII case-insensitive.
//!
//! ```rust
//! use uncased::UncasedStr;
//!
//! let x: &UncasedStr = "hello!".into();
//! let y: &UncasedStr = "HelLo!".into();
//!
//! assert_eq!(x, y);
//! assert_eq!(x.as_str(), "hello!");
//! assert_eq!(y.as_str(), "HelLo!");
//!
//! let x_sub = &x[..4];
//! let y_sub = &y[..4];
//! assert_eq!(x_sub, y_sub);
//! assert_eq!(x_sub.as_str(), "hell");
//! assert_eq!(y_sub.as_str(), "HelL");
//! ```
//!
//! ## Unicode
//!
//! This crate _does not_ perform Unicode case-folding. For Unicode
//! case-folding, see [`unicase`](https://crates.io/crates/unicase).
//!
//! ## Features and `no_std`
//!
//! Crate features:
//!
//! * `alloc` (_default_) - enables the [`Uncased`] type
//! * `with-serde` - enables (de)serializing of [`UncasedStr`] via `serde`
//! * `with-serde-alloc` - enables `alloc`, (de)serializing of [`UncasedStr`]
//!    and [`Uncased`] via `serde`
//!
//! This crate is `#![no_std]` compatible. By default, the `alloc` feature is
//! enabled, which enables the [`Uncased`] type but requires `alloc` support. To
//! disable the feature, disable this crate's default features:
//!
//! ```toml
//! [dependencies]
//! uncased = { version = "0.9", default-features = false }
//! ```
//!
//! In addition to the `alloc` feature, support for (de)serializing `UncasedStr`
//! with `serde` can be enabled via the `with-serde` feature. Support for
//! (de)serserializing both `UncasedStr` and `Uncased` can be enabled via the
//! `with-serde-alloc` feature, which implicitly enables the `alloc` feature.

#![no_std]
#![cfg_attr(nightly, feature(doc_cfg))]

#[cfg(feature = "alloc")] extern crate alloc;

#[cfg(feature = "serde")] mod serde;
#[cfg(feature = "alloc")] mod owned;
#[cfg(test)] mod tests;
mod borrowed;
mod as_uncased;

#[cfg(feature = "alloc")] pub use owned::Uncased;
pub use borrowed::UncasedStr;
pub use as_uncased::AsUncased;

/// Returns true if `s1` and `s2` are equal without considering case.
///
/// That is, this function returns `s1.to_ascii_lowercase() ==
/// s2.to_ascii_lowercase()`, but does it in a much faster way. This is also
/// equivalent to `UncasedStr::new(s1) == UncasedStr::new(s2)`.
///
/// # Example
///
/// ```rust
/// assert!(uncased::eq("ENV", "env"));
/// assert!(uncased::eq("bRoWN", "BROWN"));
/// assert!(uncased::eq("hi", "HI"));
/// assert!(uncased::eq("dogs are COOL!", "DOGS are cool!"));
/// ```
#[inline(always)]
pub fn eq<S1: AsRef<str>, S2: AsRef<str>>(s1: S1, s2: S2) -> bool {
    UncasedStr::new(s1.as_ref()) == UncasedStr::new(s2.as_ref())
}
