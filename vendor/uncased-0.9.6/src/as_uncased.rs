use crate::UncasedStr;

/// Helper trait to convert string-like references to `&UncasedStr`.
///
/// # Example
///
/// ```rust
/// use uncased::AsUncased;
///
/// let string = "Hello, world!".as_uncased();
/// assert_eq!(string, "hello, world!");
/// assert_eq!(string, "HELLO, world!");
/// assert_eq!(string, "HELLO, WORLD!");
/// ```
pub trait AsUncased {
    /// Convert `self` to an [`UncasedStr`].
    fn as_uncased(&self) -> &UncasedStr;
}

impl<T: AsRef<str> + ?Sized> AsUncased for T {
    #[inline(always)]
    fn as_uncased(&self) -> &UncasedStr {
        UncasedStr::new(self.as_ref())
    }
}
