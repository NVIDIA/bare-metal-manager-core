use alloc::borrow::{Cow, Borrow};
use alloc::{string::String, boxed::Box};

use core::ops::Deref;
use core::cmp::Ordering;
use core::hash::{Hash, Hasher};
use core::fmt;

use crate::UncasedStr;

/// An uncased (case-insensitive, case-preserving), owned _or_ borrowed ASCII
/// string.
#[cfg_attr(nightly, doc(cfg(feature = "alloc")))]
#[derive(Clone, Debug)]
pub struct Uncased<'s> {
    #[doc(hidden)]
    pub string: Cow<'s, str>
}

impl<'s> Uncased<'s> {
    /// Creates a new `Uncased` string from `string` without allocating.
    ///
    /// # Example
    ///
    /// ```rust
    /// use uncased::Uncased;
    ///
    /// let uncased = Uncased::new("Content-Type");
    /// assert_eq!(uncased, "content-type");
    /// assert_eq!(uncased, "CONTENT-Type");
    /// ```
    #[inline(always)]
    pub fn new<S: Into<Cow<'s, str>>>(string: S) -> Uncased<'s> {
        Uncased { string: string.into() }
    }

    /// Creates a new `Uncased` string from a borrowed `string`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use uncased::Uncased;
    ///
    /// const UNCASED: Uncased = Uncased::from_borrowed("Content-Type");
    /// assert_eq!(UNCASED, "content-type");
    /// assert_eq!(UNCASED, "CONTENT-Type");
    /// ```
    #[inline(always)]
    pub const fn from_borrowed(string: &'s str) -> Uncased<'s> {
        Uncased { string: Cow::Borrowed(string) }
    }

    /// Creates a new `Uncased` string from `string` without allocating.
    ///
    /// # Example
    ///
    /// ```rust
    /// use uncased::Uncased;
    ///
    /// const UNCASED: Uncased = Uncased::from_owned(String::new());
    ///
    /// let uncased = Uncased::from_owned("Content-Type".to_string());
    /// assert_eq!(uncased, "content-type");
    /// assert_eq!(uncased, "CONTENT-Type");
    /// ```
    #[inline(always)]
    pub const fn from_owned(string: String) -> Uncased<'s> {
        Uncased { string: Cow::Owned(string) }
    }

    /// Converts `self` into an owned `Uncased<'static>`, allocating if
    /// necessary.
    ///
    /// # Example
    ///
    /// ```rust
    /// use uncased::Uncased;
    ///
    /// let foo = "foo".to_string();
    /// let uncased = Uncased::from(foo.as_str());
    /// let owned: Uncased<'static> = uncased.into_owned();
    /// assert_eq!(owned, "foo");
    /// ```
    #[inline(always)]
    pub fn as_uncased_str(&self) -> &UncasedStr {
        self.as_ref()
    }

    /// Converts `self` into an owned `String`, allocating if necessary.
    ///
    /// # Example
    ///
    /// ```rust
    /// use uncased::Uncased;
    ///
    /// let uncased = Uncased::new("Content-Type");
    /// let string = uncased.into_string();
    /// assert_eq!(string, "Content-Type".to_string());
    /// ```
    #[inline(always)]
    pub fn into_string(self) -> String {
        self.string.into_owned()
    }

    /// Converts `self` into an owned `Uncased<'static>`, allocating if
    /// necessary.
    ///
    /// # Example
    ///
    /// ```rust
    /// use uncased::Uncased;
    ///
    /// let foo = "foo".to_string();
    /// let uncased = Uncased::from(foo.as_str());
    /// let owned: Uncased<'static> = uncased.into_owned();
    /// assert_eq!(owned, "foo");
    /// ```
    #[inline(always)]
    pub fn into_owned(self) -> Uncased<'static> {
        match self.string {
            Cow::Owned(string) => Uncased::new(string),
            Cow::Borrowed(str) => Uncased::new(String::from(str)),
        }
    }

    /// Converts `self` into a `Box<UncasedStr>`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use uncased::Uncased;
    ///
    /// let boxed = Uncased::new("Content-Type").into_boxed_uncased();
    /// assert_eq!(&*boxed, "content-type");
    /// ```
    #[inline(always)]
    pub fn into_boxed_uncased(self) -> Box<UncasedStr> {
        // This is simply a `newtype`-like transformation. The
        // `repr(transparent)` ensures that this is safe and correct. Note this
        // exact pattern appears often in the standard library.
        unsafe {
            let raw_str = Box::into_raw(self.string.into_owned().into_boxed_str());
            Box::from_raw(raw_str as *mut UncasedStr)
        }
    }

    /// Returns the inner `Cow`.
    #[doc(hidden)]
    #[inline(always)]
    pub fn into_cow(self) -> Cow<'s, str> {
        self.string
    }
}

impl Deref for Uncased<'_> {
    type Target = UncasedStr;

    #[inline(always)]
    fn deref(&self) -> &UncasedStr {
        UncasedStr::new(self.string.borrow())
    }
}

impl AsRef<UncasedStr> for Uncased<'_> {
    #[inline(always)]
    fn as_ref(&self) -> &UncasedStr {
        UncasedStr::new(self.string.borrow())
    }
}

impl AsRef<str> for Uncased<'_> {
    #[inline(always)]
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<[u8]> for Uncased<'_> {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        self.as_str().as_bytes()
    }
}

impl Borrow<UncasedStr> for Uncased<'_> {
    #[inline(always)]
    fn borrow(&self) -> &UncasedStr {
        self.as_str().into()
    }
}

impl<'s, 'c: 's> From<&'c UncasedStr> for Uncased<'s> {
    #[inline(always)]
    fn from(string: &'c UncasedStr) -> Self {
        Uncased::new(string.as_str())
    }
}

impl<'s, 'c: 's> From<&'c str> for Uncased<'s> {
    #[inline(always)]
    fn from(string: &'c str) -> Self {
        Uncased::new(string)
    }
}

impl From<String> for Uncased<'static> {
    #[inline(always)]
    fn from(string: String) -> Self {
        Uncased::new(string)
    }
}

impl<'s, 'c: 's> From<Cow<'c, str>> for Uncased<'s> {
    #[inline(always)]
    fn from(string: Cow<'c, str>) -> Self {
        Uncased::new(string)
    }
}

impl fmt::Display for Uncased<'_> {
    #[inline(always)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.string.fmt(f)
    }
}

macro_rules! impl_partial_eq {
    ($other:ty $([$o_i:ident])? = $this:ty $([$t_i:ident])?) => (
        impl PartialEq<$other> for $this {
            #[inline(always)]
            fn eq(&self, other: &$other) -> bool {
                self $(.$t_i())? .eq(other $(.$o_i())?)
            }
        }
    )
}

impl_partial_eq!(Uncased<'_> [as_uncased_str] = Uncased<'_> [as_uncased_str]);
impl_partial_eq!(str = Uncased<'_> [as_uncased_str]);
impl_partial_eq!(Uncased<'_> [as_uncased_str] = str);
impl_partial_eq!(&str = Uncased<'_> [as_uncased_str]);
impl_partial_eq!(Uncased<'_> [as_uncased_str] = &str);
impl_partial_eq!(String [as_str] = Uncased<'_> [as_uncased_str]);
impl_partial_eq!(Uncased<'_> [as_uncased_str] = String [as_str]);
impl_partial_eq!(String [as_str] = &Uncased<'_> [as_uncased_str]);
impl_partial_eq!(&Uncased<'_> [as_uncased_str] = String [as_str]);


macro_rules! impl_partial_ord {
    ($other:ty $([$o_i:ident])? >< $this:ty $([$t_i:ident])?) => (
        impl PartialOrd<$other> for $this {
            #[inline(always)]
            fn partial_cmp(&self, other: &$other) -> Option<Ordering> {
                let this: &UncasedStr = self$(.$t_i())?.into();
                let other: &UncasedStr = other$(.$o_i())?.into();
                this.partial_cmp(other)
            }
        }
    )
}

impl Ord for Uncased<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_uncased_str().cmp(other.as_uncased_str())
    }
}

impl_partial_ord!(Uncased<'_> [as_uncased_str] >< Uncased<'_> [as_uncased_str]);
impl_partial_ord!(str >< Uncased<'_> [as_uncased_str]);
impl_partial_ord!(Uncased<'_> [as_uncased_str] >< str);
impl_partial_ord!(String [as_str] >< Uncased<'_> [as_uncased_str]);
impl_partial_ord!(Uncased<'_> [as_uncased_str] >< String [as_str]);
impl_partial_ord!(String [as_str] >< &Uncased<'_> [as_uncased_str]);
impl_partial_ord!(&Uncased<'_> [as_uncased_str] >< String [as_str]);

impl Eq for Uncased<'_> {  }

impl Hash for Uncased<'_> {
    #[inline(always)]
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        self.as_uncased_str().hash(hasher)
    }
}
