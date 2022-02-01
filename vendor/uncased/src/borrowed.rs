use core::cmp::Ordering;
use core::hash::{Hash, Hasher};
use core::fmt;

#[cfg(feature = "alloc")]
use alloc::string::String;

/// A cost-free reference to an uncased (case-insensitive, case-preserving)
/// ASCII string.
///
/// This is typically created from an `&str` as follows:
///
/// ```rust
/// use uncased::UncasedStr;
///
/// let ascii_ref: &UncasedStr = "Hello, world!".into();
/// ```
#[derive(Debug)]
#[repr(transparent)]
pub struct UncasedStr(str);

impl UncasedStr {
    /// Cost-free conversion from an `&str` reference to an `UncasedStr`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use uncased::UncasedStr;
    ///
    /// let uncased_str = UncasedStr::new("Hello!");
    /// assert_eq!(uncased_str, "hello!");
    /// assert_eq!(uncased_str, "Hello!");
    /// assert_eq!(uncased_str, "HeLLo!");
    /// ```
    #[inline(always)]
    pub fn new(string: &str) -> &UncasedStr {
        // This is a `newtype`-like transformation. `repr(transparent)` ensures
        // that this is safe and correct.
        unsafe { &*(string as *const str as *const UncasedStr) }
    }

    /// Returns `self` as an `&str`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use uncased::UncasedStr;
    ///
    /// let uncased_str = UncasedStr::new("Hello!");
    /// assert_eq!(uncased_str.as_str(), "Hello!");
    /// assert_ne!(uncased_str.as_str(), "hELLo!");
    /// ```
    #[inline(always)]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the length, in bytes, of `self`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use uncased::UncasedStr;
    ///
    /// let uncased_str = UncasedStr::new("Hello!");
    /// assert_eq!(uncased_str.len(), 6);
    /// ```
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.as_str().len()
    }

    /// Returns `true` if `self` has a length of zero bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use uncased::UncasedStr;
    ///
    /// let s = UncasedStr::new("");
    /// assert!(s.is_empty());
    ///
    /// let s = UncasedStr::new("not empty");
    /// assert!(!s.is_empty());
    /// ```
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.as_str().is_empty()
    }

    /// Returns `true` if `self` starts with any casing of the string `string`;
    /// otherwise, returns `false`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use uncased::UncasedStr;
    ///
    /// let uncased_str = UncasedStr::new("MoOO");
    /// assert!(uncased_str.starts_with("moo"));
    /// assert!(uncased_str.starts_with("MOO"));
    /// assert!(uncased_str.starts_with("MOOO"));
    /// assert!(!uncased_str.starts_with("boo"));
    ///
    /// let uncased_str = UncasedStr::new("Bèe");
    /// assert!(!uncased_str.starts_with("Be"));
    /// assert!(uncased_str.starts_with("Bè"));
    /// assert!(uncased_str.starts_with("Bè"));
    /// assert!(uncased_str.starts_with("bèe"));
    /// assert!(uncased_str.starts_with("BèE"));
    /// ```
    #[inline(always)]
    pub fn starts_with(&self, string: &str) -> bool {
        self.as_str()
            .get(..string.len())
            .map(|s| Self::new(s) == string)
            .unwrap_or(false)
    }

    /// Converts a `Box<UncasedStr>` into an `Uncased` without copying or
    /// allocating.
    ///
    /// # Example
    ///
    /// ```rust
    /// use uncased::Uncased;
    ///
    /// let uncased = Uncased::new("Hello!");
    /// let boxed = uncased.clone().into_boxed_uncased();
    /// assert_eq!(boxed.into_uncased(), uncased);
    /// ```
    #[inline(always)]
    #[cfg(feature = "alloc")]
    #[cfg_attr(nightly, doc(cfg(feature = "alloc")))]
    pub fn into_uncased(self: alloc::boxed::Box<UncasedStr>) -> crate::Uncased<'static> {
        // This is the inverse of a `newtype`-like transformation. The
        // `repr(transparent)` ensures that this is safe and correct.
        unsafe {
            let raw_str = alloc::boxed::Box::into_raw(self) as *mut str;
            crate::Uncased::from(alloc::boxed::Box::from_raw(raw_str).into_string())
        }
    }
}

impl<'a> From<&'a str> for &'a UncasedStr {
    #[inline(always)]
    fn from(string: &'a str) -> &'a UncasedStr {
        UncasedStr::new(string)
    }
}

impl<I: core::slice::SliceIndex<str, Output=str>> core::ops::Index<I> for UncasedStr {
    type Output = UncasedStr;

    #[inline]
    fn index(&self, index: I) -> &Self::Output {
        self.as_str()[index].into()
    }
}

impl AsRef<str> for UncasedStr {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<[u8]> for UncasedStr {
    fn as_ref(&self) -> &[u8] {
        self.as_str().as_bytes()
    }
}

impl fmt::Display for UncasedStr {
    #[inline(always)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

macro_rules! impl_partial_eq {
    ($other:ty $([$o_i:ident])? = $this:ty $([$t_i:ident])?) => (
        impl PartialEq<$other> for $this {
            #[inline(always)]
            fn eq(&self, other: &$other) -> bool {
                self $(.$t_i())? .eq_ignore_ascii_case(other $(.$o_i())?)
            }
        }
    )
}

impl_partial_eq!(UncasedStr [as_str] = UncasedStr [as_str]);
impl_partial_eq!(str = UncasedStr [as_str]);
impl_partial_eq!(UncasedStr [as_str] = str);
impl_partial_eq!(str = &UncasedStr [as_str]);
impl_partial_eq!(&UncasedStr [as_str] = str);
impl_partial_eq!(&str = UncasedStr [as_str]);
impl_partial_eq!(UncasedStr [as_str] = &str);

#[cfg(feature = "alloc")] impl_partial_eq!(String [as_str] = UncasedStr [as_str]);

#[cfg(feature = "alloc")] impl_partial_eq!(UncasedStr [as_str] = String [as_str] );

impl Eq for UncasedStr {  }

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

impl PartialOrd for UncasedStr {
    #[inline(always)]
    fn partial_cmp(&self, other: &UncasedStr) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for UncasedStr {
    fn cmp(&self, other: &Self) -> Ordering {
        let self_chars = self.0.chars().map(|c| c.to_ascii_lowercase());
        let other_chars = other.0.chars().map(|c| c.to_ascii_lowercase());
        self_chars.cmp(other_chars)
    }
}

impl_partial_ord!(str >< UncasedStr);
impl_partial_ord!(UncasedStr >< str);

#[cfg(feature = "alloc")] impl_partial_ord!(String [as_str] >< UncasedStr);
#[cfg(feature = "alloc")] impl_partial_ord!(UncasedStr >< String [as_str]);

impl Hash for UncasedStr {
    #[inline(always)]
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        self.0.bytes().for_each(|b| hasher.write_u8(b.to_ascii_lowercase()));
    }
}
