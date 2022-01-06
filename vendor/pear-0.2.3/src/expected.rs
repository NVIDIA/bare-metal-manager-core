use std::fmt;

use inlinable_string::InlinableString;

use crate::input::Show;

#[derive(Clone)]
pub enum CowInlineString {
    Borrowed(&'static str),
    Inline(InlinableString)
}

impl std::ops::Deref for CowInlineString {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        match self {
            CowInlineString::Borrowed(s) => s,
            CowInlineString::Inline(s) => s,
        }
    }
}

impl std::fmt::Display for CowInlineString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        str::fmt(self, f)
    }
}

impl std::fmt::Debug for CowInlineString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        str::fmt(self, f)
    }
}

pub enum Expected<Token, Slice> {
    Token(Option<InlinableString>, Option<Token>),
    Slice(Option<InlinableString>, Option<Slice>),
    Eof(Option<Token>),
    Other(CowInlineString),
    Elided
}

impl<Token, Slice> Expected<Token, Slice> {
    pub fn token<T: Show>(expected: Option<&T>, found: Option<Token>) -> Self {
        let expected = expected.map(|t| iformat!("{}", t as &dyn Show));
        Expected::Token(expected, found)
    }

    pub fn eof(found: Option<Token>) -> Self {
        Expected::Eof(found)
    }
}

impl<Token, Slice> Expected<Token, Slice> {
    pub fn slice<S: Show>(expected: Option<&S>, found: Option<Slice>) -> Self {
        let expected = expected.map(|t| iformat!("{}", t as &dyn Show));
        Expected::Slice(expected, found)
    }
}

impl<Token, Slice> Expected<Token, Slice> {
    pub fn map<FT, FS, T, S>(self, t: FT, s: FS) -> Expected<T, S>
        where FT: Fn(Token) -> T, FS: Fn(Slice) -> S
    {
        use Expected::*;

        match self {
            Token(e, v) => Token(e, v.map(t)),
            Slice(e, v) => Slice(e, v.map(s)),
            Eof(v) => Eof(v.map(t)),
            Other(v) => Other(v),
            Expected::Elided => Expected::Elided,
        }
    }
}

impl<T: ToOwned, S: ?Sized + ToOwned> Expected<T, &S> {
    pub fn into_owned(self) -> Expected<T::Owned, S::Owned> {
        self.map(|t| t.to_owned(), |s| s.to_owned())
    }
}

impl<T, S> From<String> for Expected<T, S> {
    #[inline(always)]
    fn from(string: String) -> Expected<T, S> {
        Expected::Other(CowInlineString::Inline(InlinableString::from(string)))
    }
}

#[doc(hidden)]
impl<T, S> From<InlinableString> for Expected<T, S> {
    #[inline(always)]
    fn from(string: InlinableString) -> Expected<T, S> {
        Expected::Other(CowInlineString::Inline(string))
    }
}

impl<T, S> From<&'static str> for Expected<T, S> {
    #[inline(always)]
    fn from(string: &'static str) -> Expected<T, S> {
        Expected::Other(CowInlineString::Borrowed(string))
    }
}

impl<T: fmt::Debug, S: fmt::Debug> fmt::Debug for Expected<T, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Expected::Token(e, v) => {
                f.debug_tuple("Expected::Token").field(&e).field(&v).finish()
            }
            Expected::Slice(e, v) => {
                f.debug_tuple("Expected::Slice").field(&e).field(&v).finish()
            }
            Expected::Eof(v) => {
                f.debug_tuple("Expected::Eof").field(&v).finish()
            }
            Expected::Other(v) => {
                f.debug_tuple("Expected::Other").field(&v).finish()
            }
            Expected::Elided => f.debug_tuple("Expected::Elided").finish()
        }
    }
}

impl<T: Clone, S: Clone> Clone for Expected<T, S> {
    fn clone(&self) -> Self {
        match self {
            Expected::Token(e, f) => Expected::Token(e.clone(), f.clone()),
            Expected::Slice(e, f) => Expected::Slice(e.clone(), f.clone()),
            Expected::Eof(f) => Expected::Eof(f.clone()),
            Expected::Other(v) => Expected::Other(v.clone()),
            Expected::Elided => Expected::Elided,
        }
    }
}

impl<T: Show, S: Show> fmt::Display for Expected<T, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Expected::Token(Some(ref expected), Some(ref found)) => {
                let found = found as &dyn Show;
                write!(f, "expected token {} but found {}", expected, found)
            }
            Expected::Token(None, Some(ref found)) => {
                let found = found as &dyn Show;
                write!(f, "unexpected token: {}", found)
            }
            Expected::Token(Some(ref expected), None) => {
                write!(f, "unexpected EOF: expected token {}", expected)
            }
            Expected::Token(None, None) => {
                write!(f, "unexpected EOF: expected some token")
            }
            Expected::Slice(Some(ref expected), Some(ref found)) => {
                let found = found as &dyn Show;
                write!(f, "expected slice {} but found {}", expected, found)
            }
            Expected::Slice(None, Some(ref found)) => {
                let found = found as &dyn Show;
                write!(f, "unexpected slice: {}", found)
            }
            Expected::Slice(Some(ref expected), None) => {
                write!(f, "unexpected EOF: expected slice {}", expected)
            }
            Expected::Slice(None, None) => {
                write!(f, "unexpected EOF: expected some slice")
            }
            Expected::Eof(None) => {
                write!(f, "expected EOF but input remains")
            }
            Expected::Eof(Some(ref found)) => {
                let found = found as &dyn Show;
                write!(f, "unexpected token {}", found)
            }
            Expected::Other(ref other) => write!(f, "{}", other),
            Expected::Elided => write!(f, "[ERROR ELIDED]")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Expected;

    #[test]
    fn test_into_owned() {
        let expected: Expected<char, &str> = Expected::Slice(None, Some("hi"));
        let _owned: Expected<char, String> = expected.into_owned();
    }
}
