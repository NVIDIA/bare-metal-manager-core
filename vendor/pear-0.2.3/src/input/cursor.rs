use std::fmt::Debug;

use crate::input::{Input, Show, Rewind, ParserInfo, Length};

#[derive(Debug)]
pub struct Cursor<T> {
    pub start: T,
    pub items: T,
}

impl<T: Copy> From<T> for Cursor<T> {
    fn from(items: T) -> Self {
        Cursor { start: items, items }
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct Extent<T> {
    pub start: usize,
    pub end: usize,
    pub values: T,
}

impl<T: Length> From<T> for Extent<T> {
    fn from(values: T) -> Self {
        Extent { start: 0, end: values.len(), values }
    }
}

impl<T> std::ops::Deref for Extent<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.values
    }
}

impl<T: PartialEq> PartialEq<T> for Extent<T> {
    fn eq(&self, other: &T) -> bool {
        &self.values == other
    }
}

impl PartialEq<Extent<&str>> for &str {
    fn eq(&self, other: &Extent<&str>) -> bool {
        other == self
    }
}

impl<T: PartialEq> PartialEq<Extent<&[T]>> for &[T] {
    fn eq(&self, other: &Extent<&[T]>) -> bool {
        other == self
    }
}

macro_rules! impl_for_slice_len {
    ($($n:expr),*) => ($(
        impl<T: PartialEq> PartialEq<Extent<&[T]>> for &[T; $n] {
            fn eq(&self, other: &Extent<&[T]>) -> bool {
                &other.values[..] == *self
            }
        }
    )*)
}

impl_for_slice_len!(
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32
);

impl<T> Length for Extent<T> {
    fn len(&self) -> usize {
        self.end - self.start
    }
}

impl<T: Show> Show for Extent<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}..{} {}", self.start, self.end, &self.values as &dyn Show)
    }
}

impl<T: ?Sized + ToOwned> Extent<&T> {
    pub fn into_owned(self) -> Extent<T::Owned> {
        Extent {
            start: self.start,
            end: self.end,
            values: self.values.to_owned(),
        }
    }
}

pub trait Indexable: Sized {
    type One: Clone;
    type Iter: Iterator<Item = Self::One>;

    fn head(&self) -> Option<Self::One>;
    fn length_of(token: Self::One) -> usize;
    fn slice<R: std::ops::RangeBounds<usize>>(&self, range: R) -> Option<Self>;
    fn iter(&self) -> Self::Iter;
}

use std::ops::{Bound, RangeBounds, Range};

fn abs<R: RangeBounds<usize>>(range: R, start: usize, end: usize) -> Range<usize> {
    let start = match range.start_bound() {
        Bound::Unbounded => start,
        Bound::Included(&n) => n,
        Bound::Excluded(&n) => n.saturating_add(1),
    };

    let end = match range.end_bound() {
        Bound::Unbounded => end,
        Bound::Included(&n) => n.saturating_add(1),
        Bound::Excluded(&n) => n,
    };

    Range { start, end }
}

impl<'a> Indexable for &'a str {
    type One = char;
    type Iter = std::str::Chars<'a>;

    fn head(&self) -> Option<Self::One> {
        self.chars().next()
    }

    fn length_of(token: Self::One) -> usize {
        token.len_utf8()
    }

    fn slice<R: std::ops::RangeBounds<usize>>(&self, range: R) -> Option<Self> {
        self.get(abs(range, 0, self.len()))
    }

    fn iter(&self) -> Self::Iter {
        self.chars()
    }
}

impl<'a, T: Clone> Indexable for &'a [T] {
    type One = T;
    type Iter = std::iter::Cloned<std::slice::Iter<'a, T>>;

    fn head(&self) -> Option<Self::One> {
        self.get(0).cloned()
    }

    fn length_of(_: Self::One) -> usize {
        1
    }

    fn slice<R: std::ops::RangeBounds<usize>>(&self, range: R) -> Option<Self> {
        self.get(abs(range, 0, self.len()))
    }

    fn iter(&self) -> Self::Iter {
        (*self as &[T]).iter().cloned()
    }
}

impl<T: Length> Cursor<T> {
    fn offset(&self) -> usize {
        self.start.len() - self.items.len()
    }
}

impl<T: Indexable + Length> Cursor<T> {
    /// Returns an `Extent` that spans from `a` to `b` if `a..b` is in bounds.
    pub fn span(&self, a: Extent<T>, b: Extent<T>) -> Option<Extent<T>> {
        let start = std::cmp::min(a.start, b.start);
        let end = std::cmp::max(a.end, b.end);
        let values = self.start.slice(start..end)?;
        Some(Extent { start, end, values })
    }
}

impl<T: Indexable + Show + Length + PartialEq> Input for Cursor<T>
    where T::One: Show + PartialEq
{
    type Token = T::One;
    type Slice = Extent<T>;
    type Many = Extent<T>;

    type Marker = usize;
    type Context = Extent<T>;

    /// Returns a copy of the current token, if there is one.
    fn token(&mut self) -> Option<Self::Token> {
        self.items.head()
    }

    /// Returns a copy of the current slice of size `n`, if there is one.
    fn slice(&mut self, n: usize) -> Option<Self::Slice> {
        Some(Extent {
            start: self.offset(),
            end: self.offset() + n,
            values: self.items.slice(..n)?
        })
    }

    /// Checks if the current token fulfills `cond`.
    fn peek<F>(&mut self, mut cond: F) -> bool
        where F: FnMut(&Self::Token) -> bool
    {
        self.token().map(|t| cond(&t)).unwrap_or(false)
    }

    /// Checks if the current slice of size `n` (if any) fulfills `cond`.
    fn peek_slice<F>(&mut self, n: usize, mut cond: F) -> bool
        where F: FnMut(&Self::Slice) -> bool
    {
        self.slice(n).map(|s| cond(&s)).unwrap_or(false)
    }

    /// Checks if the current token fulfills `cond`. If so, the token is
    /// consumed and returned. Otherwise, returns `None`.
    fn eat<F>(&mut self, mut cond: F) -> Option<Self::Token>
        where F: FnMut(&Self::Token) -> bool
    {
        let token = self.token()?;
        if cond(&token) {
            self.items = self.items.slice(T::length_of(token.clone())..).unwrap();
            Some(token)
        } else {
            None
        }
    }

    /// Checks if the current slice of size `n` (if any) fulfills `cond`. If so,
    /// the slice is consumed and returned. Otherwise, returns `None`.
    fn eat_slice<F>(&mut self, n: usize, mut cond: F) -> Option<Self::Slice>
        where F: FnMut(&Self::Slice) -> bool
    {
        let slice = self.slice(n)?;
        if cond(&slice) {
            self.items = self.items.slice(n..).unwrap();
            Some(slice)
        } else {
            None
        }
    }

    /// Takes tokens while `cond` returns true, collecting them into a
    /// `Self::Many` and returning it.
    fn take<F>(&mut self, cond: F) -> Self::Many
        where F: FnMut(&Self::Token) -> bool
    {
        let start = self.offset();
        let matches: usize = self.items.iter()
            .take_while(cond)
            .map(T::length_of)
            .sum();

        let values = self.items.slice(..matches).unwrap();
        self.items = self.items.slice(matches..).unwrap();
        Extent { start, end: self.offset(), values }
    }

    /// Skips tokens while `cond` returns true. Returns the number of skipped
    /// tokens.
    fn skip<F>(&mut self, cond: F) -> usize
        where F: FnMut(&Self::Token) -> bool
    {
        self.take(cond).len()
    }

    /// Returns `true` if there are at least `n` tokens remaining.
    fn has(&mut self, n: usize) -> bool {
        self.items.len() >= n
    }

    fn mark(&mut self, _: &ParserInfo) -> Self::Marker {
        self.offset()
    }

    /// Optionally returns a context to identify the current input position. By
    /// default, this method returns `None`, indicating that no context could be
    /// resolved.
    fn context(&mut self, mark: Self::Marker) -> Self::Context {
        let end = self.offset();
        let values = self.start.slice(mark..end).unwrap();
        Extent { start: mark, end, values }
    }
}

impl<T: Indexable + Show + Length + PartialEq> Rewind for Cursor<T>
    where T::One: Show + PartialEq
{
    fn rewind_to(&mut self, marker: Self::Marker) {
        self.items = self.start.slice(marker..).unwrap();
    }
}
