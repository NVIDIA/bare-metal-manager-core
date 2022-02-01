//! Iterators for `str` methods.

use core::fmt;
use core::iter::FusedIterator;


use super::pattern::Pattern;
use super::pattern::{DoubleEndedSearcher, ReverseSearcher, Searcher};

/// This macro generates a Clone impl for string pattern API
/// wrapper types of the form X<'a, P>
macro_rules! derive_pattern_clone {
    (clone $t:ident with |$s:ident| $e:expr) => {
        impl<'a, P> Clone for $t<'a, P>
        where
            P: Pattern<'a>, <P as Pattern<'a>>::Searcher: Clone
        {
            fn clone(&self) -> Self {
                let $s = self;
                $e
            }
        }
    };
}

/// This macro generates two public iterator structs
/// wrapping a private internal one that makes use of the `Pattern` API.
///
/// For all patterns `P: Pattern<'a>` the following items will be
/// generated (generics omitted):
///
/// struct $forward_iterator($internal_iterator);
/// struct $reverse_iterator($internal_iterator);
///
/// impl Iterator for $forward_iterator
/// { /* internal ends up calling Searcher::next_match() */ }
///
/// impl DoubleEndedIterator for $forward_iterator
///       where P::Searcher: DoubleEndedSearcher
/// { /* internal ends up calling Searcher::next_match_back() */ }
///
/// impl Iterator for $reverse_iterator
///       where P::Searcher: ReverseSearcher
/// { /* internal ends up calling Searcher::next_match_back() */ }
///
/// impl DoubleEndedIterator for $reverse_iterator
///       where P::Searcher: DoubleEndedSearcher
/// { /* internal ends up calling Searcher::next_match() */ }
///
/// The internal one is defined outside the macro, and has almost the same
/// semantic as a DoubleEndedIterator by delegating to `pattern::Searcher` and
/// `pattern::ReverseSearcher` for both forward and reverse iteration.
///
/// "Almost", because a `Searcher` and a `ReverseSearcher` for a given
/// `Pattern` might not return the same elements, so actually implementing
/// `DoubleEndedIterator` for it would be incorrect.
/// (See the docs in `str::pattern` for more details)
///
/// However, the internal struct still represents a single ended iterator from
/// either end, and depending on pattern is also a valid double ended iterator,
/// so the two wrapper structs implement `Iterator`
/// and `DoubleEndedIterator` depending on the concrete pattern type, leading
/// to the complex impls seen above.
macro_rules! generate_pattern_iterators {
    {
        // Forward iterator
        forward:
            $(#[$forward_iterator_attribute:meta])*
            struct $forward_iterator:ident;

        // Reverse iterator
        reverse:
            $(#[$reverse_iterator_attribute:meta])*
            struct $reverse_iterator:ident;

        // Internal almost-iterator that is being delegated to
        internal:
            $internal_iterator:ident yielding ($iterty:ty);

        // Kind of delegation - either single ended or double ended
        delegate $($t:tt)*
    } => {
        $(#[$forward_iterator_attribute])*
        pub struct $forward_iterator<'a, P: Pattern<'a>>(pub $internal_iterator<'a, P>);

        impl<'a, P> fmt::Debug for $forward_iterator<'a, P>
        where
            P: Pattern<'a>, <P as Pattern<'a>>::Searcher: fmt::Debug,
        {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_tuple(stringify!($forward_iterator))
                    .field(&self.0)
                    .finish()
            }
        }

        impl<'a, P: Pattern<'a>> Iterator for $forward_iterator<'a, P> {
            type Item = $iterty;

            #[inline]
            fn next(&mut self) -> Option<$iterty> {
                self.0.next()
            }
        }

        impl<'a, P> Clone for $forward_iterator<'a, P>
        where
            P: Pattern<'a>, <P as Pattern<'a>>::Searcher: Clone,
        {
            fn clone(&self) -> Self {
                $forward_iterator(self.0.clone())
            }
        }

        $(#[$reverse_iterator_attribute])*
        pub struct $reverse_iterator<'a, P: Pattern<'a>>(pub $internal_iterator<'a, P>);

        impl<'a, P> fmt::Debug for $reverse_iterator<'a, P>
        where
            P: Pattern<'a>, <P as Pattern<'a>>::Searcher: fmt::Debug,
        {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_tuple(stringify!($reverse_iterator))
                    .field(&self.0)
                    .finish()
            }
        }

        impl<'a, P> Iterator for $reverse_iterator<'a, P>
        where
            P: Pattern<'a>, <P as Pattern<'a>>::Searcher: ReverseSearcher<'a>,
        {
            type Item = $iterty;

            #[inline]
            fn next(&mut self) -> Option<$iterty> {
                self.0.next_back()
            }
        }

        impl<'a, P> Clone for $reverse_iterator<'a, P>
        where
            P: Pattern<'a>, <P as Pattern<'a>>::Searcher: Clone,
        {
            fn clone(&self) -> Self {
                $reverse_iterator(self.0.clone())
            }
        }

        impl<'a, P: Pattern<'a>> FusedIterator for $forward_iterator<'a, P> {}

        impl<'a, P> FusedIterator for $reverse_iterator<'a, P>
        where
            P: Pattern<'a>, <P as Pattern<'a>>::Searcher: ReverseSearcher<'a>,
        {}

        generate_pattern_iterators!($($t)* with $forward_iterator, $reverse_iterator, $iterty);
    };
    {
        double ended; with $forward_iterator:ident,
                           $reverse_iterator:ident, $iterty:ty
    } => {
        impl<'a, P> DoubleEndedIterator for $forward_iterator<'a, P>
        where
            P: Pattern<'a>, <P as Pattern<'a>>::Searcher: DoubleEndedSearcher<'a>,
        {
            #[inline]
            fn next_back(&mut self) -> Option<$iterty> {
                self.0.next_back()
            }
        }

        impl<'a, P> DoubleEndedIterator for $reverse_iterator<'a, P>
        where
            P: Pattern<'a>, <P as Pattern<'a>>::Searcher: DoubleEndedSearcher<'a>,
        {
            #[inline]
            fn next_back(&mut self) -> Option<$iterty> {
                self.0.next()
            }
        }
    };
    {
        single ended; with $forward_iterator:ident,
                           $reverse_iterator:ident, $iterty:ty
    } => {}
}

derive_pattern_clone! {
    clone SplitInternal
    with |s| SplitInternal { matcher: s.matcher.clone(), ..*s }
}

pub struct SplitInternal<'a, P: Pattern<'a>> {
    pub start: usize,
    pub end: usize,
    pub matcher: P::Searcher,
    pub allow_trailing_empty: bool,
    pub finished: bool,
}

impl<'a, P> fmt::Debug for SplitInternal<'a, P>
where
    P: Pattern<'a>, <P as Pattern<'a>>::Searcher: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SplitInternal")
            .field("start", &self.start)
            .field("end", &self.end)
            .field("matcher", &self.matcher)
            .field("allow_trailing_empty", &self.allow_trailing_empty)
            .field("finished", &self.finished)
            .finish()
    }
}

impl<'a, P: Pattern<'a>> SplitInternal<'a, P> {
    #[inline]
    fn get_end(&mut self) -> Option<&'a str> {
        if !self.finished && (self.allow_trailing_empty || self.end - self.start > 0) {
            self.finished = true;
            // SAFETY: `self.start` and `self.end` always lie on unicode boundaries.
            unsafe {
                let string = self.matcher.haystack().get_unchecked(self.start..self.end);
                Some(string)
            }
        } else {
            None
        }
    }

    #[inline]
    fn next(&mut self) -> Option<&'a str> {
        if self.finished {
            return None;
        }

        let haystack = self.matcher.haystack();
        match self.matcher.next_match() {
            // SAFETY: `Searcher` guarantees that `a` and `b` lie on unicode boundaries.
            Some((a, b)) => unsafe {
                let elt = haystack.get_unchecked(self.start..a);
                self.start = b;
                Some(elt)
            },
            None => self.get_end(),
        }
    }

    #[inline]
    #[allow(dead_code)]
    fn next_inclusive(&mut self) -> Option<&'a str> {
        if self.finished {
            return None;
        }

        let haystack = self.matcher.haystack();
        match self.matcher.next_match() {
            // SAFETY: `Searcher` guarantees that `b` lies on unicode boundary,
            // and self.start is either the start of the original string,
            // or `b` was assigned to it, so it also lies on unicode boundary.
            Some((_, b)) => unsafe {
                let elt = haystack.get_unchecked(self.start..b);
                self.start = b;
                Some(elt)
            },
            None => self.get_end(),
        }
    }

    #[inline]
    fn next_back(&mut self) -> Option<&'a str>
    where
        P::Searcher: ReverseSearcher<'a>,
    {
        if self.finished {
            return None;
        }

        if !self.allow_trailing_empty {
            self.allow_trailing_empty = true;
            match self.next_back() {
                Some(elt) if !elt.is_empty() => return Some(elt),
                _ => {
                    if self.finished {
                        return None;
                    }
                }
            }
        }

        let haystack = self.matcher.haystack();
        match self.matcher.next_match_back() {
            // SAFETY: `Searcher` guarantees that `a` and `b` lie on unicode boundaries.
            Some((a, b)) => unsafe {
                let elt = haystack.get_unchecked(b..self.end);
                self.end = a;
                Some(elt)
            },
            // SAFETY: `self.start` and `self.end` always lie on unicode boundaries.
            None => unsafe {
                self.finished = true;
                Some(haystack.get_unchecked(self.start..self.end))
            },
        }
    }

    #[inline]
    #[allow(dead_code)]
    fn next_back_inclusive(&mut self) -> Option<&'a str>
    where
        P::Searcher: ReverseSearcher<'a>,
    {
        if self.finished {
            return None;
        }

        if !self.allow_trailing_empty {
            self.allow_trailing_empty = true;
            match self.next_back_inclusive() {
                Some(elt) if !elt.is_empty() => return Some(elt),
                _ => {
                    if self.finished {
                        return None;
                    }
                }
            }
        }

        let haystack = self.matcher.haystack();
        match self.matcher.next_match_back() {
            // SAFETY: `Searcher` guarantees that `b` lies on unicode boundary,
            // and self.end is either the end of the original string,
            // or `b` was assigned to it, so it also lies on unicode boundary.
            Some((_, b)) => unsafe {
                let elt = haystack.get_unchecked(b..self.end);
                self.end = b;
                Some(elt)
            },
            // SAFETY: self.start is either the start of the original string,
            // or start of a substring that represents the part of the string that hasn't
            // iterated yet. Either way, it is guaranteed to lie on unicode boundary.
            // self.end is either the end of the original string,
            // or `b` was assigned to it, so it also lies on unicode boundary.
            None => unsafe {
                self.finished = true;
                Some(haystack.get_unchecked(self.start..self.end))
            },
        }
    }

    #[inline]
    fn as_str(&self) -> &'a str {
        // `Self::get_end` doesn't change `self.start`
        if self.finished {
            return "";
        }

        // SAFETY: `self.start` and `self.end` always lie on unicode boundaries.
        unsafe { self.matcher.haystack().get_unchecked(self.start..self.end) }
    }
}

generate_pattern_iterators! {
    forward:
        /// Created with the method [`split`].
        ///
        /// [`split`]: str::split
        struct Split;
    reverse:
        /// Created with the method [`rsplit`].
        ///
        /// [`rsplit`]: str::rsplit
        struct RSplit;
    internal:
        SplitInternal yielding (&'a str);
    delegate double ended;
}

impl<'a, P: Pattern<'a>> Split<'a, P> {
    /// Returns remainder of the splitted string
    ///
    /// # Examples
    ///
    /// ```
    /// let mut split = "Mary had a little lamb".split(' ');
    /// assert_eq!(split.as_str(), "Mary had a little lamb");
    /// split.next();
    /// assert_eq!(split.as_str(), "had a little lamb");
    /// split.by_ref().for_each(drop);
    /// assert_eq!(split.as_str(), "");
    /// ```
    #[inline]
    pub fn as_str(&self) -> &'a str {
        self.0.as_str()
    }
}

impl<'a, P: Pattern<'a>> RSplit<'a, P> {
    /// Returns remainder of the splitted string
    ///
    /// # Examples
    ///
    /// ```
    /// let mut split = "Mary had a little lamb".rsplit(' ');
    /// assert_eq!(split.as_str(), "Mary had a little lamb");
    /// split.next();
    /// assert_eq!(split.as_str(), "Mary had a little");
    /// split.by_ref().for_each(drop);
    /// assert_eq!(split.as_str(), "");
    /// ```
    #[inline]
    pub fn as_str(&self) -> &'a str {
        self.0.as_str()
    }
}

generate_pattern_iterators! {
    forward:
        /// Created with the method [`split_terminator`].
        ///
        /// [`split_terminator`]: str::split_terminator
        struct SplitTerminator;
    reverse:
        /// Created with the method [`rsplit_terminator`].
        ///
        /// [`rsplit_terminator`]: str::rsplit_terminator
        struct RSplitTerminator;
    internal:
        SplitInternal yielding (&'a str);
    delegate double ended;
}

impl<'a, P: Pattern<'a>> SplitTerminator<'a, P> {
    /// Returns remainder of the splitted string
    ///
    /// # Examples
    ///
    /// ```
    /// let mut split = "A..B..".split_terminator('.');
    /// assert_eq!(split.as_str(), "A..B..");
    /// split.next();
    /// assert_eq!(split.as_str(), ".B..");
    /// split.by_ref().for_each(drop);
    /// assert_eq!(split.as_str(), "");
    /// ```
    #[inline]
    pub fn as_str(&self) -> &'a str {
        self.0.as_str()
    }
}

impl<'a, P: Pattern<'a>> RSplitTerminator<'a, P> {
    /// Returns remainder of the splitted string
    ///
    /// # Examples
    ///
    /// ```
    /// let mut split = "A..B..".rsplit_terminator('.');
    /// assert_eq!(split.as_str(), "A..B..");
    /// split.next();
    /// assert_eq!(split.as_str(), "A..B");
    /// split.by_ref().for_each(drop);
    /// assert_eq!(split.as_str(), "");
    /// ```
    #[inline]
    pub fn as_str(&self) -> &'a str {
        self.0.as_str()
    }
}

derive_pattern_clone! {
    clone SplitNInternal
    with |s| SplitNInternal { iter: s.iter.clone(), ..*s }
}

pub struct SplitNInternal<'a, P: Pattern<'a>> {
    pub iter: SplitInternal<'a, P>,
    /// The number of splits remaining
    pub count: usize,
}

impl<'a, P> fmt::Debug for SplitNInternal<'a, P>
where
    P: Pattern<'a>, <P as Pattern<'a>>::Searcher: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SplitNInternal")
            .field("iter", &self.iter)
            .field("count", &self.count)
            .finish()
    }
}

impl<'a, P: Pattern<'a>> SplitNInternal<'a, P> {
    #[inline]
    fn next(&mut self) -> Option<&'a str> {
        match self.count {
            0 => None,
            1 => {
                self.count = 0;
                self.iter.get_end()
            }
            _ => {
                self.count -= 1;
                self.iter.next()
            }
        }
    }

    #[inline]
    fn next_back(&mut self) -> Option<&'a str>
    where
        P::Searcher: ReverseSearcher<'a>,
    {
        match self.count {
            0 => None,
            1 => {
                self.count = 0;
                self.iter.get_end()
            }
            _ => {
                self.count -= 1;
                self.iter.next_back()
            }
        }
    }

    #[inline]
    fn as_str(&self) -> &'a str {
        self.iter.as_str()
    }
}

generate_pattern_iterators! {
    forward:
        /// Created with the method [`splitn`].
        ///
        /// [`splitn`]: str::splitn
        struct SplitN;
    reverse:
        /// Created with the method [`rsplitn`].
        ///
        /// [`rsplitn`]: str::rsplitn
        struct RSplitN;
    internal:
        SplitNInternal yielding (&'a str);
    delegate single ended;
}

impl<'a, P: Pattern<'a>> SplitN<'a, P> {
    /// Returns remainder of the splitted string
    ///
    /// # Examples
    ///
    /// ```
    /// let mut split = "Mary had a little lamb".splitn(3, ' ');
    /// assert_eq!(split.as_str(), "Mary had a little lamb");
    /// split.next();
    /// assert_eq!(split.as_str(), "had a little lamb");
    /// split.by_ref().for_each(drop);
    /// assert_eq!(split.as_str(), "");
    /// ```
    #[inline]
    pub fn as_str(&self) -> &'a str {
        self.0.as_str()
    }
}

impl<'a, P: Pattern<'a>> RSplitN<'a, P> {
    /// Returns remainder of the splitted string
    ///
    /// # Examples
    ///
    /// ```
    /// let mut split = "Mary had a little lamb".rsplitn(3, ' ');
    /// assert_eq!(split.as_str(), "Mary had a little lamb");
    /// split.next();
    /// assert_eq!(split.as_str(), "Mary had a little");
    /// split.by_ref().for_each(drop);
    /// assert_eq!(split.as_str(), "");
    /// ```
    #[inline]
    pub fn as_str(&self) -> &'a str {
        self.0.as_str()
    }
}

derive_pattern_clone! {
    clone MatchIndicesInternal
    with |s| MatchIndicesInternal(s.0.clone())
}

pub struct MatchIndicesInternal<'a, P: Pattern<'a>>(pub P::Searcher);

impl<'a, P> fmt::Debug for MatchIndicesInternal<'a, P>
where
    P: Pattern<'a>, <P as Pattern<'a>>::Searcher: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("MatchIndicesInternal").field(&self.0).finish()
    }
}

impl<'a, P: Pattern<'a>> MatchIndicesInternal<'a, P> {
    #[inline]
    fn next(&mut self) -> Option<(usize, &'a str)> {
        self.0
            .next_match()
            // SAFETY: `Searcher` guarantees that `start` and `end` lie on unicode boundaries.
            .map(|(start, end)| unsafe { (start, self.0.haystack().get_unchecked(start..end)) })
    }

    #[inline]
    fn next_back(&mut self) -> Option<(usize, &'a str)>
    where
        P::Searcher: ReverseSearcher<'a>,
    {
        self.0
            .next_match_back()
            // SAFETY: `Searcher` guarantees that `start` and `end` lie on unicode boundaries.
            .map(|(start, end)| unsafe { (start, self.0.haystack().get_unchecked(start..end)) })
    }
}

generate_pattern_iterators! {
    forward:
        /// Created with the method [`match_indices`].
        ///
        /// [`match_indices`]: str::match_indices
        struct MatchIndices;
    reverse:
        /// Created with the method [`rmatch_indices`].
        ///
        /// [`rmatch_indices`]: str::rmatch_indices
        struct RMatchIndices;
    internal:
        MatchIndicesInternal yielding ((usize, &'a str));
    delegate double ended;
}

derive_pattern_clone! {
    clone MatchesInternal
    with |s| MatchesInternal(s.0.clone())
}

pub struct MatchesInternal<'a, P: Pattern<'a>>(pub P::Searcher);

impl<'a, P> fmt::Debug for MatchesInternal<'a, P>
where
    P: Pattern<'a>, <P as Pattern<'a>>::Searcher: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("MatchesInternal").field(&self.0).finish()
    }
}

impl<'a, P: Pattern<'a>> MatchesInternal<'a, P> {
    #[inline]
    fn next(&mut self) -> Option<&'a str> {
        // SAFETY: `Searcher` guarantees that `start` and `end` lie on unicode boundaries.
        self.0.next_match().map(|(a, b)| unsafe {
            // Indices are known to be on utf8 boundaries
            self.0.haystack().get_unchecked(a..b)
        })
    }

    #[inline]
    fn next_back(&mut self) -> Option<&'a str>
    where
        P::Searcher: ReverseSearcher<'a>,
    {
        // SAFETY: `Searcher` guarantees that `start` and `end` lie on unicode boundaries.
        self.0.next_match_back().map(|(a, b)| unsafe {
            // Indices are known to be on utf8 boundaries
            self.0.haystack().get_unchecked(a..b)
        })
    }
}

generate_pattern_iterators! {
    forward:
        /// Created with the method [`matches`].
        ///
        /// [`matches`]: str::matches
        struct Matches;
    reverse:
        /// Created with the method [`rmatches`].
        ///
        /// [`rmatches`]: str::rmatches
        struct RMatches;
    internal:
        MatchesInternal yielding (&'a str);
    delegate double ended;
}
