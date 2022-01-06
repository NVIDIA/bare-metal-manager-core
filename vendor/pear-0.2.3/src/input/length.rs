/// Trait implemented for types that have a length as required by the
/// [`Input::Slice`](crate::input::Input::Slice) associated type.
pub trait Length {
    /// Returns the length of `self`.
    ///
    /// While the units of length are unspecified, the returned value must be
    /// consistent with the use of `n` in the [`Input::slice()`] method. In
    /// particular, if [`Input::slice(n)`] returns `Some(x)`, then `x.len()`
    /// must return `n`.
    ///
    /// [`Input::slice()`]: crate::input::Input::slice()
    /// [`Input::slice(n)`]: crate::input::Input::slice()
    fn len(&self) -> usize;

    /// Returns true iff the length of `self` is equal to zero.
    fn is_empty(&self) -> bool { self.len() == 0 }
}

impl Length for str {
    #[inline(always)]
    fn len(&self) -> usize {
        str::len(self)
    }
}

impl<'a, T> Length for &'a [T] {
    #[inline(always)]
    fn len(&self) -> usize {
        <[T]>::len(self)
    }
}

macro_rules! impl_length_for_sized_slice {
    ($($size:expr),*) => ($(
        impl<'a, T> Length for &'a [T; $size] {
            #[inline(always)] fn len(&self) -> usize { $size }
        }
    )*)
}

impl_length_for_sized_slice! {
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
    10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
    20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
    30, 31, 32
}

impl<T> Length for [T] {
    #[inline(always)]
    fn len(&self) -> usize {
        <[T]>::len(self)
    }
}

impl<T> Length for Vec<T> {
    #[inline(always)]
    fn len(&self) -> usize {
        <Vec<T>>::len(self)
    }
}

impl<'a> Length for &'a str {
    #[inline(always)]
    fn len(&self) -> usize {
        str::len(self)
    }
}

impl Length for String {
    #[inline(always)]
    fn len(&self) -> usize {
        String::len(self)
    }
}
