// TODO: Print parser arguments in debug/error output.

pub trait Show {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result;
}

impl std::fmt::Display for &dyn Show {
    #[inline(always)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Show::fmt(*self, f)
    }
}

impl<T: Show + ?Sized> Show for &T {
    #[inline(always)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <T as Show>::fmt(self, f)
    }
}

impl<T: Show> Show for Option<T> {
    #[inline(always)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(val) = self {
            <T as Show>::fmt(val, f)?;
        }

        Ok(())
    }
}

impl<T: Show> Show for [T] {
    #[inline(always)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, value) in self.iter().enumerate() {
            if i > 0 { write!(f, " ")?; }
            write!(f, "{}", value as &dyn Show)?;
        }

        Ok(())
    }
}

impl<T: Show + ?Sized + ToOwned> Show for std::borrow::Cow<'_, T> {
    #[inline(always)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Show::fmt(self.as_ref(), f)
    }
}

macro_rules! impl_for_slice_len {
    ($($n:expr),*) => ($(
        impl<T: Show> Show for [T; $n] {
            #[inline(always)]
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                Show::fmt(&self[..], f)
            }
        }
    )*)
}

impl_for_slice_len!(
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32
);

impl<T: Show> Show for Vec<T> {
    #[inline(always)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Show::fmt(self.as_slice(), f)
    }
}

impl Show for u8 {
    #[inline(always)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_ascii() {
            write!(f, "'{}'", char::from(*self).escape_debug())
        } else {
            write!(f, "byte {}", self)
        }
    }
}

impl_show_with! { Debug,
        u16, u32, u64, u128, usize,
    i8, i16, i32, i64, i128, isize
}

macro_rules! impl_with_tick_display {
    ($($T:ty,)*) => ($(
        impl Show for $T {
            #[inline(always)]
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{:?}", self)
            }
        }
    )*)
}

impl_with_tick_display! {
    &str, String, char, std::borrow::Cow<'static, str>,
}
