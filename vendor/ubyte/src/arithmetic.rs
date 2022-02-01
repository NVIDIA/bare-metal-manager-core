use core::cmp::Ordering;
use core::ops::{Mul, Add, Shl, Sub, Div, Shr, Rem};

use crate::ByteUnit;

impl<T: Into<ByteUnit>> Mul<T> for ByteUnit {
    type Output = Self;

    #[inline(always)]
    fn mul(self, rhs: T) -> Self::Output {
        ByteUnit(self.0.saturating_mul(rhs.into().0))
    }
}

impl<T: Into<ByteUnit>> Div<T> for ByteUnit {
    type Output = Self;

    #[inline(always)]
    fn div(self, rhs: T) -> Self::Output {
        let value = rhs.into().0;
        match value {
            0 => ByteUnit::max_value(),
            _ => ByteUnit(self.0 / value)
        }
    }
}

impl<T: Into<ByteUnit>> Rem<T> for ByteUnit {
    type Output = Self;

    #[inline(always)]
    fn rem(self, rhs: T) -> Self::Output {
        let value = rhs.into().0;
        match value {
            0 => ByteUnit(0),
            _ => ByteUnit(self.0 % value)
        }
    }
}

impl<T: Into<ByteUnit>> Add<T> for ByteUnit {
    type Output = Self;

    #[inline(always)]
    fn add(self, rhs: T) -> Self::Output {
        ByteUnit(self.0.saturating_add(rhs.into().0))
    }
}

impl<T: Into<ByteUnit>> Sub<T> for ByteUnit {
    type Output = Self;

    #[inline(always)]
    fn sub(self, rhs: T) -> Self::Output {
        ByteUnit(self.0.saturating_sub(rhs.into().0))
    }
}

impl<T: Into<ByteUnit>> Shl<T> for ByteUnit {
    type Output = Self;
    fn shl(self, rhs: T) -> Self::Output {
        let wanted = rhs.into().0;
        let available = self.0.leading_zeros() as u64;
        if wanted > available {
            ByteUnit::max_value()
        } else {
            ByteUnit(self.0 << wanted)
        }
    }
}

impl<T: Into<ByteUnit>> Shr<T> for ByteUnit {
    type Output = Self;
    fn shr(self, rhs: T) -> Self::Output {
        ByteUnit(self.0 >> rhs.into().0)
    }
}

impl<T: Into<ByteUnit> + Copy> PartialEq<T> for ByteUnit {
    fn eq(&self, other: &T) -> bool {
        self.0 == (*other).into().0
    }
}

impl<T: Into<ByteUnit> + Copy> PartialOrd<T> for ByteUnit {
    fn partial_cmp(&self, other: &T) -> Option<Ordering> {
        self.0.partial_cmp(&(*other).into().0)
    }
}

macro_rules! impl_arith_ops_on_core {
    ($T:ty) => (
        impl Mul<ByteUnit> for $T {
            type Output = ByteUnit;

            #[inline(always)]
            fn mul(self, rhs: ByteUnit) -> Self::Output {
                ByteUnit::from(self) * rhs
            }
        }

        impl Div<ByteUnit> for $T {
            type Output = ByteUnit;

            #[inline(always)]
            fn div(self, rhs: ByteUnit) -> Self::Output {
                ByteUnit::from(self) / rhs
            }
        }

        impl Rem<ByteUnit> for $T {
            type Output = ByteUnit;

            #[inline(always)]
            fn rem(self, rhs: ByteUnit) -> Self::Output {
                ByteUnit::from(self) % rhs
            }
        }

        impl Add<ByteUnit> for $T {
            type Output = ByteUnit;

            #[inline(always)]
            fn add(self, rhs: ByteUnit) -> Self::Output {
                ByteUnit::from(self) + rhs
            }
        }

        impl Sub<ByteUnit> for $T {
            type Output = ByteUnit;

            #[inline(always)]
            fn sub(self, rhs: ByteUnit) -> Self::Output {
                ByteUnit::from(self) - rhs
            }
        }

        impl Shr<ByteUnit> for $T {
            type Output = ByteUnit;

            #[inline(always)]
            fn shr(self, rhs: ByteUnit) -> Self::Output {
                ByteUnit::from(self) >> rhs
            }
        }

        impl Shl<ByteUnit> for $T {
            type Output = ByteUnit;

            #[inline(always)]
            fn shl(self, rhs: ByteUnit) -> Self::Output {
                ByteUnit::from(self) << rhs
            }
        }

        impl PartialEq<ByteUnit> for $T {
            #[inline(always)]
            fn eq(&self, other: &ByteUnit) -> bool {
                ByteUnit::from(*self).eq(other)
            }
        }

        impl PartialOrd<ByteUnit> for $T {
            #[inline(always)]
            fn partial_cmp(&self, other: &ByteUnit) -> Option<Ordering> {
                ByteUnit::from(*self).partial_cmp(other)
            }
        }
    )
}

impl_arith_ops_on_core!(usize);
impl_arith_ops_on_core!(u8);
impl_arith_ops_on_core!(u16);
impl_arith_ops_on_core!(u32);
impl_arith_ops_on_core!(u64);
impl_arith_ops_on_core!(u128);

impl_arith_ops_on_core!(isize);
impl_arith_ops_on_core!(i8);
impl_arith_ops_on_core!(i16);
impl_arith_ops_on_core!(i32);
impl_arith_ops_on_core!(i64);
impl_arith_ops_on_core!(i128);

#[cfg(test)]
mod tests {
    use crate::{ByteUnit, ToByteUnit};

    #[test]
    fn test_saturation() {
        assert_eq!(ByteUnit::B * -1, 0);
        assert_eq!(ByteUnit::B * -3, 0);
        assert_eq!(ByteUnit::B / -3, ByteUnit::max_value());
        assert_eq!(ByteUnit::B - 100, 0);
        assert_eq!((100 * ByteUnit::B) % -10, 0);

        // These are suprising, but ~correct. Should we document?
        assert_eq!(ByteUnit::B + (-100i32), 1);
        assert_eq!(-100 + ByteUnit::B, 1);
    }

    #[test]
    fn test_core_types_operations() {
        assert_eq!(1000 - 300.bytes(), 700);
        assert_eq!(1024 >> 2.bytes(), 256);
        assert_eq!(2 << 2.bytes(), 8);
        assert_eq!(2048 / 4.bytes(), 512);
        assert!((500 + 700) < 2.mebibytes());
        assert!((500 + 700) > 2.bytes());
    }
}
