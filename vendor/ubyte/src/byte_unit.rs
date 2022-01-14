/// A unit of bytes with saturating `const` constructors and arithmetic.
///
/// # Overview
///
/// A `ByteUnit` represents a unit, a count, a number, of bytes. All operations
/// on a `ByteUnit` -- constructors, arithmetic, conversions -- saturate.
/// Overflow, underflow, and divide-by-zero are impossible. See the [top-level
/// documentation](./index.html) for more.
///
/// [`ToByteUnit`] provides human-friendly methods on all integer types for
/// converting into a `ByteUnit`: [`512.megabytes()`](ToByteUnit::megabytes).
///
/// # Parsing
///
/// `ByteUnit` implements `FromStr` for parsing byte unit strings into a
/// `ByteUnit`. The grammar accepted by the parser is:
///
/// ```ebnf
/// byte_unit := uint+ ('.' uint+)? WHITESPACE* suffix
///
/// uint := '0'..'9'
/// suffix := case insensitive SI byte unit suffix ('b' to 'eib')
/// WHITESPACE := the ' ' character
/// ```
///
/// ```rust
/// use ubyte::{ByteUnit, ToByteUnit};
///
/// let one_gib: ByteUnit = "1GiB".parse().unwrap();
/// assert_eq!(one_gib, 1.gibibytes());
///
/// let quarter_mb: ByteUnit = "256 kB".parse().unwrap();
/// assert_eq!(quarter_mb, 256.kilobytes());
///
/// let half_mb: ByteUnit = "0.5MB".parse().unwrap();
/// assert_eq!(half_mb, 500.kilobytes());
///
/// let half_mib: ByteUnit = "0.500 mib".parse().unwrap();
/// assert_eq!(half_mib, 512.kibibytes());
///
/// let some_mb: ByteUnit = "20.5MB".parse().unwrap();
/// assert_eq!(some_mb, 20.megabytes() + 500.kilobytes());
/// ```
///
/// # (De)serialization
///
/// With the `serde` feaure enabled (disabled by default), `ByteUnit` implements
/// [`Deserialize`](#impl-Deserialize<%27de>) from strings, using the same
/// grammar as the `FromStr` implementation, defined above, as well as all
/// integer types. The [`Serialize`](struct.ByteUnit.html#impl-Serialize)
/// implementation serializes into a `u64`.
///
/// # Example
///
/// ```rust
/// use ubyte::{ByteUnit, ToByteUnit};
///
/// // Construct with unit-valued associated constants, `const` constructors, or
/// // human-friendly methods from the `ToByteUnit` integer extension trait.
/// const HALF_GB: ByteUnit = ByteUnit::Megabyte(500);
/// const HALF_GIB: ByteUnit = ByteUnit::Mebibyte(512);
/// let half_gb = 500 * ByteUnit::MB;
/// let half_gib = 512 * ByteUnit::MiB;
/// let half_gb = 500.megabytes();
/// let half_gib = 512.mebibytes();
///
/// // All arithmetic operations and conversions saturate.
/// let exbibyte = ByteUnit::Exbibyte(1);
/// let exbibyte_too_large_a = 1024 * ByteUnit::EiB;
/// let exbibyte_too_large_b = ByteUnit::Exbibyte(1024);
/// let exbibyte_too_large_c = 1024.exbibytes();
/// let div_by_zero = 1024.exbibytes() / 0;
/// let too_small = 1000.megabytes() - 1.gibibytes();
/// assert_eq!(exbibyte << 4, ByteUnit::max_value());
/// assert_eq!(exbibyte << 10, ByteUnit::max_value());
/// assert_eq!(exbibyte_too_large_a, ByteUnit::max_value());
/// assert_eq!(exbibyte_too_large_b, ByteUnit::max_value());
/// assert_eq!(exbibyte_too_large_c, ByteUnit::max_value());
/// assert_eq!(div_by_zero, ByteUnit::max_value());
/// assert_eq!(too_small, 0);
/// ```
#[repr(transparent)]
#[derive(Debug, Copy, Clone, Eq, Hash, Ord)]
pub struct ByteUnit(pub(crate) u64);

macro_rules! rem_and_suffix {
    ($n:expr => $(($isuffix:ident, $suffix:ident)),+ $or_else:ident) => {
        loop {
            $(
                let i_val = ByteUnit::$isuffix.as_u64();
                let s_val = ByteUnit::$suffix.as_u64();

                if $n >= s_val {
                    let (u_val, unit, string) = if $n % s_val >= i_val - s_val {
                        (i_val, ByteUnit::$isuffix, stringify!($isuffix))
                    } else {
                        (s_val, ByteUnit::$suffix, stringify!($suffix))
                    };

                    break ($n / u_val, ($n % u_val) as f64 / u_val as f64, string, unit)
                }
            )+

            break ($n, 0f64, stringify!($or_else), ByteUnit::$or_else)
        }
    };
}

macro_rules! const_if {
    ($cond:expr, $on_true:expr, $on_false:expr) => (
        [$on_false, $on_true][$cond as usize];
    )
}

macro_rules! constructor_fns {
    ($($sstr:expr, $nstr:expr, $example:expr, $suffix:ident, $name:ident = $size:expr),*) => (
        $(
            /// Number of bytes in 1
            #[doc = $sstr]
            /// (`
            #[doc = $nstr]
            /// `).
            #[allow(non_upper_case_globals)]
            pub const $suffix: ByteUnit = ByteUnit::$name(1);
        )*

        $(
            /// Constructs a `ByteUnit` representing `n`
            #[doc = $sstr]
            /// .
            ///
            /// # Example
            ///
            /// ```rust
            /// # use ubyte::ByteUnit;
            #[doc = $example]
            /// ```
            #[allow(non_snake_case)]
            pub const fn $name(n: u64) -> ByteUnit {
                let size: u64 = $size;
                let v = const_if!(n as u128 * size as u128 > u64::max_value() as u128,
                    ByteUnit::max_value().as_u128(),
                    n as u128 * size as u128
                );

                ByteUnit(v as u64)
            }
        )*
    );

    ($($suffix:ident, $name:ident = $size:expr),* $(,)?) => (
        constructor_fns!($(
            stringify!($suffix), stringify!($size), concat!(
                "assert_eq!(ByteUnit::", stringify!($name), "(10), ",
                "10 * ByteUnit::", stringify!($suffix), ");"
            ), $suffix, $name = $size
        ),*);
    )
}

impl ByteUnit {
    constructor_fns! {
        B, Byte = 1,
        kB, Kilobyte = 1_000,
        KiB, Kibibyte = 1 << 10,
        MB, Megabyte = 1_000_000,
        MiB, Mebibyte = 1 << 20,
        GB, Gigabyte = 1_000_000_000,
        GiB, Gibibyte = 1 << 30,
        TB, Terabyte = 1_000_000_000_000,
        TiB, Tebibyte = 1 << 40,
        PB, Petabyte = 1_000_000_000_000_000,
        PiB, Pebibyte = 1 << 50,
        EB, Exabyte = 1_000_000_000_000_000_000,
        EiB, Exbibyte = 1  << 60,
    }

    /// The maximum value of bytes representable by `ByteUnit`.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use ubyte::ByteUnit;
    /// assert_eq!(ByteUnit::max_value(), u64::max_value());
    /// ```
    pub const fn max_value() -> ByteUnit {
        ByteUnit(u64::max_value())
    }

    /// Returns the value of bytes represented by `self` as a `u64`.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use ubyte::ByteUnit;
    /// let int: u64 = ByteUnit::Gigabyte(4).as_u64();
    /// assert_eq!(int, 4 * ByteUnit::GB);
    ///
    /// assert_eq!(ByteUnit::Megabyte(42).as_u64(), 42 * 1_000_000);
    /// assert_eq!(ByteUnit::Exbibyte(7).as_u64(), 7 * 1 << 60);
    /// ```
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Returns the value of bytes represented by `self` as a `u128`.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use ubyte::ByteUnit;
    /// let int: u128 = ByteUnit::Gigabyte(4).as_u128();
    /// assert_eq!(int, 4 * ByteUnit::GB);
    ///
    /// assert_eq!(ByteUnit::Megabyte(42).as_u64(), 42 * 1_000_000);
    /// assert_eq!(ByteUnit::Exbibyte(7).as_u64(), 7 * 1 << 60);
    /// ```
    pub const fn as_u128(self) -> u128 {
        self.0 as u128
    }

    /// Returns the components of the minimal unit representation of `self`.
    ///
    /// The "minimal unit representation" is the representation that maximizes
    /// the SI-unit while minimizing the whole part of the value. For example,
    /// `1024.bytes()` is minimally represented by `1KiB`, while `1023.bytes()`
    /// is minimally represented by `1.023kB`.
    ///
    /// The four components returned, in tuple-order, are:
    ///   * `whole` - the whole part of the minimal representation.
    ///   * `frac` - the fractional part of the minimal representation.
    ///   * `suffix` - the suffix of the minimal representation.
    ///   * `unit` - the `1`-unit of the minimal representation.
    ///
    /// Succinctly, this is: `(whole, frac, suffix, unit)`. Observe that `(whole
    /// + frac) * unit` reconstructs the original value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use ubyte::{ByteUnit, ToByteUnit};
    ///
    /// let value = 2.mebibytes() + 512.kibibytes();
    /// assert_eq!(value.to_string(), "2.50MiB");
    ///
    /// let (whole, frac, suffix, unit) = value.repr();
    /// assert_eq!(whole, 2);
    /// assert_eq!(frac, 0.5);
    /// assert_eq!(suffix, "MiB");
    /// assert_eq!(unit, ByteUnit::MiB);
    ///
    /// let reconstructed = (whole as f64 + frac) * unit.as_u64() as f64;
    /// assert_eq!(reconstructed as u64, value);
    /// ```
    pub fn repr(self) -> (u64, f64, &'static str, ByteUnit) {
        rem_and_suffix! { self.as_u64() =>
            (EiB, EB), (TiB, TB), (GiB, GB), (MiB, MB), (KiB, kB) B
        }
    }
}

impl From<ByteUnit> for u64 {
    #[inline(always)]
    fn from(v: ByteUnit) -> Self {
        v.as_u64()
    }
}

impl From<ByteUnit> for u128 {
    #[inline(always)]
    fn from(v: ByteUnit) -> Self {
        v.as_u128()
    }
}

macro_rules! impl_from_int_unknown {
    ($T:ty) => (
        impl From<$T> for ByteUnit {
            #[inline(always)]
            fn from(value: $T) -> Self {
                if core::mem::size_of::<$T>() <= core::mem::size_of::<i64>() {
                    ByteUnit::from(value as i64)
                } else if value <= i64::max_value() as $T {
                    ByteUnit::from(value as i64)
                } else {
                    ByteUnit::max_value()
                }
            }
        }
    )
}

macro_rules! impl_from_uint_unknown {
    ($T:ty) => (
        impl From<$T> for ByteUnit {
            #[inline(always)]
            fn from(value: $T) -> Self {
                if core::mem::size_of::<$T>() <= core::mem::size_of::<u64>() {
                    ByteUnit(value as u64)
                } else if value <= u64::max_value() as $T {
                    ByteUnit(value as u64)
                } else {
                    ByteUnit::max_value()
                }
            }
        }
    )
}

macro_rules! impl_from_unsigned {
    ($T:ty) => (
        impl From<$T> for ByteUnit {
            #[inline(always)] fn from(v: $T) -> Self { ByteUnit(v as u64) }
        }
    )
}

macro_rules! impl_from_signed {
    ($T:ty) => (
        impl From<$T> for ByteUnit {
            #[inline(always)] fn from(v: $T) -> Self {
                ByteUnit(core::cmp::max(v, 0) as u64)
            }
        }
    )
}

impl_from_unsigned!(u8);
impl_from_unsigned!(u16);
impl_from_unsigned!(u32);
impl_from_unsigned!(u64);

impl_from_signed!(i8);
impl_from_signed!(i16);
impl_from_signed!(i32);
impl_from_signed!(i64);

impl_from_uint_unknown!(usize);
impl_from_uint_unknown!(u128);
impl_from_int_unknown!(isize);
impl_from_int_unknown!(i128);

macro_rules! helper_fn {
    ($kindstr:expr, $name:ident = $kind:ident) => (
        /// Converts `self` to a `ByteUnit` representing `self`
        #[doc = $kindstr]
        /// .
        #[inline(always)]
        fn $name(self) -> ByteUnit {
            self.bytes() * ByteUnit::$kind
        }
    );

    ($name:ident = $kind:ident) => (
        helper_fn!(stringify!($kind), $name = $kind);
    )
}

/// Extension trait for conversion from integer types to [`ByteUnit`].
///
/// The `ToByteUnit` trait provides methods on integer types that convert the
/// integer type into the [`ByteUnit`] unit represented by the method name. To
/// use the trait, simply import it. The trait is implemented for all integer
/// types.
///
/// As with all other `ByteUnit` operations, conversions saturate.
///
/// # Example
///
/// ```rust
/// use ubyte::ToByteUnit;
///
/// assert_eq!(512.kilobytes(), 512000.bytes());
/// assert_eq!(512.kibibytes(), 524288.bytes());
/// assert_eq!(512.kilobytes(), 512 * 1.kilobytes());
///
/// assert_eq!(1000.bytes(), 1.kilobytes());
/// assert_eq!(1000.bytes() + 24, 1.kibibytes());
/// assert_eq!(2048.mebibytes(), 2.gibibytes());
///
/// assert!(2.megabytes() + 500.kilobytes() > 2.mebibytes());
/// assert!(2.pebibytes() > 2.petabytes());
///
/// // As with other `ByteUnit` operations, conversions saturate.
/// assert_eq!((1 << 10).exbibytes(), (1 << 20).exbibytes());
/// ```
pub trait ToByteUnit: Into<ByteUnit> {
    /// Converts `self` to a `ByteUnit` representing `self` bytes.
    #[inline(always)]
    fn bytes(self) -> ByteUnit {
        self.into()
    }

    helper_fn!(kilobytes = kB);
    helper_fn!(kibibytes = KiB);
    helper_fn!(megabytes = MB);
    helper_fn!(mebibytes = MiB);
    helper_fn!(gigabytes = GB);
    helper_fn!(gibibytes = GiB);
    helper_fn!(terabytes = TB);
    helper_fn!(tibibytes = TiB);
    helper_fn!(petabytes = PB);
    helper_fn!(pebibytes = PiB);
    helper_fn!(exabytes = EB);
    helper_fn!(exbibytes = EiB);
}

impl<T: Into<ByteUnit> + Copy> ToByteUnit for T {}

/// Display `self` as best as possible. For perfectly custom display output,
/// consider using [`ByteUnit::repr()`].
///
/// # Example
///
/// ```rust
/// use ubyte::{ByteUnit, ToByteUnit};
///
/// assert_eq!(323.kilobytes().to_string(), "323kB");
/// assert_eq!(3.megabytes().to_string(), "3MB");
/// assert_eq!(3.mebibytes().to_string(), "3MiB");
///
/// assert_eq!((3.mebibytes() + 140.kilobytes()).to_string(), "3.13MiB");
/// assert_eq!((3.mebibytes() + 2.mebibytes()).to_string(), "5MiB");
/// assert_eq!((7.gigabytes() + 58.mebibytes() + 3.kilobytes()).to_string(), "7.06GB");
/// assert_eq!((7.gibibytes() + 920.mebibytes()).to_string(), "7.90GiB");
/// assert_eq!(7231.kilobytes().to_string(), "6.90MiB");
///
/// assert_eq!(format!("{:.0}", 7.gibibytes() + 920.mebibytes()), "8GiB");
/// assert_eq!(format!("{:.1}", 7.gibibytes() + 920.mebibytes()), "7.9GiB");
/// assert_eq!(format!("{:.2}", 7.gibibytes() + 920.mebibytes()), "7.90GiB");
/// assert_eq!(format!("{:.3}", 7.gibibytes() + 920.mebibytes()), "7.898GiB");
/// assert_eq!(format!("{:.4}", 7.gibibytes() + 920.mebibytes()), "7.8984GiB");
/// assert_eq!(format!("{:.4}", 7231.kilobytes()), "6.8960MiB");
/// assert_eq!(format!("{:.0}", 7231.kilobytes()), "7MiB");
/// assert_eq!(format!("{:.2}", 999.kilobytes() + 990.bytes()), "976.55KiB");
/// assert_eq!(format!("{:.0}", 999.kilobytes() + 990.bytes()), "1MB");
///
/// assert_eq!(format!("{:04.2}", 999.kilobytes() + 990.bytes()), "0976.55KiB");
/// assert_eq!(format!("{:02.0}", 999.kilobytes() + 990.bytes()), "01MB");
/// assert_eq!(format!("{:04.0}", 999.kilobytes() + 990.bytes()), "0001MB");
/// ```
impl core::fmt::Display for ByteUnit {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let (whole, rem, suffix, unit) = self.repr();
        let width = f.width().unwrap_or(0);
        if rem != 0f64 && f.precision().map(|p| p > 0).unwrap_or(true) {
            let p = f.precision().unwrap_or(2);
            let k = 10u64.pow(p as u32) as f64;
            write!(f, "{:0width$}.{:0p$.0}{}", whole, rem * k, suffix,
                p = p, width = width)
        } else if rem > 0.5f64 {
            ((whole.bytes() + 1) * unit).fmt(f)
        } else {
            write!(f, "{:0width$}{}", whole, suffix, width = width)
        }
    }
}
