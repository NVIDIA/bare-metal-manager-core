//! Macros.
//!
//!
//!   * [`parse_declare!`](#parse_declare)
//!   * [`parse_error!`](#parse_error)
//!   * [`impl_show_with!`](#impl_show_with)
//!
//! [`Input`]: crate::input::Input
//! [`Result<O, I>`]: crate::result::Result
//! [`Input::mark()`]: crate::input::Input::mark()
//! [`Input::unmark()`]: crate::input::Input::unmark()
//! [`Input::context()`]: crate::input::Input::context()
//! [`ParseError::push_context()`]: crate::error::ParseError::push_context()
//! [`eof()`]: crate::parsers::eof()

#[doc(inline)]
pub use pear_codegen::{parser, switch};
#[doc(inline)]
pub use crate::{parse, parse_declare, parse_error, parse_try, is_parse_debug};
#[doc(inline)]
pub use crate::{parse_current_marker, parse_last_marker, parse_mark, parse_context};
#[doc(inline)]
pub use crate::impl_show_with;

/// Runs the parser with the given name and input, then [`parsers::eof()`].
///
/// Returns the combined result.
///
/// Syntax:
///
/// ```text
/// parse := PARSER_NAME ( '(' (EXPR ',')* ')' )? ':' INPUT_EXPR
///
/// PARSER_NAME := rust identifier to parser function
/// INPUT_EXPR := any valid rust expression which resolves to a mutable
///               reference to type that implements `Input`
/// ```
#[macro_export]
macro_rules! parse {
    ($parser:ident : &mut $e:expr) => ({
        let input = &mut $e;
        (move || {
            let result = $parser(input)?;
            $crate::parsers::eof(input).map_err(|e| e.into())?;
            $crate::result::AsResult::as_result(result)
        })()
    });
    ($parser:ident : $e:expr) => (parse!($parser(): $e));
    ($parser:ident ($($x:expr),*) : $e:expr) => ({
        let mut input: $crate::input::Pear<_> = $e.into();
        (move || {
            let result = $parser(&mut input $(, $x)*)?;
            $crate::parsers::eof(&mut input).map_err(|e| e.into())?;
            $crate::result::AsResult::as_result(result)
        })()
    })
}

#[doc(hidden)]
#[macro_export(local_inner_macros)]
macro_rules! parse_declare {
    (pub($($inner:tt)+) $($rest:tt)*) => { $crate::_parse_declare!([pub($($inner)+)] $($rest)*); };
    (pub $($rest:tt)*) => { $crate::_parse_declare!([pub] $($rest)*); };
    ($($rest:tt)*) => { $crate::_parse_declare!([] $($rest)*); }
}

#[doc(hidden)]
#[macro_export(local_inner_macros)]
macro_rules! _parse_declare {
    ([$($vis:tt)*] $input:ident $(<$($gen:tt),+>)* ($($T:ident = $t:ty),*)) => {
        $($vis)* trait $input $(<$($gen),+>)*: $crate::input::Input<$($T = $t),*> {  }

        impl<$($($gen,)+)* T> $input $(<$($gen)+>)* for T
            where T: $crate::input::Input<$($T = $t),*> + $($($gen),+)* {  }
    }
}

/// Like `format!` but tries to inline the string.
#[doc(hidden)]
#[macro_export]
macro_rules! iformat {
    () => (iformat!("",));
    ($fmt:expr) => (iformat!($fmt,));
    ($fmt:expr, $($arg:tt)*) => ({
        #[allow(unused_imports)]
        use std::fmt::Write;
        #[allow(unused_imports)]
        use $crate::inlinable_string::{InlinableString, StringExt};
        let mut string = $crate::inlinable_string::InlinableString::new();
        let _ = write!(string, $fmt, $($arg)*);
        string
    })
}

/// Returns an `Err(ParseError::new($e))`. Can used like `format!` as well.
#[macro_export]
macro_rules! parse_error {
    ([$info:expr; $input:expr; $marker:expr; $T:ty] $err:expr) => ({
        let context = $crate::parse_context!([$info; $input; $marker; $T]);
        Err($crate::error::ParseError::new(*$info, $err, context))
    });
    ([$n:expr; $i:expr; $m:expr; $T:ty] $fmt:expr, $($arg:tt)*) => {
        parse_error!([$n; $i; $m; $T] $crate::iformat!($fmt, $($arg)*))
    };
}

/// Returns the last marker that was set.
///
/// Invoked with no arguments: `parse_marker!()`
#[macro_export]
macro_rules! parse_last_marker {
    ([$n:expr; $i:expr; $marker:expr; $T:ty]) => (*$marker);
}

/// Return the mark at the current parsing position.
///
/// Invoked with no arguments: `parse_current_marker!()`
#[macro_export]
macro_rules! parse_current_marker {
    ([$info:expr; $input:expr; $marker:expr; $T:ty]) => (
        $crate::input::Input::mark($input, $info)
    )
}

/// Sets the marker to the current position.
#[macro_export]
macro_rules! parse_mark {
    ([$info:expr; $input:expr; $marker:expr; $T:ty]) => {{
        *$marker = $crate::input::Input::mark($input, $info);
    }}
}

/// Returns the context from the current mark to the input position inclusive.
///
/// Invoked with no arguments: `parse_context!()`
#[macro_export]
macro_rules! parse_context {
    ([$n:expr; $i:expr; $marker:expr; $T:ty]) => (
        $crate::input::Input::context($i, *$marker)
    );
}

/// Runs a parser returning `Some` if it succeeds or `None` otherwise.
///
/// Take a single parser expression as input. Without additional arguments,
/// returns the output in `Some` on success. If called as `parse_try!(parse_expr
/// => result_expr)`, returns `result_expr` in `Some` on success. The result of
/// the parse expression can be pattern-binded as `parse_try!(pat@pexpr =>
/// rexpr)`.
// FIXME: This is an issue with rustc here where if `$input` is `expr`
// everything fails.
#[macro_export]
macro_rules! parse_try {
    ([$n:expr; $input:ident; $m:expr; $T:ty] $e:expr) => {{
        $crate::macros::switch! { [$n;$input;$m;$T] result@$e => { Some(result) }, _ => { None } }
    }};
    ([$n:expr; $input:ident; $m:expr; $T:ty] $e:expr => $r:expr) => {{
        $crate::macros::switch! { [$n;$input;$m;$T] $e => { Some($r) }, _ => { None } }
    }};
    ([$n:expr; $input:ident; $m:expr; $T:ty] $e:expr => $r:expr => || $f:expr) => {{
        $crate::macros::switch! { [$n;$input;$m;$T] $e => { $r }, _ => { $f } }
    }};
    ([$n:expr; $input:ident; $m:expr; $T:ty] $pat:ident@$e:expr => $r:expr) => {{
        $crate::macros::switch! { [$n;$input;$m;$T] $pat@$e => { Some($r) }, _ => { None } }
    }}
}

#[doc(hidden)]
#[macro_export]
macro_rules! is_parse_debug {
    () => ({
        #[cfg(not(debug_assertions))] { false }
        #[cfg(debug_assertions)] { ::std::env::var("PARSE_DEBUG").is_ok() }
    });

    ($kind:expr) => ({
        #[cfg(not(debug_assertions))] { false }
        #[cfg(debug_assertions)] {
            ::std::env::var("PARSE_DEBUG").map(|v| v == $kind).unwrap_or(false)
        }
    })
}

/// Implements the `Show` trait for $($T)+ using the existing trait `$trait`.
#[macro_export]
macro_rules! impl_show_with {
    ($trait:ident, $($T:ty),+) => (
        $(impl $crate::input::Show for $T {
            #[inline(always)]
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                std::fmt::$trait::fmt(self, f)
            }
        })+
    )
}
