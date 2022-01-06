mod input;
mod length;
mod string;
mod cursor;
mod text;
mod text_file;
mod show;
mod pear;

pub use self::pear::{Pear, Debugger, Options};
pub use input::{Input, Rewind, Token, Slice, ParserInfo};
pub use cursor::{Cursor, Extent};
pub use text::{Text, Span};
pub use length::Length;
pub use show::Show;

use crate::error;

pub type Expected<I> = error::Expected<<I as Input>::Token, <I as Input>::Slice>;
pub type ParseError<I> = error::ParseError<<I as Input>::Context, Expected<I>>;
pub type Result<T, I> = std::result::Result<T, ParseError<I>>;

// TODO: Implement new inputs: `Bytes` (akin to `Text`), `Cursor` but for
// files/anything `Read`.
