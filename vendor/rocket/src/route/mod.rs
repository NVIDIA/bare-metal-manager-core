//! Types and traits for routes and their request handlers and return types.

mod route;
mod handler;
mod uri;
mod segment;

pub use route::*;
pub use handler::*;
pub use uri::*;

pub(crate) use segment::Segment;
