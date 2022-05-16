use std::fmt;

/// A representation of all key types typical Value types will assume.
#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd)]
pub enum Key {
    /// An array index
    Index(usize),
    /// A string index for mappings
    String(String),
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Key::String(ref v) => v.fmt(f),
            Key::Index(ref v) => v.fmt(f),
        }
    }
}
