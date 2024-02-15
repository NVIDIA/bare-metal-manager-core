use std::any::Any;
use std::hash::{Hash, Hasher};

pub use command::bash_command::BashCommand;
pub use command::wrapper::CommandWrapper;
pub use command::Command;
pub mod container;

pub mod command;

pub mod image;

// AsAny
pub trait AsAny {
    fn as_any(&self) -> &dyn Any;
}

impl<T: Any> crate::containerd::AsAny for T {
    fn as_any(&self) -> &dyn Any {
        self
    }
}
// end AsAny

// DynHash
pub trait DynHash {
    fn dyn_hash(&self, state: &mut dyn Hasher);
}

impl<H: Hash + ?Sized> DynHash for H {
    fn dyn_hash(&self, mut state: &mut dyn Hasher) {
        self.hash(&mut state);
    }
}
// end DynHash

// DynEq
pub trait DynEq {
    fn dyn_eq(&self, other: &dyn Any) -> bool;
}

impl<T: Eq + Any> DynEq for T {
    fn dyn_eq(&self, other: &dyn Any) -> bool {
        if let Some(other) = other.downcast_ref::<Self>() {
            self == other
        } else {
            false
        }
    }
}
// end DynEq
