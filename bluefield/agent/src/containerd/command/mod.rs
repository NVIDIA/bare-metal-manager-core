use std::hash::{Hash, Hasher};

use crate::containerd::{AsAny, DynEq, DynHash};

pub mod bash_command;
pub mod cache;
pub mod wrapper;

#[async_trait::async_trait]
pub trait Command: AsAny + DynHash + DynEq + std::fmt::Debug + Send + Sync + CommandClone {
    async fn run(&mut self) -> eyre::Result<String>;
}

// implementation of Hash for Command
impl Hash for dyn Command {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.dyn_hash(state);
    }
}

impl PartialEq for dyn Command {
    fn eq(&self, other: &dyn Command) -> bool {
        DynEq::dyn_eq(self, other.as_any())
    }
}

impl Eq for dyn Command {}
// end implementation of Hash for Command

pub trait CommandClone: Send + Sync {
    fn clone_box(&self) -> Box<dyn Command>;
}

impl<T> CommandClone for T
where
    T: 'static + Command + Clone,
{
    fn clone_box(&self) -> Box<dyn Command> {
        Box::new(self.clone())
    }
}

// We can now implement Clone manually by forwarding to clone_box.
impl Clone for Box<dyn Command> {
    fn clone(&self) -> Box<dyn Command> {
        self.clone_box()
    }
}
