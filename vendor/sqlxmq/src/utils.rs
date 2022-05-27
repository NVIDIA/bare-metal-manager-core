use std::any::Any;
use std::fmt::{self, Debug};
use std::ops::{Deref, DerefMut};

use tokio::task::JoinHandle;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Opaque<T: Any>(pub T);

impl<T: Any> Debug for Opaque<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <dyn Any>::fmt(&self.0, f)
    }
}

impl<T: Any> Deref for Opaque<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: Any> DerefMut for Opaque<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// A handle to a background task which will be automatically cancelled if
/// the handle is dropped. Extract the inner join handle to prevent this
/// behaviour.
#[derive(Debug)]
pub struct OwnedHandle(Option<JoinHandle<()>>);

impl OwnedHandle {
    /// Construct a new `OwnedHandle` from the provided `JoinHandle`
    pub fn new(inner: JoinHandle<()>) -> Self {
        Self(Some(inner))
    }
    /// Get back the original `JoinHandle`
    pub fn into_inner(mut self) -> JoinHandle<()> {
        self.0.take().expect("Only consumed once")
    }
    /// Stop the task and wait for it to finish.
    pub async fn stop(self) {
        let handle = self.into_inner();
        handle.abort();
        let _ = handle.await;
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            handle.abort();
        }
    }
}
