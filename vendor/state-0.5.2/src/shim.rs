#[cfg(not(loom))] pub use std::sync;
#[cfg(loom)] pub use loom::sync;

pub mod cell {
    #[cfg(not(loom))] type Inner<T> = std::cell::UnsafeCell<T>;
    #[cfg(loom)] type Inner<T> = loom::cell::UnsafeCell<T>;

    #[derive(Debug)]
    pub struct UnsafeCell<T>(Inner<T>);

    impl<T> UnsafeCell<T> {
        #[cfg(not(loom))]
        #[inline(always)]
        pub const fn new(data: T) -> UnsafeCell<T> {
            UnsafeCell(Inner::new(data))
        }

        #[cfg(loom)]
        #[cfg_attr(loom_nightly, track_caller)]
        pub fn new(data: T) -> UnsafeCell<T> {
            UnsafeCell(Inner::new(data))
        }

        #[inline(always)]
        #[cfg_attr(loom_nightly, track_caller)]
        pub fn with<R>(&self, f: impl FnOnce(*const T) -> R) -> R {
            #[cfg(not(loom))] { f(self.0.get()) }
            #[cfg(loom)] { self.0.with(f) }
        }

        #[inline(always)]
        #[cfg_attr(loom_nightly, track_caller)]
        pub fn with_mut<R>(&self, f: impl FnOnce(*mut T) -> R) -> R {
            #[cfg(not(loom))] { f(self.0.get()) }
            #[cfg(loom)] { self.0.with_mut(f) }
        }

        #[inline(always)]
        #[cfg_attr(loom_nightly, track_caller)]
        pub fn get_mut(&mut self) -> &mut T {
            // SAFETY: This is the fully safe `UnsafeCell::get_mut()` introduced
            // in Rust 1.50.0. We don't use it to keep the MSRV down.
            #[cfg(not(loom))] unsafe { &mut *self.0.get() }
            #[cfg(loom)] { self.with_mut(|ptr| unsafe { &mut *ptr }) }
        }

        #[inline(always)]
        #[cfg_attr(loom_nightly, track_caller)]
        pub fn into_inner(self) -> T {
            #[cfg(not(loom))] { self.0.into_inner() }
            #[cfg(loom)] {
                let value = self.with(|ptr| unsafe { std::ptr::read(ptr) });
                std::mem::forget(self);
                value
            }
        }
    }
}

#[cfg(loom)] pub use loom::thread_local;
#[cfg(not(loom))] pub use std::thread_local;

#[cfg(loom)] pub use loom::thread;
#[cfg(not(loom))] pub use std::thread;
