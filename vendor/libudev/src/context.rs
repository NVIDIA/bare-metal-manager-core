use ::handle::Handle;

/// A libudev context. Contexts may not be sent or shared between threads. The `libudev(3)` manpage
/// says:
///
/// > All functions require a libudev context to operate. This context can be create via
/// > udev_new(3). It is used to track library state and link objects together. No global state is
/// > used by libudev, everything is always linked to a udev context. Furthermore, multiple
/// > different udev contexts can be used in parallel by multiple threads. However, a single
/// > context must not be accessed by multiple threads in parallel.
///
/// In Rust, that means that `Context` is `!Send` and `!Sync`. This means a `Context` must be
/// created in the thread where it will be used. Several contexts can exist in separate threads,
/// but they can not be sent between threads.
///
/// Other types in this library (`Device`, `Enumerator`, `Monitor`, etc.) share a reference to a
/// context, which means that these types must also be `!Send` and `!Sync`.
pub struct Context {
    udev: *mut ::ffi::udev,
}

impl Clone for Context {
    /// Increments reference count of `libudev` context.
    fn clone(&self) -> Self {
        Context {
            udev: unsafe { ::ffi::udev_ref(self.udev) },
        }
    }
}

impl Drop for Context {
    /// Decrements reference count of `libudev` context.
    fn drop(&mut self) {
        unsafe {
            ::ffi::udev_unref(self.udev);
        }
    }
}

#[doc(hidden)]
impl Handle<::ffi::udev> for Context {
    fn as_ptr(&self) -> *mut ::ffi::udev {
        self.udev
    }
}

impl Context {
    /// Creates a new context.
    pub fn new() -> ::Result<Self> {
        Ok(Context {
            udev: try_alloc!(unsafe { ::ffi::udev_new() }),
        })
    }
}
