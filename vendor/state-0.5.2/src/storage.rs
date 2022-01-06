use std::fmt;

use crate::cell::UnsafeCell;
use crate::init::Init;

/// A single storage location for global access to a value.
///
/// A `Storage` instance can hold a single value in a global context. A
/// `Storage` instance begins without a value and must be initialized via the
/// [set](#method.set) method. Once a value has been set, it can be retrieved at
/// any time and in any thread via the [get](#method.get) method. The
/// [try_get](#method.try_get) can be used to determine whether the `Storage`
/// has been initialized before attempting to retrieve the value.
///
/// For safety reasons, values stored in `Storage` must be `Send + Sync`.
///
/// # Example
///
/// The following example uses `Storage` to hold a global instance of a
/// `HashMap` which can be modified at will:
///
/// ```rust
/// use std::collections::HashMap;
/// use std::sync::Mutex;
/// use std::thread;
///
/// use state::Storage;
///
/// static GLOBAL_MAP: Storage<Mutex<HashMap<String, String>>> = Storage::new();
///
/// fn run_program() {
///     let mut map = GLOBAL_MAP.get().lock().unwrap();
///     map.insert("another_key".into(), "another_value".into());
/// }
///
/// fn main() {
///     // Create the initial map and store it in `GLOBAL_MAP`.
///     let mut initial_map = HashMap::new();
///     initial_map.insert("key".into(), "value".into());
///     GLOBAL_MAP.set(Mutex::new(initial_map));
///
///     // For illustration, we spawn a new thread that modified the map.
///     thread::spawn(|| run_program()).join().expect("thread");
///
///     // Assert that the modification took place.
///     let map = GLOBAL_MAP.get().lock().unwrap();
///     assert_eq!(map.get("another_key").unwrap(), "another_value");
/// }
pub struct Storage<T> {
    item: UnsafeCell<Option<T>>,
    init: Init
}

impl<T> Storage<T> {
    /// Create a new, uninitialized storage location.
    ///
    /// # Example
    ///
    /// ```rust
    /// use state::Storage;
    ///
    /// static MY_GLOBAL: Storage<String> = Storage::new();
    /// ```
    #[cfg(not(loom))]
    pub const fn new() -> Storage<T> {
        Storage {
            item: UnsafeCell::new(None),
            init: Init::new()
        }
    }

    /// New, for loom.
    #[cfg(loom)]
    pub fn new() -> Storage<T> {
        Storage {
            item: UnsafeCell::new(None),
            init: Init::new()
        }
    }
}

impl<T: Send + Sync> Storage<T> {
    /// Sets the value for this storage unit to `value` if it has not already
    /// been set before.
    ///
    /// If a value has previously been set, `self` is unchanged and `false` is
    /// returned. Otherwise `true` is returned.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use state::Storage;
    /// static MY_GLOBAL: Storage<&'static str> = Storage::new();
    ///
    /// assert_eq!(MY_GLOBAL.set("Hello, world!"), true);
    /// assert_eq!(MY_GLOBAL.set("Goodbye, world!"), false);
    /// ```
    pub fn set(&self, value: T) -> bool {
        if self.init.needed() {
            unsafe { self.item.with_mut(|ptr| *ptr = Some(value)); }
            self.init.mark_complete();
            return true;
        }

        false
    }

    /// Attempts to borrow the value in this storage location.
    ///
    /// Returns `Some` if the state has previously been [set](#method.set).
    /// Otherwise returns `None`.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use state::Storage;
    /// static MY_GLOBAL: Storage<&'static str> = Storage::new();
    ///
    /// assert_eq!(MY_GLOBAL.try_get(), None);
    ///
    /// MY_GLOBAL.set("Hello, world!");
    ///
    /// assert_eq!(MY_GLOBAL.try_get(), Some(&"Hello, world!"));
    /// ```
    #[inline]
    pub fn try_get(&self) -> Option<&T> {
        if !self.init.has_completed() {
            return None
        }

        unsafe {
            self.item.with(|ptr| (*ptr).as_ref())
        }
    }

    /// Borrows the value in this storage location.
    ///
    /// # Panics
    ///
    /// Panics if a value has not previously been [`set()`](#method.set). Use
    /// [`try_get()`](#method.try_get) for a non-panicking version.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use state::Storage;
    /// static MY_GLOBAL: Storage<&'static str> = Storage::new();
    ///
    /// MY_GLOBAL.set("Hello, world!");
    /// assert_eq!(*MY_GLOBAL.get(), "Hello, world!");
    /// ```
    #[inline]
    pub fn get(&self) -> &T {
        self.try_get()
            .expect("storage::get(): called get() before set()")
    }

    /// If the storage location has not yet been set, it is set to the return
    /// value of `from`. Returns a borrow to the value in this storage location.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use state::Storage;
    /// static MY_GLOBAL: Storage<&'static str> = Storage::new();
    ///
    /// assert_eq!(*MY_GLOBAL.get_or_set(|| "Hello, world!"), "Hello, world!");
    /// ```
    #[inline]
    pub fn get_or_set<F: FnOnce() -> T>(&self, from: F) -> &T {
        if let Some(value) = self.try_get() {
            value
        } else {
            self.set(from());
            self.get()
        }
    }

    /// Returns a mutable reference to the underlying data if any is set.
    ///
    /// This call borrows `Storage` mutably (at compile-time) so there is no
    /// need for dynamic checks.
    ///
    /// # Example
    ///
    /// ```rust
    /// use state::Storage;
    ///
    /// let mut storage = Storage::from(5);
    /// *storage.try_get_mut().unwrap() += 1;
    ///
    /// let mut storage: Storage<usize> = Storage::new();
    /// assert!(storage.try_get_mut().is_none());
    /// ```
    pub fn try_get_mut(&mut self) -> Option<&mut T> {
        self.item.get_mut().as_mut()
    }

    /// Returns the inner value if any is set.
    ///
    /// # Example
    ///
    /// ```rust
    /// use state::Storage;
    ///
    /// let storage = Storage::from(5);
    /// assert_eq!(storage.into_inner().unwrap(), 5);
    ///
    /// let storage: Storage<usize> = Storage::new();
    /// assert!(storage.into_inner().is_none());
    /// ```
    pub fn into_inner(self) -> Option<T> {
        self.item.into_inner()
    }

    /// Applies the function `f` to the inner value, if there is any, and
    /// returns a new `Storage` with mapped value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use state::Storage;
    ///
    /// let storage = Storage::from(5);
    /// assert_eq!(storage.get(), &5);
    ///
    /// let storage = storage.map(|v| v + 10);
    /// assert_eq!(storage.get(), &15);
    /// ```
    pub fn map<U: Send + Sync, F: FnOnce(T) -> U>(self, f: F) -> Storage<U> {
        self.into_inner()
            .map(|v| Storage::from(f(v)))
            .unwrap_or_else(|| Storage::new())
    }
}

unsafe impl<T: Send + Sync> Sync for Storage<T> {  }

unsafe impl<T: Send + Sync> Send for Storage<T> {  }

impl<T: fmt::Debug + Send + Sync> fmt::Debug for Storage<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self.try_get() {
            Some(object) => object.fmt(f),
            None => write!(f, "[uninitialized storage]")
        }
    }
}

impl<T: Send + Sync> From<T> for Storage<T> {
    fn from(value: T) -> Storage<T> {
        let storage = Storage::new();
        assert!(storage.set(value));
        storage
    }
}

impl<T: Clone + Send + Sync> Clone for Storage<T> {
    fn clone(&self) -> Storage<T> {
        match self.try_get() {
            Some(val) => Storage::from(val.clone()),
            None => Storage::new()
        }
    }
}
