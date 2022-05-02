pub trait Handle<T> {
    fn as_ptr(&self) -> *mut T;
}
