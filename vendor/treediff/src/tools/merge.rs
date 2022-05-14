use crate::traitdef::{Delegate, Mutable};
use std::{borrow::BorrowMut, borrow::Cow, fmt::Display, marker::PhantomData};

/// A `Delegate` which applies differences to a target object.
///
/// It wraps the target object and applies all calls by the `diff`
/// algorithm to it, which changes it in some way.
///
/// Custom resolver functions can be provided to arbitrarily alter
/// the way the merge is performed. This allows you, for example, to
/// keep your own meta-data, or to implement custom conflict resolutions.
///
/// # Examples
/// Please see the [tests][tests] for usage examples.
/// [tests]: https://github.com/Byron/treediff-rs/blob/master/tests/merge.rs#L22
pub struct Merger<K, V, BF, F> {
    cursor: Vec<K>,
    inner: V,
    filter: BF,
    _d: PhantomData<F>,
}

fn appended<'b, K>(keys: &Vec<K>, k: Option<&'b K>) -> Vec<K>
where
    K: Clone,
{
    let mut keys = keys.clone();
    if let Some(k) = k {
        keys.push(k.clone());
    }
    keys
}

/// A filter to manipulate calls to be made to `Value`s implementing the `Mutable` trait in calls
/// made by the `Merger` `Delegate`.
///
/// This allows you to control the exact way merge operations are performed independently of the
/// type implementing the `Value` trait, which usually is not under your control.
pub trait MutableFilter {
    /// Called during `Delegate::modified(...)`, returns `None` to cause the Value at the `keys` to
    /// be removed, or any Value to be set in its place.
    ///
    /// `old` is the previous value at the given `keys` path, and `new` is the one now at its place.
    /// `_self` provides access to the target of the merge operation.
    fn resolve_conflict<'a, K: Clone + Display, V: Clone>(
        &mut self,
        _keys: &[K],
        _old: &'a V,
        new: &'a V,
        _self: &mut V,
    ) -> Option<Cow<'a, V>> {
        Some(Cow::Borrowed(new))
    }
    /// Called during `Delegate::removed(...)`, returns `None` to allow the Value at the `keys` path
    /// to be removed, or any Value to be set in its place instead.
    ///
    /// `removed` is the Value which is to be removed.
    fn resolve_removal<'a, K: Clone + Display, V: Clone>(
        &mut self,
        _keys: &[K],
        _removed: &'a V,
        _self: &mut V,
    ) -> Option<Cow<'a, V>> {
        None
    }
}

/// The default implementation used when when creating a new `Merger` from any `Value` type.
///
/// If you want to choose your own filter, use `Merger::with_filter(...)` instead.
pub struct DefaultMutableFilter;
impl MutableFilter for DefaultMutableFilter {}

impl<'a, K, V, F, BF> Delegate<'a, K, V> for Merger<K, V, BF, F>
where
    V: Mutable<Key = K, Item = V> + Clone + 'a,
    K: Clone + Display,
    F: MutableFilter,
    BF: BorrowMut<F>,
{
    fn push<'b>(&mut self, k: &'b K) {
        self.cursor.push(k.clone());
    }
    fn pop(&mut self) {
        self.cursor.pop();
    }
    fn removed<'b>(&mut self, k: &'b K, v: &'a V) {
        let keys = appended(&self.cursor, Some(k));
        match self
            .filter
            .borrow_mut()
            .resolve_removal(&keys, v, &mut self.inner)
        {
            Some(nv) => self.inner.set(&keys, &nv),
            None => self.inner.remove(&keys),
        }
    }
    fn added<'b>(&mut self, k: &'b K, v: &'a V) {
        self.inner.set(&appended(&self.cursor, Some(k)), v);
    }
    fn unchanged<'b>(&mut self, v: &'a V) {
        self.inner.set(&self.cursor, v)
    }
    fn modified<'b>(&mut self, old: &'a V, new: &'a V) {
        let keys = appended(&self.cursor, None);
        match self
            .filter
            .borrow_mut()
            .resolve_conflict(&keys, old, new, &mut self.inner)
        {
            Some(v) => self.inner.set(&keys, &v),
            None => self.inner.remove(&keys),
        }
    }
}

impl<K, V, BF, F> Merger<K, V, BF, F> {
    /// Consume the merger and return the contained target Value, which is the result of the
    /// merge operation.
    pub fn into_inner(self) -> V {
        self.inner
    }

    /// Returns a mutable borrow to the `MutableFilter` instance
    pub fn filter_mut(&mut self) -> &mut BF {
        &mut self.filter
    }

    /// Returns a borrow to the `MutableFilter` instance
    pub fn filter(&self) -> &BF {
        &self.filter
    }
}

impl<K, V, BF, F> AsRef<V> for Merger<K, V, BF, F> {
    fn as_ref(&self) -> &V {
        &self.inner
    }
}

impl<'a, V, BF, F> Merger<V::Key, V, BF, F>
where
    V: Mutable + 'a + Clone,
    F: MutableFilter,
    BF: BorrowMut<F>,
{
    /// Return a new Merger with the given initial value `v` and the filter `f`
    pub fn with_filter(v: V, f: BF) -> Self {
        Merger {
            inner: v,
            cursor: Vec::new(),
            filter: f,
            _d: PhantomData,
        }
    }
}

impl<'a, V> From<V> for Merger<V::Key, V, DefaultMutableFilter, DefaultMutableFilter>
where
    V: Mutable + 'a + Clone,
{
    /// Return a new merger with the given initial value `v`, and the `DefaultMutableFilter`.
    fn from(v: V) -> Self {
        Merger {
            inner: v,
            cursor: Vec::new(),
            filter: DefaultMutableFilter,
            _d: PhantomData,
        }
    }
}
