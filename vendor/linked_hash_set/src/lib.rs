//! A linked hash set implementation based on the `linked_hash_map` crate.
//! See [`LinkedHashSet`](struct.LinkedHashSet.html).
//!
//! # Examples
//!
//! ```
//! let mut set = linked_hash_set::LinkedHashSet::new();
//! assert!(set.insert(234));
//! assert!(set.insert(123));
//! assert!(set.insert(345));
//! assert!(!set.insert(123)); // Also see `insert_if_absent` which won't change order
//!
//! assert_eq!(set.into_iter().collect::<Vec<_>>(), vec![234, 345, 123]);
//! ```
#[cfg(feature = "serde")]
pub mod serde;

use linked_hash_map as map;
use linked_hash_map::{Keys, LinkedHashMap};
use std::borrow::Borrow;
use std::collections::hash_map::RandomState;
use std::fmt;
use std::hash::{BuildHasher, Hash, Hasher};
use std::iter::{Chain, FromIterator};
use std::ops::{BitAnd, BitOr, BitXor, Sub};

// Note: This implementation is adapted from std `HashSet` implementation ~2017-10
// parts relying on std `HashMap` functionality that is not present in `LinkedHashMap` or
// relying on private access to map internals have been removed.

/// A linked hash set implemented as a `linked_hash_map::LinkedHashMap` where the value is
/// `()`, in a similar way std `HashSet` is implemented from `HashMap`.
///
/// General usage is very similar to a std `HashSet`. However, a `LinkedHashSet` **maintains
/// insertion order** using a doubly-linked list running through its entries. As such methods
/// [`front()`], [`pop_front()`], [`back()`] and [`pop_back()`] are provided.
///
/// # Examples
///
/// ```
/// use linked_hash_set::LinkedHashSet;
/// // Type inference lets us omit an explicit type signature (which
/// // would be `LinkedHashSet<&str>` in this example).
/// let mut books = LinkedHashSet::new();
///
/// // Add some books.
/// books.insert("A Dance With Dragons");
/// books.insert("To Kill a Mockingbird");
/// books.insert("The Odyssey");
/// books.insert("The Great Gatsby");
///
/// // Check for a specific one.
/// if !books.contains("The Winds of Winter") {
///     println!(
///         "We have {} books, but The Winds of Winter ain't one.",
///         books.len()
///     );
/// }
///
/// // Remove a book.
/// books.remove("The Odyssey");
///
/// // Remove the first inserted book.
/// books.pop_front();
///
/// // Iterate over the remaining books in insertion order.
/// for book in &books {
///     println!("{}", book);
/// }
///
/// assert_eq!(
///     books.into_iter().collect::<Vec<_>>(),
///     vec!["To Kill a Mockingbird", "The Great Gatsby"]
/// );
/// ```
///
/// The easiest way to use `LinkedHashSet` with a custom type is to derive
/// `Eq` and `Hash`. We must also derive `PartialEq`, this will in the
/// future be implied by `Eq`.
///
/// ```
/// use linked_hash_set::LinkedHashSet;
/// #[derive(Hash, Eq, PartialEq, Debug)]
/// struct Viking<'a> {
///     name: &'a str,
///     power: usize,
/// }
///
/// let mut vikings = LinkedHashSet::new();
///
/// vikings.insert(Viking {
///     name: "Einar",
///     power: 9,
/// });
/// vikings.insert(Viking {
///     name: "Einar",
///     power: 9,
/// });
/// vikings.insert(Viking {
///     name: "Olaf",
///     power: 4,
/// });
/// vikings.insert(Viking {
///     name: "Harald",
///     power: 8,
/// });
///
/// // Use derived implementation to print the vikings.
/// for x in &vikings {
///     println!("{:?}", x);
/// }
/// ```
///
/// A `LinkedHashSet` with fixed list of elements can be initialized from an array:
///
/// ```
/// use linked_hash_set::LinkedHashSet;
///
/// fn main() {
///     let viking_names: LinkedHashSet<&str> =
///         ["Einar", "Olaf", "Harald"].iter().cloned().collect();
///     // use the values stored in the set
/// }
/// ```
///
/// [`front()`]: struct.LinkedHashSet.html#method.front
/// [`pop_front()`]: struct.LinkedHashSet.html#method.pop_front
/// [`back()`]: struct.LinkedHashSet.html#method.back
/// [`pop_back()`]: struct.LinkedHashSet.html#method.pop_back
pub struct LinkedHashSet<T, S = RandomState> {
    map: LinkedHashMap<T, (), S>,
}

impl<T: Hash + Eq> LinkedHashSet<T, RandomState> {
    /// Creates an empty `LinkedHashSet`.
    ///
    /// # Examples
    ///
    /// ```
    /// use linked_hash_set::LinkedHashSet;
    /// let set: LinkedHashSet<i32> = LinkedHashSet::new();
    /// ```
    #[inline]
    pub fn new() -> LinkedHashSet<T, RandomState> {
        LinkedHashSet {
            map: LinkedHashMap::new(),
        }
    }

    /// Creates an empty `LinkedHashSet` with the specified capacity.
    ///
    /// The hash set will be able to hold at least `capacity` elements without
    /// reallocating. If `capacity` is 0, the hash set will not allocate.
    ///
    /// # Examples
    ///
    /// ```
    /// use linked_hash_set::LinkedHashSet;
    /// let set: LinkedHashSet<i32> = LinkedHashSet::with_capacity(10);
    /// assert!(set.capacity() >= 10);
    /// ```
    #[inline]
    pub fn with_capacity(capacity: usize) -> LinkedHashSet<T, RandomState> {
        LinkedHashSet {
            map: LinkedHashMap::with_capacity(capacity),
        }
    }
}

impl<T, S> LinkedHashSet<T, S>
where
    T: Eq + Hash,
    S: BuildHasher,
{
    /// Creates a new empty hash set which will use the given hasher to hash
    /// keys.
    ///
    /// The hash set is also created with the default initial capacity.
    ///
    /// Warning: `hasher` is normally randomly generated, and
    /// is designed to allow `LinkedHashSet`s to be resistant to attacks that
    /// cause many collisions and very poor performance. Setting it
    /// manually using this function can expose a DoS attack vector.
    ///
    /// # Examples
    ///
    /// ```
    /// use linked_hash_set::LinkedHashSet;
    /// use std::collections::hash_map::RandomState;
    ///
    /// let s = RandomState::new();
    /// let mut set = LinkedHashSet::with_hasher(s);
    /// set.insert(2);
    /// ```
    #[inline]
    pub fn with_hasher(hasher: S) -> LinkedHashSet<T, S> {
        LinkedHashSet {
            map: LinkedHashMap::with_hasher(hasher),
        }
    }

    /// Creates an empty `LinkedHashSet` with with the specified capacity, using
    /// `hasher` to hash the keys.
    ///
    /// The hash set will be able to hold at least `capacity` elements without
    /// reallocating. If `capacity` is 0, the hash set will not allocate.
    ///
    /// Warning: `hasher` is normally randomly generated, and
    /// is designed to allow `LinkedHashSet`s to be resistant to attacks that
    /// cause many collisions and very poor performance. Setting it
    /// manually using this function can expose a DoS attack vector.
    ///
    /// # Examples
    ///
    /// ```
    /// use linked_hash_set::LinkedHashSet;
    /// use std::collections::hash_map::RandomState;
    ///
    /// let s = RandomState::new();
    /// let mut set = LinkedHashSet::with_capacity_and_hasher(10, s);
    /// set.insert(1);
    /// ```
    #[inline]
    pub fn with_capacity_and_hasher(capacity: usize, hasher: S) -> LinkedHashSet<T, S> {
        LinkedHashSet {
            map: LinkedHashMap::with_capacity_and_hasher(capacity, hasher),
        }
    }

    /// Returns a reference to the set's `BuildHasher`.
    ///
    /// # Examples
    ///
    /// ```
    /// use linked_hash_set::LinkedHashSet;
    /// use std::collections::hash_map::RandomState;
    ///
    /// let hasher = RandomState::new();
    /// let set: LinkedHashSet<i32> = LinkedHashSet::with_hasher(hasher);
    /// let hasher: &RandomState = set.hasher();
    /// ```
    pub fn hasher(&self) -> &S {
        self.map.hasher()
    }

    /// Returns the number of elements the set can hold without reallocating.
    ///
    /// # Examples
    ///
    /// ```
    /// use linked_hash_set::LinkedHashSet;
    /// let set: LinkedHashSet<i32> = LinkedHashSet::with_capacity(100);
    /// assert!(set.capacity() >= 100);
    /// ```
    #[inline]
    pub fn capacity(&self) -> usize {
        self.map.capacity()
    }

    /// Reserves capacity for at least `additional` more elements to be inserted
    /// in the `LinkedHashSet`. The collection may reserve more space to avoid
    /// frequent reallocations.
    ///
    /// # Panics
    ///
    /// Panics if the new allocation size overflows `usize`.
    ///
    /// # Examples
    ///
    /// ```
    /// use linked_hash_set::LinkedHashSet;
    /// let mut set: LinkedHashSet<i32> = LinkedHashSet::new();
    /// set.reserve(10);
    /// assert!(set.capacity() >= 10);
    /// ```
    pub fn reserve(&mut self, additional: usize) {
        self.map.reserve(additional)
    }

    /// Shrinks the capacity of the set as much as possible. It will drop
    /// down as much as possible while maintaining the internal rules
    /// and possibly leaving some space in accordance with the resize policy.
    ///
    /// # Examples
    ///
    /// ```
    /// use linked_hash_set::LinkedHashSet;
    ///
    /// let mut set = LinkedHashSet::with_capacity(100);
    /// set.insert(1);
    /// set.insert(2);
    /// assert!(set.capacity() >= 100);
    /// set.shrink_to_fit();
    /// assert!(set.capacity() >= 2);
    /// ```
    pub fn shrink_to_fit(&mut self) {
        self.map.shrink_to_fit()
    }

    /// An iterator visiting all elements in insertion order.
    /// The iterator element type is `&'a T`.
    ///
    /// # Examples
    ///
    /// ```
    /// use linked_hash_set::LinkedHashSet;
    /// let mut set = LinkedHashSet::new();
    /// set.insert("a");
    /// set.insert("b");
    ///
    /// // Will print in an insertion order.
    /// for x in set.iter() {
    ///     println!("{}", x);
    /// }
    /// ```
    pub fn iter(&self) -> Iter<'_, T> {
        Iter {
            iter: self.map.keys(),
        }
    }

    /// Visits the values representing the difference,
    /// i.e. the values that are in `self` but not in `other`.
    ///
    /// # Examples
    ///
    /// ```
    /// use linked_hash_set::LinkedHashSet;
    /// let a: LinkedHashSet<_> = [1, 2, 3].iter().cloned().collect();
    /// let b: LinkedHashSet<_> = [4, 2, 3, 4].iter().cloned().collect();
    ///
    /// // Can be seen as `a - b`.
    /// for x in a.difference(&b) {
    ///     println!("{}", x); // Print 1
    /// }
    ///
    /// let diff: LinkedHashSet<_> = a.difference(&b).collect();
    /// assert_eq!(diff, [1].iter().collect());
    ///
    /// // Note that difference is not symmetric,
    /// // and `b - a` means something else:
    /// let diff: LinkedHashSet<_> = b.difference(&a).collect();
    /// assert_eq!(diff, [4].iter().collect());
    /// ```
    pub fn difference<'a>(&'a self, other: &'a LinkedHashSet<T, S>) -> Difference<'a, T, S> {
        Difference {
            iter: self.iter(),
            other,
        }
    }

    /// Visits the values representing the symmetric difference,
    /// i.e. the values that are in `self` or in `other` but not in both.
    ///
    /// # Examples
    ///
    /// ```
    /// use linked_hash_set::LinkedHashSet;
    /// let a: LinkedHashSet<_> = [1, 2, 3].iter().cloned().collect();
    /// let b: LinkedHashSet<_> = [4, 2, 3, 4].iter().cloned().collect();
    ///
    /// // Print 1, 4 in insertion order.
    /// for x in a.symmetric_difference(&b) {
    ///     println!("{}", x);
    /// }
    ///
    /// let diff1: LinkedHashSet<_> = a.symmetric_difference(&b).collect();
    /// let diff2: LinkedHashSet<_> = b.symmetric_difference(&a).collect();
    ///
    /// assert_eq!(diff1, diff2);
    /// assert_eq!(diff1, [1, 4].iter().collect());
    /// ```
    pub fn symmetric_difference<'a>(
        &'a self,
        other: &'a LinkedHashSet<T, S>,
    ) -> SymmetricDifference<'a, T, S> {
        SymmetricDifference {
            iter: self.difference(other).chain(other.difference(self)),
        }
    }

    /// Visits the values representing the intersection,
    /// i.e. the values that are both in `self` and `other`.
    ///
    /// # Examples
    ///
    /// ```
    /// use linked_hash_set::LinkedHashSet;
    /// let a: LinkedHashSet<_> = [1, 2, 3].iter().cloned().collect();
    /// let b: LinkedHashSet<_> = [4, 2, 3, 4].iter().cloned().collect();
    ///
    /// // Print 2, 3 in insertion order.
    /// for x in a.intersection(&b) {
    ///     println!("{}", x);
    /// }
    ///
    /// let intersection: LinkedHashSet<_> = a.intersection(&b).collect();
    /// assert_eq!(intersection, [2, 3].iter().collect());
    /// ```
    pub fn intersection<'a>(&'a self, other: &'a LinkedHashSet<T, S>) -> Intersection<'a, T, S> {
        Intersection {
            iter: self.iter(),
            other,
        }
    }

    /// Visits the values representing the union,
    /// i.e. all the values in `self` or `other`, without duplicates.
    ///
    /// # Examples
    ///
    /// ```
    /// use linked_hash_set::LinkedHashSet;
    /// let a: LinkedHashSet<_> = [1, 2, 3].iter().cloned().collect();
    /// let b: LinkedHashSet<_> = [4, 2, 3, 4].iter().cloned().collect();
    ///
    /// // Print 1, 2, 3, 4 in insertion order.
    /// for x in a.union(&b) {
    ///     println!("{}", x);
    /// }
    ///
    /// let union: LinkedHashSet<_> = a.union(&b).collect();
    /// assert_eq!(union, [1, 2, 3, 4].iter().collect());
    /// ```
    pub fn union<'a>(&'a self, other: &'a LinkedHashSet<T, S>) -> Union<'a, T, S> {
        Union {
            iter: self.iter().chain(other.difference(self)),
        }
    }

    /// Returns the number of elements in the set.
    ///
    /// # Examples
    ///
    /// ```
    /// use linked_hash_set::LinkedHashSet;
    ///
    /// let mut v = LinkedHashSet::new();
    /// assert_eq!(v.len(), 0);
    /// v.insert(1);
    /// assert_eq!(v.len(), 1);
    /// ```
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Returns true if the set contains no elements.
    ///
    /// # Examples
    ///
    /// ```
    /// use linked_hash_set::LinkedHashSet;
    ///
    /// let mut v = LinkedHashSet::new();
    /// assert!(v.is_empty());
    /// v.insert(1);
    /// assert!(!v.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    // TODO not in linked_hash_map
    // /// Clears the set, returning all elements in an iterator.
    // ///
    // /// # Examples
    // ///
    // /// ```
    // /// use linked_hash_set::LinkedHashSet;
    // ///
    // /// let mut set: LinkedHashSet<_> = [1, 2, 3].iter().cloned().collect();
    // /// assert!(!set.is_empty());
    // ///
    // /// // print 1, 2, 3 in an insertion order
    // /// for i in set.drain() {
    // ///     println!("{}", i);
    // /// }
    // ///
    // /// assert!(set.is_empty());
    // /// ```
    // #[inline]
    // pub fn drain(&mut self) -> Drain<T> {
    //     Drain { iter: self.map.drain() }
    // }

    /// Clears the set, removing all values.
    ///
    /// # Examples
    ///
    /// ```
    /// use linked_hash_set::LinkedHashSet;
    ///
    /// let mut v = LinkedHashSet::new();
    /// v.insert(1);
    /// v.clear();
    /// assert!(v.is_empty());
    /// ```
    pub fn clear(&mut self) {
        self.map.clear()
    }

    /// Returns `true` if the set contains a value.
    ///
    /// The value may be any borrowed form of the set's value type, but
    /// `Hash` and `Eq` on the borrowed form *must* match those for
    /// the value type.
    ///
    /// # Examples
    ///
    /// ```
    /// use linked_hash_set::LinkedHashSet;
    ///
    /// let set: LinkedHashSet<_> = [1, 2, 3].iter().cloned().collect();
    /// assert_eq!(set.contains(&1), true);
    /// assert_eq!(set.contains(&4), false);
    /// ```
    pub fn contains<Q: ?Sized>(&self, value: &Q) -> bool
    where
        T: Borrow<Q>,
        Q: Hash + Eq,
    {
        self.map.contains_key(value)
    }

    /// If already present, moves a value to the end of the ordering.
    ///
    /// If the set did have this value present, `true` is returned.
    ///
    /// If the set did not have this value present, `false` is returned.
    ///
    /// Similar to `LinkedHashMap::get_refresh`.
    ///
    /// # Examples
    ///
    /// ```
    /// use linked_hash_set::LinkedHashSet;
    ///
    /// let mut set: LinkedHashSet<_> = [1, 2, 3].iter().cloned().collect();
    /// let was_refreshed = set.refresh(&2);
    ///
    /// assert_eq!(was_refreshed, true);
    /// assert_eq!(set.into_iter().collect::<Vec<_>>(), vec![1, 3, 2]);
    /// ```
    pub fn refresh<Q: ?Sized>(&mut self, value: &Q) -> bool
    where
        T: Borrow<Q>,
        Q: Hash + Eq,
    {
        self.map.get_refresh(value).is_some()
    }

    // TODO Non-trivial port without private access to map
    // /// Returns a reference to the value in the set, if any, that is equal to the given value.
    // ///
    // /// The value may be any borrowed form of the set's value type, but
    // /// `Hash` and `Eq` on the borrowed form *must* match those for
    // /// the value type.
    // pub fn get<Q: ?Sized>(&self, value: &Q) -> Option<&T>
    //     where T: Borrow<Q>,
    //           Q: Hash + Eq
    // {
    //     Recover::get(&self.map, value)
    // }

    /// Returns `true` if `self` has no elements in common with `other`.
    /// This is equivalent to checking for an empty intersection.
    ///
    /// # Examples
    ///
    /// ```
    /// use linked_hash_set::LinkedHashSet;
    ///
    /// let a: LinkedHashSet<_> = [1, 2, 3].iter().cloned().collect();
    /// let mut b = LinkedHashSet::new();
    ///
    /// assert_eq!(a.is_disjoint(&b), true);
    /// b.insert(4);
    /// assert_eq!(a.is_disjoint(&b), true);
    /// b.insert(1);
    /// assert_eq!(a.is_disjoint(&b), false);
    /// ```
    pub fn is_disjoint(&self, other: &LinkedHashSet<T, S>) -> bool {
        self.iter().all(|v| !other.contains(v))
    }

    /// Returns `true` if the set is a subset of another,
    /// i.e. `other` contains at least all the values in `self`.
    ///
    /// # Examples
    ///
    /// ```
    /// use linked_hash_set::LinkedHashSet;
    ///
    /// let sup: LinkedHashSet<_> = [1, 2, 3].iter().cloned().collect();
    /// let mut set = LinkedHashSet::new();
    ///
    /// assert_eq!(set.is_subset(&sup), true);
    /// set.insert(2);
    /// assert_eq!(set.is_subset(&sup), true);
    /// set.insert(4);
    /// assert_eq!(set.is_subset(&sup), false);
    /// ```
    pub fn is_subset(&self, other: &LinkedHashSet<T, S>) -> bool {
        self.iter().all(|v| other.contains(v))
    }

    /// Returns `true` if the set is a superset of another,
    /// i.e. `self` contains at least all the values in `other`.
    ///
    /// # Examples
    ///
    /// ```
    /// use linked_hash_set::LinkedHashSet;
    ///
    /// let sub: LinkedHashSet<_> = [1, 2].iter().cloned().collect();
    /// let mut set = LinkedHashSet::new();
    ///
    /// assert_eq!(set.is_superset(&sub), false);
    ///
    /// set.insert(0);
    /// set.insert(1);
    /// assert_eq!(set.is_superset(&sub), false);
    ///
    /// set.insert(2);
    /// assert_eq!(set.is_superset(&sub), true);
    /// ```
    #[inline]
    pub fn is_superset(&self, other: &LinkedHashSet<T, S>) -> bool {
        other.is_subset(self)
    }

    /// Adds a value to the set.
    ///
    /// If the set did not have this value present, `true` is returned.
    ///
    /// If the set did have this value present, `false` is returned.
    ///
    /// Note that performing this action will always place the value at the end of the ordering
    /// whether the set already contained the value or not. Also see
    /// [`insert_if_absent`](#method.insert_if_absent).
    ///
    /// # Examples
    ///
    /// ```
    /// use linked_hash_set::LinkedHashSet;
    ///
    /// let mut set = LinkedHashSet::new();
    ///
    /// assert_eq!(set.insert(2), true);
    /// assert_eq!(set.insert(2), false);
    /// assert_eq!(set.len(), 1);
    /// ```
    pub fn insert(&mut self, value: T) -> bool {
        self.map.insert(value, ()).is_none()
    }

    /// Adds a value to the set, if not already present. The distinction with `insert` is that
    /// order of elements is unaffected when calling this method for a value already contained.
    ///
    /// If the set did not have this value present, `true` is returned.
    ///
    /// If the set did have this value present, `false` is returned.
    ///
    /// # Examples
    ///
    /// ```
    /// use linked_hash_set::LinkedHashSet;
    ///
    /// let mut set = LinkedHashSet::new();
    ///
    /// assert_eq!(set.insert_if_absent(2), true);
    /// assert_eq!(set.insert_if_absent(2), false);
    /// assert_eq!(set.len(), 1);
    /// ```
    pub fn insert_if_absent(&mut self, value: T) -> bool {
        if !self.map.contains_key(&value) {
            self.map.insert(value, ()).is_none()
        } else {
            false
        }
    }

    // TODO Non-trivial port without private access to map
    // /// Adds a value to the set, replacing the existing value, if any, that is equal to the given
    // /// one. Returns the replaced value.
    // pub fn replace(&mut self, value: T) -> Option<T> {
    //     Recover::replace(&mut self.map, value)
    // }

    /// Removes a value from the set. Returns `true` if the value was
    /// present in the set.
    ///
    /// The value may be any borrowed form of the set's value type, but
    /// `Hash` and `Eq` on the borrowed form *must* match those for
    /// the value type.
    ///
    /// This operation will not affect the ordering of the other elements.
    ///
    /// # Examples
    ///
    /// ```
    /// use linked_hash_set::LinkedHashSet;
    ///
    /// let mut set = LinkedHashSet::new();
    ///
    /// set.insert(2);
    /// assert_eq!(set.remove(&2), true);
    /// assert_eq!(set.remove(&2), false);
    /// ```
    pub fn remove<Q: ?Sized>(&mut self, value: &Q) -> bool
    where
        T: Borrow<Q>,
        Q: Hash + Eq,
    {
        self.map.remove(value).is_some()
    }

    // TODO Non-trivial port without private access to map
    // /// Removes and returns the value in the set, if any, that is equal to the given one.
    // ///
    // /// The value may be any borrowed form of the set's value type, but
    // /// `Hash` and `Eq` on the borrowed form *must* match those for
    // /// the value type.
    // pub fn take<Q: ?Sized>(&mut self, value: &Q) -> Option<T>
    //     where T: Borrow<Q>,
    //           Q: Hash + Eq
    // {
    //     Recover::take(&mut self.map, value)
    // }

    // TODO not in linked_hash_map
    // /// Retains only the elements specified by the predicate.
    // ///
    // /// In other words, remove all elements `e` such that `f(&e)` returns `false`.
    // ///
    // /// # Examples
    // ///
    // /// ```
    // /// use linked_hash_set::LinkedHashSet;
    // ///
    // /// let xs = [1,2,3,4,5,6];
    // /// let mut set: LinkedHashSet<isize> = xs.iter().cloned().collect();
    // /// set.retain(|&k| k % 2 == 0);
    // /// assert_eq!(set.len(), 3);
    // /// ```
    // pub fn retain<F>(&mut self, mut f: F)
    //     where F: FnMut(&T) -> bool
    // {
    //     self.map.retain(|k, _| f(k));
    // }

    /// Gets the first entry.
    pub fn front(&self) -> Option<&T> {
        self.map.front().map(|(k, _)| k)
    }

    /// Removes the first entry.
    pub fn pop_front(&mut self) -> Option<T> {
        self.map.pop_front().map(|(k, _)| k)
    }

    /// Gets the last entry.
    pub fn back(&mut self) -> Option<&T> {
        self.map.back().map(|(k, _)| k)
    }

    /// Removes the last entry.
    pub fn pop_back(&mut self) -> Option<T> {
        self.map.pop_back().map(|(k, _)| k)
    }
}

impl<T: Hash + Eq + Clone, S: BuildHasher + Clone> Clone for LinkedHashSet<T, S> {
    fn clone(&self) -> Self {
        let map = self.map.clone();
        Self { map }
    }
}

impl<T, S> PartialEq for LinkedHashSet<T, S>
where
    T: Eq + Hash,
    S: BuildHasher,
{
    fn eq(&self, other: &LinkedHashSet<T, S>) -> bool {
        if self.len() != other.len() {
            return false;
        }

        self.iter().all(|key| other.contains(key))
    }
}

impl<T, S> Hash for LinkedHashSet<T, S>
where
    T: Eq + Hash,
    S: BuildHasher,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        for e in self {
            e.hash(state);
        }
    }
}

impl<T, S> Eq for LinkedHashSet<T, S>
where
    T: Eq + Hash,
    S: BuildHasher,
{
}

impl<T, S> fmt::Debug for LinkedHashSet<T, S>
where
    T: Eq + Hash + fmt::Debug,
    S: BuildHasher,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.iter()).finish()
    }
}

impl<T, S> FromIterator<T> for LinkedHashSet<T, S>
where
    T: Eq + Hash,
    S: BuildHasher + Default,
{
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> LinkedHashSet<T, S> {
        let mut set = LinkedHashSet::with_hasher(Default::default());
        set.extend(iter);
        set
    }
}

impl<T, S> Extend<T> for LinkedHashSet<T, S>
where
    T: Eq + Hash,
    S: BuildHasher,
{
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        self.map.extend(iter.into_iter().map(|k| (k, ())));
    }
}

impl<'a, T, S> Extend<&'a T> for LinkedHashSet<T, S>
where
    T: 'a + Eq + Hash + Copy,
    S: BuildHasher,
{
    fn extend<I: IntoIterator<Item = &'a T>>(&mut self, iter: I) {
        self.extend(iter.into_iter().cloned());
    }
}

impl<T, S> Default for LinkedHashSet<T, S>
where
    T: Eq + Hash,
    S: BuildHasher + Default,
{
    /// Creates an empty `LinkedHashSet<T, S>` with the `Default` value for the hasher.
    fn default() -> LinkedHashSet<T, S> {
        LinkedHashSet {
            map: LinkedHashMap::default(),
        }
    }
}

impl<'a, 'b, T, S> BitOr<&'b LinkedHashSet<T, S>> for &'a LinkedHashSet<T, S>
where
    T: Eq + Hash + Clone,
    S: BuildHasher + Default,
{
    type Output = LinkedHashSet<T, S>;

    /// Returns the union of `self` and `rhs` as a new `LinkedHashSet<T, S>`.
    ///
    /// # Examples
    ///
    /// ```
    /// use linked_hash_set::LinkedHashSet;
    ///
    /// let a: LinkedHashSet<_> = vec![1, 2, 3].into_iter().collect();
    /// let b: LinkedHashSet<_> = vec![3, 4, 5].into_iter().collect();
    ///
    /// let set = &a | &b;
    ///
    /// let mut i = 0;
    /// let expected = [1, 2, 3, 4, 5];
    /// for x in &set {
    ///     assert!(expected.contains(x));
    ///     i += 1;
    /// }
    /// assert_eq!(i, expected.len());
    /// ```
    fn bitor(self, rhs: &LinkedHashSet<T, S>) -> LinkedHashSet<T, S> {
        self.union(rhs).cloned().collect()
    }
}

impl<'a, 'b, T, S> BitAnd<&'b LinkedHashSet<T, S>> for &'a LinkedHashSet<T, S>
where
    T: Eq + Hash + Clone,
    S: BuildHasher + Default,
{
    type Output = LinkedHashSet<T, S>;

    /// Returns the intersection of `self` and `rhs` as a new `LinkedHashSet<T, S>`.
    ///
    /// # Examples
    ///
    /// ```
    /// use linked_hash_set::LinkedHashSet;
    ///
    /// let a: LinkedHashSet<_> = vec![1, 2, 3].into_iter().collect();
    /// let b: LinkedHashSet<_> = vec![2, 3, 4].into_iter().collect();
    ///
    /// let set = &a & &b;
    ///
    /// let mut i = 0;
    /// let expected = [2, 3];
    /// for x in &set {
    ///     assert!(expected.contains(x));
    ///     i += 1;
    /// }
    /// assert_eq!(i, expected.len());
    /// ```
    fn bitand(self, rhs: &LinkedHashSet<T, S>) -> LinkedHashSet<T, S> {
        self.intersection(rhs).cloned().collect()
    }
}

impl<'a, 'b, T, S> BitXor<&'b LinkedHashSet<T, S>> for &'a LinkedHashSet<T, S>
where
    T: Eq + Hash + Clone,
    S: BuildHasher + Default,
{
    type Output = LinkedHashSet<T, S>;

    /// Returns the symmetric difference of `self` and `rhs` as a new `LinkedHashSet<T, S>`.
    ///
    /// # Examples
    ///
    /// ```
    /// use linked_hash_set::LinkedHashSet;
    ///
    /// let a: LinkedHashSet<_> = vec![1, 2, 3].into_iter().collect();
    /// let b: LinkedHashSet<_> = vec![3, 4, 5].into_iter().collect();
    ///
    /// let set = &a ^ &b;
    ///
    /// let mut i = 0;
    /// let expected = [1, 2, 4, 5];
    /// for x in &set {
    ///     assert!(expected.contains(x));
    ///     i += 1;
    /// }
    /// assert_eq!(i, expected.len());
    /// ```
    fn bitxor(self, rhs: &LinkedHashSet<T, S>) -> LinkedHashSet<T, S> {
        self.symmetric_difference(rhs).cloned().collect()
    }
}

impl<'a, 'b, T, S> Sub<&'b LinkedHashSet<T, S>> for &'a LinkedHashSet<T, S>
where
    T: Eq + Hash + Clone,
    S: BuildHasher + Default,
{
    type Output = LinkedHashSet<T, S>;

    /// Returns the difference of `self` and `rhs` as a new `LinkedHashSet<T, S>`.
    ///
    /// # Examples
    ///
    /// ```
    /// use linked_hash_set::LinkedHashSet;
    ///
    /// let a: LinkedHashSet<_> = vec![1, 2, 3].into_iter().collect();
    /// let b: LinkedHashSet<_> = vec![3, 4, 5].into_iter().collect();
    ///
    /// let set = &a - &b;
    ///
    /// let mut i = 0;
    /// let expected = [1, 2];
    /// for x in &set {
    ///     assert!(expected.contains(x));
    ///     i += 1;
    /// }
    /// assert_eq!(i, expected.len());
    /// ```
    fn sub(self, rhs: &LinkedHashSet<T, S>) -> LinkedHashSet<T, S> {
        self.difference(rhs).cloned().collect()
    }
}

/// An iterator over the items of a `LinkedHashSet`.
///
/// This `struct` is created by the [`iter`] method on [`LinkedHashSet`].
/// See its documentation for more.
/// [`LinkedHashSet`]: struct.LinkedHashSet.html
/// [`iter`]: struct.LinkedHashSet.html#method.iter
pub struct Iter<'a, K> {
    iter: Keys<'a, K, ()>,
}

/// An owning iterator over the items of a `LinkedHashSet`.
///
/// This `struct` is created by the [`into_iter`] method on [`LinkedHashSet`][`LinkedHashSet`]
/// (provided by the `IntoIterator` trait). See its documentation for more.
///
/// [`LinkedHashSet`]: struct.LinkedHashSet.html
/// [`into_iter`]: struct.LinkedHashSet.html#method.into_iter
pub struct IntoIter<K> {
    iter: map::IntoIter<K, ()>,
}

// TODO not in linked_hash_map
// /// A draining iterator over the items of a `LinkedHashSet`.
// ///
// /// This `struct` is created by the [`drain`] method on [`LinkedHashSet`].
// /// See its documentation for more.
// ///
// /// [`LinkedHashSet`]: struct.LinkedHashSet.html
// /// [`drain`]: struct.LinkedHashSet.html#method.drain
// pub struct Drain<'a, K: 'a> {
//     iter: map::Drain<'a, K, ()>,
// }

/// A lazy iterator producing elements in the intersection of `LinkedHashSet`s.
///
/// This `struct` is created by the [`intersection`] method on [`LinkedHashSet`].
/// See its documentation for more.
///
/// [`LinkedHashSet`]: struct.LinkedHashSet.html
/// [`intersection`]: struct.LinkedHashSet.html#method.intersection
pub struct Intersection<'a, T, S> {
    // iterator of the first set
    iter: Iter<'a, T>,
    // the second set
    other: &'a LinkedHashSet<T, S>,
}

/// A lazy iterator producing elements in the difference of `LinkedHashSet`s.
///
/// This `struct` is created by the [`difference`] method on [`LinkedHashSet`].
/// See its documentation for more.
///
/// [`LinkedHashSet`]: struct.LinkedHashSet.html
/// [`difference`]: struct.LinkedHashSet.html#method.difference
pub struct Difference<'a, T, S> {
    // iterator of the first set
    iter: Iter<'a, T>,
    // the second set
    other: &'a LinkedHashSet<T, S>,
}

/// A lazy iterator producing elements in the symmetric difference of `LinkedHashSet`s.
///
/// This `struct` is created by the [`symmetric_difference`] method on
/// [`LinkedHashSet`]. See its documentation for more.
///
/// [`LinkedHashSet`]: struct.LinkedHashSet.html
/// [`symmetric_difference`]: struct.LinkedHashSet.html#method.symmetric_difference
pub struct SymmetricDifference<'a, T, S> {
    iter: Chain<Difference<'a, T, S>, Difference<'a, T, S>>,
}

/// A lazy iterator producing elements in the union of `LinkedHashSet`s.
///
/// This `struct` is created by the [`union`] method on [`LinkedHashSet`].
/// See its documentation for more.
///
/// [`LinkedHashSet`]: struct.LinkedHashSet.html
/// [`union`]: struct.LinkedHashSet.html#method.union
pub struct Union<'a, T, S> {
    iter: Chain<Iter<'a, T>, Difference<'a, T, S>>,
}

impl<'a, T, S> IntoIterator for &'a LinkedHashSet<T, S>
where
    T: Eq + Hash,
    S: BuildHasher,
{
    type Item = &'a T;
    type IntoIter = Iter<'a, T>;

    fn into_iter(self) -> Iter<'a, T> {
        self.iter()
    }
}

impl<T, S> IntoIterator for LinkedHashSet<T, S>
where
    T: Eq + Hash,
    S: BuildHasher,
{
    type Item = T;
    type IntoIter = IntoIter<T>;

    /// Creates a consuming iterator, that is, one that moves each value out
    /// of the set in insertion order. The set cannot be used after calling
    /// this.
    ///
    /// # Examples
    ///
    /// ```
    /// use linked_hash_set::LinkedHashSet;
    /// let mut set = LinkedHashSet::new();
    /// set.insert("a".to_string());
    /// set.insert("b".to_string());
    ///
    /// // Not possible to collect to a Vec<String> with a regular `.iter()`.
    /// let v: Vec<String> = set.into_iter().collect();
    ///
    /// // Will print in an insertion order.
    /// for x in &v {
    ///     println!("{}", x);
    /// }
    /// ```
    fn into_iter(self) -> IntoIter<T> {
        IntoIter {
            iter: self.map.into_iter(),
        }
    }
}

impl<'a, K> Clone for Iter<'a, K> {
    fn clone(&self) -> Iter<'a, K> {
        Iter {
            iter: self.iter.clone(),
        }
    }
}
impl<'a, K> Iterator for Iter<'a, K> {
    type Item = &'a K;

    fn next(&mut self) -> Option<&'a K> {
        self.iter.next()
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}
impl<'a, K> ExactSizeIterator for Iter<'a, K> {
    fn len(&self) -> usize {
        self.iter.len()
    }
}
impl<'a, T> DoubleEndedIterator for Iter<'a, T> {
    fn next_back(&mut self) -> Option<&'a T> {
        self.iter.next_back()
    }
}

impl<'a, K: fmt::Debug> fmt::Debug for Iter<'a, K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.clone()).finish()
    }
}

impl<K> Iterator for IntoIter<K> {
    type Item = K;

    fn next(&mut self) -> Option<K> {
        self.iter.next().map(|(k, _)| k)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}
impl<K> ExactSizeIterator for IntoIter<K> {
    fn len(&self) -> usize {
        self.iter.len()
    }
}
impl<K> DoubleEndedIterator for IntoIter<K> {
    fn next_back(&mut self) -> Option<K> {
        self.iter.next_back().map(|(k, _)| k)
    }
}

// TODO Non-trivial port without private access to map
// impl<K: fmt::Debug> fmt::Debug for IntoIter<K> {
//     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//         let entries_iter = self.iter
//             .inner
//             .iter()
//             .map(|(k, _)| k);
//         f.debug_list().entries(entries_iter).finish()
//     }
// }

// TODO not in linked_hash_map
// impl<'a, K> Iterator for Drain<'a, K> {
//     type Item = K;
//
//     fn next(&mut self) -> Option<K> {
//         self.iter.next().map(|(k, _)| k)
//     }
//     fn size_hint(&self) -> (usize, Option<usize>) {
//         self.iter.size_hint()
//     }
// }
// impl<'a, K> ExactSizeIterator for Drain<'a, K> {
//     fn len(&self) -> usize {
//         self.iter.len()
//     }
// }
//
// impl<'a, K: fmt::Debug> fmt::Debug for Drain<'a, K> {
//     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//         let entries_iter = self.iter
//             .inner
//             .iter()
//             .map(|(k, _)| k);
//         f.debug_list().entries(entries_iter).finish()
//     }
// }

impl<'a, T, S> Clone for Intersection<'a, T, S> {
    fn clone(&self) -> Intersection<'a, T, S> {
        Intersection {
            iter: self.iter.clone(),
            ..*self
        }
    }
}

impl<'a, T, S> Iterator for Intersection<'a, T, S>
where
    T: Eq + Hash,
    S: BuildHasher,
{
    type Item = &'a T;

    fn next(&mut self) -> Option<&'a T> {
        loop {
            match self.iter.next() {
                None => return None,
                Some(elt) => {
                    if self.other.contains(elt) {
                        return Some(elt);
                    }
                }
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let (_, upper) = self.iter.size_hint();
        (0, upper)
    }
}

impl<'a, T, S> fmt::Debug for Intersection<'a, T, S>
where
    T: fmt::Debug + Eq + Hash,
    S: BuildHasher,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.clone()).finish()
    }
}

impl<'a, T, S> Clone for Difference<'a, T, S> {
    fn clone(&self) -> Difference<'a, T, S> {
        Difference {
            iter: self.iter.clone(),
            ..*self
        }
    }
}

impl<'a, T, S> Iterator for Difference<'a, T, S>
where
    T: Eq + Hash,
    S: BuildHasher,
{
    type Item = &'a T;

    fn next(&mut self) -> Option<&'a T> {
        loop {
            match self.iter.next() {
                None => return None,
                Some(elt) => {
                    if !self.other.contains(elt) {
                        return Some(elt);
                    }
                }
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let (_, upper) = self.iter.size_hint();
        (0, upper)
    }
}

impl<'a, T, S> fmt::Debug for Difference<'a, T, S>
where
    T: fmt::Debug + Eq + Hash,
    S: BuildHasher,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.clone()).finish()
    }
}

impl<'a, T, S> Clone for SymmetricDifference<'a, T, S> {
    fn clone(&self) -> SymmetricDifference<'a, T, S> {
        SymmetricDifference {
            iter: self.iter.clone(),
        }
    }
}

impl<'a, T, S> Iterator for SymmetricDifference<'a, T, S>
where
    T: Eq + Hash,
    S: BuildHasher,
{
    type Item = &'a T;

    fn next(&mut self) -> Option<&'a T> {
        self.iter.next()
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}

impl<'a, T, S> fmt::Debug for SymmetricDifference<'a, T, S>
where
    T: fmt::Debug + Eq + Hash,
    S: BuildHasher,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.clone()).finish()
    }
}

impl<'a, T, S> Clone for Union<'a, T, S> {
    fn clone(&self) -> Union<'a, T, S> {
        Union {
            iter: self.iter.clone(),
        }
    }
}

impl<'a, T, S> fmt::Debug for Union<'a, T, S>
where
    T: fmt::Debug + Eq + Hash,
    S: BuildHasher,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.clone()).finish()
    }
}

impl<'a, T, S> Iterator for Union<'a, T, S>
where
    T: Eq + Hash,
    S: BuildHasher,
{
    type Item = &'a T;

    fn next(&mut self) -> Option<&'a T> {
        self.iter.next()
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}

// TODO does not currently work like HashSet-HashMap with linked_hash_map
// #[allow(dead_code)]
// fn assert_covariance() {
//     fn set<'new>(v: LinkedHashSet<&'static str>) -> LinkedHashSet<&'new str> {
//         v
//     }
//     fn iter<'a, 'new>(v: Iter<'a, &'static str>) -> Iter<'a, &'new str> {
//         v
//     }
//     fn into_iter<'new>(v: IntoIter<&'static str>) -> IntoIter<&'new str> {
//         v
//     }
//     fn difference<'a, 'new>(v: Difference<'a, &'static str, RandomState>)
//                             -> Difference<'a, &'new str, RandomState> {
//         v
//     }
//     fn symmetric_difference<'a, 'new>(v: SymmetricDifference<'a, &'static str, RandomState>)
//                                       -> SymmetricDifference<'a, &'new str, RandomState> {
//         v
//     }
//     fn intersection<'a, 'new>(v: Intersection<'a, &'static str, RandomState>)
//                               -> Intersection<'a, &'new str, RandomState> {
//         v
//     }
//     fn union<'a, 'new>(v: Union<'a, &'static str, RandomState>)
//                        -> Union<'a, &'new str, RandomState> {
//         v
//     }
//     fn drain<'new>(d: Drain<'static, &'static str>) -> Drain<'new, &'new str> {
//         d
//     }
// }

// Tests in common with `HashSet`
#[cfg(test)]
mod test_set {
    use super::*;

    #[test]
    fn test_zero_capacities() {
        type HS = LinkedHashSet<i32>;

        let s = HS::new();
        assert_eq!(s.capacity(), 0);

        let s = HS::default();
        assert_eq!(s.capacity(), 0);

        let s = HS::with_hasher(RandomState::new());
        assert_eq!(s.capacity(), 0);

        let s = HS::with_capacity(0);
        assert_eq!(s.capacity(), 0);

        let s = HS::with_capacity_and_hasher(0, RandomState::new());
        assert_eq!(s.capacity(), 0);

        let mut s = HS::new();
        s.insert(1);
        s.insert(2);
        s.remove(&1);
        s.remove(&2);
        s.shrink_to_fit();
        assert_eq!(s.capacity(), 0);

        let mut s = HS::new();
        s.reserve(0);
        assert_eq!(s.capacity(), 0);
    }

    #[test]
    fn test_disjoint() {
        let mut xs = LinkedHashSet::new();
        let mut ys = LinkedHashSet::new();
        assert!(xs.is_disjoint(&ys));
        assert!(ys.is_disjoint(&xs));
        assert!(xs.insert(5));
        assert!(ys.insert(11));
        assert!(xs.is_disjoint(&ys));
        assert!(ys.is_disjoint(&xs));
        assert!(xs.insert(7));
        assert!(xs.insert(19));
        assert!(xs.insert(4));
        assert!(ys.insert(2));
        assert!(ys.insert(-11));
        assert!(xs.is_disjoint(&ys));
        assert!(ys.is_disjoint(&xs));
        assert!(ys.insert(7));
        assert!(!xs.is_disjoint(&ys));
        assert!(!ys.is_disjoint(&xs));
    }

    #[test]
    fn test_subset_and_superset() {
        let mut a = LinkedHashSet::new();
        assert!(a.insert(0));
        assert!(a.insert(5));
        assert!(a.insert(11));
        assert!(a.insert(7));

        let mut b = LinkedHashSet::new();
        assert!(b.insert(0));
        assert!(b.insert(7));
        assert!(b.insert(19));
        assert!(b.insert(250));
        assert!(b.insert(11));
        assert!(b.insert(200));

        assert!(!a.is_subset(&b));
        assert!(!a.is_superset(&b));
        assert!(!b.is_subset(&a));
        assert!(!b.is_superset(&a));

        assert!(b.insert(5));

        assert!(a.is_subset(&b));
        assert!(!a.is_superset(&b));
        assert!(!b.is_subset(&a));
        assert!(b.is_superset(&a));
    }

    #[test]
    fn test_iterate() {
        let mut a = LinkedHashSet::new();
        for i in 0..32 {
            assert!(a.insert(i));
        }
        let mut observed: u32 = 0;
        for k in &a {
            observed |= 1 << *k;
        }
        assert_eq!(observed, 0xFFFF_FFFF);
    }

    #[test]
    fn test_intersection() {
        let mut a = LinkedHashSet::new();
        let mut b = LinkedHashSet::new();

        assert!(a.insert(11));
        assert!(a.insert(1));
        assert!(a.insert(3));
        assert!(a.insert(77));
        assert!(a.insert(103));
        assert!(a.insert(5));
        assert!(a.insert(-5));

        assert!(b.insert(2));
        assert!(b.insert(11));
        assert!(b.insert(77));
        assert!(b.insert(-9));
        assert!(b.insert(-42));
        assert!(b.insert(5));
        assert!(b.insert(3));

        let mut i = 0;
        let expected = [3, 5, 11, 77];
        for x in a.intersection(&b) {
            assert!(expected.contains(x));
            i += 1
        }
        assert_eq!(i, expected.len());
    }

    #[test]
    fn test_difference() {
        let mut a = LinkedHashSet::new();
        let mut b = LinkedHashSet::new();

        assert!(a.insert(1));
        assert!(a.insert(3));
        assert!(a.insert(5));
        assert!(a.insert(9));
        assert!(a.insert(11));

        assert!(b.insert(3));
        assert!(b.insert(9));

        let mut i = 0;
        let expected = [1, 5, 11];
        for x in a.difference(&b) {
            assert!(expected.contains(x));
            i += 1
        }
        assert_eq!(i, expected.len());
    }

    #[test]
    fn test_symmetric_difference() {
        let mut a = LinkedHashSet::new();
        let mut b = LinkedHashSet::new();

        assert!(a.insert(1));
        assert!(a.insert(3));
        assert!(a.insert(5));
        assert!(a.insert(9));
        assert!(a.insert(11));

        assert!(b.insert(-2));
        assert!(b.insert(3));
        assert!(b.insert(9));
        assert!(b.insert(14));
        assert!(b.insert(22));

        let mut i = 0;
        let expected = [-2, 1, 5, 11, 14, 22];
        for x in a.symmetric_difference(&b) {
            assert!(expected.contains(x));
            i += 1
        }
        assert_eq!(i, expected.len());
    }

    #[test]
    fn test_union() {
        let mut a = LinkedHashSet::new();
        let mut b = LinkedHashSet::new();

        assert!(a.insert(1));
        assert!(a.insert(3));
        assert!(a.insert(5));
        assert!(a.insert(9));
        assert!(a.insert(11));
        assert!(a.insert(16));
        assert!(a.insert(19));
        assert!(a.insert(24));

        assert!(b.insert(-2));
        assert!(b.insert(1));
        assert!(b.insert(5));
        assert!(b.insert(9));
        assert!(b.insert(13));
        assert!(b.insert(19));

        let mut i = 0;
        let expected = [-2, 1, 3, 5, 9, 11, 13, 16, 19, 24];
        for x in a.union(&b) {
            assert!(expected.contains(x));
            i += 1
        }
        assert_eq!(i, expected.len());
    }

    #[test]
    fn test_from_iter() {
        let xs = [1, 2, 3, 4, 5, 6, 7, 8, 9];

        let set: LinkedHashSet<_> = xs.iter().cloned().collect();

        for x in &xs {
            assert!(set.contains(x));
        }
    }

    #[test]
    fn test_move_iter() {
        let hs = {
            let mut hs = LinkedHashSet::new();

            hs.insert('a');
            hs.insert('b');

            hs
        };

        let v = hs.into_iter().collect::<Vec<char>>();
        assert!(v == ['a', 'b'] || v == ['b', 'a']);
    }

    #[test]
    fn test_eq() {
        // These constants once happened to expose a bug in insert().
        // I'm keeping them around to prevent a regression.
        let mut s1 = LinkedHashSet::new();

        s1.insert(1);
        s1.insert(2);
        s1.insert(3);

        let mut s2 = LinkedHashSet::new();

        s2.insert(1);
        s2.insert(2);

        assert!(s1 != s2);

        s2.insert(3);

        assert_eq!(s1, s2);
    }

    #[test]
    fn test_show() {
        let mut set = LinkedHashSet::new();
        let empty = LinkedHashSet::<i32>::new();

        set.insert(1);
        set.insert(2);

        let set_str = format!("{:?}", set);

        assert!(set_str == "{1, 2}" || set_str == "{2, 1}");
        assert_eq!(format!("{:?}", empty), "{}");
    }

    // #[test]
    // fn test_trivial_drain() {
    //     let mut s = LinkedHashSet::<i32>::new();
    //     for _ in s.drain() {}
    //     assert!(s.is_empty());
    //     drop(s);
    //
    //     let mut s = LinkedHashSet::<i32>::new();
    //     drop(s.drain());
    //     assert!(s.is_empty());
    // }

    // #[test]
    // fn test_drain() {
    //     let mut s: LinkedHashSet<_> = (1..100).collect();
    //
    //     // try this a bunch of times to make sure we don't screw up internal state.
    //     for _ in 0..20 {
    //         assert_eq!(s.len(), 99);
    //
    //         {
    //             let mut last_i = 0;
    //             let mut d = s.drain();
    //             for (i, x) in d.by_ref().take(50).enumerate() {
    //                 last_i = i;
    //                 assert!(x != 0);
    //             }
    //             assert_eq!(last_i, 49);
    //         }
    //
    //         for _ in &s {
    //             panic!("s should be empty!");
    //         }
    //
    //         // reset to try again.
    //         s.extend(1..100);
    //     }
    // }

    // #[test]
    // fn test_replace() {
    //     use std::hash;
    //
    //     #[derive(Debug)]
    //     struct Foo(&'static str, i32);
    //
    //     impl PartialEq for Foo {
    //         fn eq(&self, other: &Self) -> bool {
    //             self.0 == other.0
    //         }
    //     }
    //
    //     impl Eq for Foo {}
    //
    //     impl hash::Hash for Foo {
    //         fn hash<H: hash::Hasher>(&self, h: &mut H) {
    //             self.0.hash(h);
    //         }
    //     }
    //
    //     let mut s = LinkedHashSet::new();
    //     assert_eq!(s.replace(Foo("a", 1)), None);
    //     assert_eq!(s.len(), 1);
    //     assert_eq!(s.replace(Foo("a", 2)), Some(Foo("a", 1)));
    //     assert_eq!(s.len(), 1);
    //
    //     let mut it = s.iter();
    //     assert_eq!(it.next(), Some(&Foo("a", 2)));
    //     assert_eq!(it.next(), None);
    // }

    #[test]
    fn test_extend_ref() {
        let mut a = LinkedHashSet::new();
        a.insert(1);

        a.extend(&[2, 3, 4]);

        assert_eq!(a.len(), 4);
        assert!(a.contains(&1));
        assert!(a.contains(&2));
        assert!(a.contains(&3));
        assert!(a.contains(&4));

        let mut b = LinkedHashSet::new();
        b.insert(5);
        b.insert(6);

        a.extend(&b);

        assert_eq!(a.len(), 6);
        assert!(a.contains(&1));
        assert!(a.contains(&2));
        assert!(a.contains(&3));
        assert!(a.contains(&4));
        assert!(a.contains(&5));
        assert!(a.contains(&6));
    }

    // #[test]
    // fn test_retain() {
    //     let xs = [1, 2, 3, 4, 5, 6];
    //     let mut set: LinkedHashSet<isize> = xs.iter().cloned().collect();
    //     set.retain(|&k| k % 2 == 0);
    //     assert_eq!(set.len(), 3);
    //     assert!(set.contains(&2));
    //     assert!(set.contains(&4));
    //     assert!(set.contains(&6));
    // }
}

// Tests for `LinkedHashSet` functionality over `HashSet`
#[cfg(test)]
mod test_linked {
    use super::*;

    macro_rules! set {
        ($($el:expr),*) => {{
            let mut set = LinkedHashSet::new();
            $(
                set.insert($el);
            )*
            set
        }}
    }

    #[test]
    fn order_is_maintained() {
        let set = set![123, 234, 56, 677];
        assert_eq!(set.into_iter().collect::<Vec<_>>(), vec![123, 234, 56, 677]);
    }

    #[test]
    fn clone_order_is_maintained() {
        let set = set![123, 234, 56, 677];
        assert_eq!(
            set.clone().into_iter().collect::<Vec<_>>(),
            vec![123, 234, 56, 677]
        );
    }

    #[test]
    fn delegate_front() {
        let set = set![123, 234, 56, 677];
        assert_eq!(set.front(), Some(&123));
    }

    #[test]
    fn delegate_pop_front() {
        let mut set = set![123, 234, 56, 677];
        assert_eq!(set.pop_front(), Some(123));
        assert_eq!(set.into_iter().collect::<Vec<_>>(), vec![234, 56, 677]);
    }

    #[test]
    fn delegate_back() {
        let mut set = set![123, 234, 56, 677];
        assert_eq!(set.back(), Some(&677));
    }

    #[test]
    fn delegate_pop_back() {
        let mut set = set![123, 234, 56, 677];
        assert_eq!(set.pop_back(), Some(677));
        assert_eq!(set.into_iter().collect::<Vec<_>>(), vec![123, 234, 56]);
    }

    #[test]
    fn double_ended_iter() {
        let set = set![123, 234, 56, 677];
        let mut iter = set.iter();

        assert_eq!(iter.next(), Some(&123));
        assert_eq!(iter.next(), Some(&234));
        assert_eq!(iter.next_back(), Some(&677));
        assert_eq!(iter.next_back(), Some(&56));

        assert_eq!(iter.next(), None);
        assert_eq!(iter.next_back(), None);
    }

    #[test]
    fn double_ended_into_iter() {
        let mut iter = set![123, 234, 56, 677].into_iter();

        assert_eq!(iter.next(), Some(123));
        assert_eq!(iter.next_back(), Some(677));
        assert_eq!(iter.next_back(), Some(56));
        assert_eq!(iter.next_back(), Some(234));

        assert_eq!(iter.next(), None);
        assert_eq!(iter.next_back(), None);
    }
}
