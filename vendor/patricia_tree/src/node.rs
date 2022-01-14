//! A node which represents a subtree of a patricia tree.
use std::alloc::{alloc, dealloc, handle_alloc_error, Layout};
use std::marker::PhantomData;
use std::mem;
use std::ptr;
use std::slice;

macro_rules! assert_some {
    ($expr:expr) => {
        if let Some(value) = $expr {
            value
        } else {
            panic!("`{}` must be `Some(..)`", stringify!($expr));
        }
    };
}

bitflags! {
    pub (crate) struct Flags: u8 {
        const VALUE_ALLOCATED = 0b0000_0001;
        const VALUE_INITIALIZED = 0b0000_0010;

        const CHILD_ALLOCATED = 0b0000_0100;
        const CHILD_INITIALIZED = 0b0000_1000;

        const SIBLING_ALLOCATED = 0b0001_0000;
        const SIBLING_INITIALIZED = 0b0010_0000;
    }
}

#[cfg(feature = "binary-format")]
pub use crate::codec::{NodeDecoder, NodeEncoder};

const FLAGS_OFFSET: isize = 0;
const LABEL_LEN_OFFSET: isize = 1;
const LABEL_OFFSET: isize = 2;

const MAX_LABEL_LEN: usize = 255;

/// A node which represents a subtree of a patricia tree.
///
/// Note that this is a low level building block.
/// Usually it is recommended to use more high level data structures (e.g., `PatriciaTree`).
#[derive(Debug)]
pub struct Node<V> {
    // layout:
    //   - flags: u8
    //   - label_len: u8
    //   - label: [u8; label_len]
    //   - value: Option<V>
    //   - child: Option<Node<V>>
    //   - sibling: Option<Node<V>>
    ptr: *mut u8,

    _value: PhantomData<V>,
}
unsafe impl<V: Send> Send for Node<V> {}
unsafe impl<V: Sync> Sync for Node<V> {}
impl<V> Node<V> {
    /// Makes a new node which represents an empty tree.
    ///
    /// # Examples
    ///
    /// ```
    /// use patricia_tree::node::Node;
    ///
    /// let node = Node::<()>::root();
    /// assert!(node.label().is_empty());
    /// assert!(node.value().is_none());
    /// assert!(node.child().is_none());
    /// assert!(node.sibling().is_none());
    /// ```
    pub fn root() -> Self {
        Node::new(b"", None, None, None)
    }

    /// Makes a new node.
    ///
    /// # Examples
    ///
    /// ```
    /// use patricia_tree::node::Node;
    ///
    /// let node0 = Node::new("foo".as_ref(), Some(3), None, None);
    /// assert_eq!(node0.label(), b"foo");
    /// assert_eq!(node0.value(), Some(&3));
    /// assert_eq!(node0.child().map(|n| n.label()), None);
    /// assert_eq!(node0.sibling().map(|n| n.label()), None);
    ///
    /// let node1 = Node::new("bar".as_ref(), None, None, Some(node0));
    /// assert_eq!(node1.label(), b"bar");
    /// assert_eq!(node1.value(), None);
    /// assert_eq!(node1.child().map(|n| n.label()), None);
    /// assert_eq!(node1.sibling().map(|n| n.label()), Some(&b"foo"[..]));
    ///
    /// // If the length of a label name is longer than 255, it will be splitted to two nodes.
    /// let node2 = Node::new([b'a'; 256].as_ref(), Some(4), Some(node1), None);
    /// assert_eq!(node2.label(), [b'a'; 255].as_ref());
    /// assert_eq!(node2.value(), None);
    /// assert_eq!(node2.child().map(|n| n.label()), Some(&b"a"[..]));
    /// assert_eq!(node2.sibling().map(|n| n.label()), None);
    ///
    /// assert_eq!(node2.child().unwrap().value(), Some(&4));
    /// assert_eq!(node2.child().unwrap().child().unwrap().label(), b"bar");
    /// ```
    pub fn new(
        mut label: &[u8],
        mut value: Option<V>,
        mut child: Option<Self>,
        sibling: Option<Self>,
    ) -> Self {
        if label.len() > MAX_LABEL_LEN {
            child = Some(Node::new(&label[MAX_LABEL_LEN..], value, child, None));
            label = &label[..MAX_LABEL_LEN];
            value = None;
        }

        let mut flags = Flags::empty();
        let mut layout = Self::initial_layout(label.len());
        let value = value.map(|value| {
            flags.insert(Flags::VALUE_ALLOCATED | Flags::VALUE_INITIALIZED);
            let (new_layout, offset) = layout.extend(Layout::new::<V>()).expect("unreachable");
            layout = new_layout;
            (value, offset)
        });
        let child = child.map(|child| {
            flags.insert(Flags::CHILD_ALLOCATED | Flags::CHILD_INITIALIZED);
            let (new_layout, offset) = layout.extend(Layout::new::<Self>()).expect("unreachable");
            layout = new_layout;
            (child, offset)
        });
        let sibling = sibling.map(|sibling| {
            flags.insert(Flags::SIBLING_ALLOCATED | Flags::SIBLING_INITIALIZED);
            let (new_layout, offset) = layout.extend(Layout::new::<Self>()).expect("unreachable");
            layout = new_layout;
            (sibling, offset)
        });

        unsafe {
            let ptr = alloc(layout.pad_to_align());
            if ptr.is_null() {
                handle_alloc_error(layout)
            }

            ptr::write(ptr.offset(FLAGS_OFFSET), flags.bits() as u8);
            ptr::write(ptr.offset(LABEL_LEN_OFFSET), label.len() as u8);
            ptr::copy_nonoverlapping(label.as_ptr(), ptr.offset(LABEL_OFFSET), label.len());

            if let Some((value, offset)) = value {
                ptr::write(ptr.add(offset) as _, value);
            }
            if let Some((child, offset)) = child {
                ptr::write(ptr.add(offset) as _, child);
            }
            if let Some((sibling, offset)) = sibling {
                ptr::write(ptr.add(offset) as _, sibling);
            }
            Node {
                ptr,
                _value: PhantomData,
            }
        }
    }

    #[cfg(feature = "binary-format")]
    pub(crate) fn new_for_decoding(flags: Flags, label_len: u8) -> Self {
        let mut init_flags = Flags::empty();
        let mut layout = Self::initial_layout(label_len as usize);
        if flags.contains(Flags::VALUE_INITIALIZED) {
            init_flags.insert(Flags::VALUE_ALLOCATED);
            layout = layout.extend(Layout::new::<V>()).expect("unreachable").0;
        }
        if flags.contains(Flags::CHILD_INITIALIZED) {
            init_flags.insert(Flags::CHILD_ALLOCATED);
            layout = layout.extend(Layout::new::<Self>()).expect("unreachable").0;
        }
        if flags.contains(Flags::SIBLING_INITIALIZED) {
            init_flags.insert(Flags::SIBLING_ALLOCATED);
            layout = layout.extend(Layout::new::<Self>()).expect("unreachable").0;
        }

        let ptr = unsafe { alloc(layout.pad_to_align()) };
        assert_ne!(ptr, ptr::null_mut());

        unsafe {
            ptr::write(ptr.offset(FLAGS_OFFSET), init_flags.bits());
            ptr::write(ptr.offset(LABEL_LEN_OFFSET), label_len);
        }
        Node {
            ptr,
            _value: PhantomData,
        }
    }

    /// Returns the label of this node.
    pub fn label(&self) -> &[u8] {
        unsafe {
            let label_len = *self.ptr.offset(LABEL_LEN_OFFSET) as usize;
            slice::from_raw_parts(self.ptr.offset(LABEL_OFFSET), label_len)
        }
    }

    #[cfg(feature = "binary-format")]
    pub(crate) fn label_mut(&mut self) -> &mut [u8] {
        unsafe {
            let label_len = *self.ptr.offset(LABEL_LEN_OFFSET) as usize;
            slice::from_raw_parts_mut(self.ptr.offset(LABEL_OFFSET), label_len)
        }
    }

    /// Returns the reference to the value of this node.
    pub fn value(&self) -> Option<&V> {
        if let Some(offset) = self.value_offset() {
            if self.flags().contains(Flags::VALUE_INITIALIZED) {
                unsafe {
                    let value = self.ptr.offset(offset) as *const V;
                    return Some(&*value);
                }
            }
        }
        None
    }

    /// Returns the mutable reference to the value of this node.
    pub fn value_mut(&mut self) -> Option<&mut V> {
        if let Some(offset) = self.value_offset() {
            if self.flags().contains(Flags::VALUE_INITIALIZED) {
                unsafe {
                    let value = self.ptr.offset(offset) as *mut V;
                    return Some(&mut *value);
                }
            }
        }
        None
    }

    /// Returns the reference to the child of this node.
    pub fn child(&self) -> Option<&Self> {
        if let Some(offset) = self.child_offset() {
            if self.flags().contains(Flags::CHILD_INITIALIZED) {
                unsafe {
                    let child = self.ptr.offset(offset) as *const Self;
                    return Some(&*child);
                }
            }
        }
        None
    }

    /// Returns the mutable reference to the child of this node.
    pub fn child_mut(&mut self) -> Option<&mut Self> {
        if let Some(offset) = self.child_offset() {
            if self.flags().contains(Flags::CHILD_INITIALIZED) {
                unsafe {
                    let child = self.ptr.offset(offset) as *mut Self;
                    return Some(&mut *child);
                }
            }
        }
        None
    }

    /// Returns the reference to the sibling of this node.
    pub fn sibling(&self) -> Option<&Self> {
        if let Some(offset) = self.sibling_offset() {
            if self.flags().contains(Flags::SIBLING_INITIALIZED) {
                unsafe {
                    let sibling = self.ptr.offset(offset) as *const Self;
                    return Some(&*sibling);
                }
            }
        }
        None
    }

    /// Returns the mutable reference to the sibling of this node.
    pub fn sibling_mut(&mut self) -> Option<&mut Self> {
        if let Some(offset) = self.sibling_offset() {
            if self.flags().contains(Flags::SIBLING_INITIALIZED) {
                unsafe {
                    let sibling = self.ptr.offset(offset) as *mut Self;
                    return Some(&mut *sibling);
                }
            }
        }
        None
    }

    /// Returns mutable references to the node itself with its sibling and child
    pub fn as_mut(&mut self) -> NodeMut<'_, V> {
        let mut sibling_result = None;
        let mut child_result = None;
        let mut value_result = None;

        if let Some(offset) = self.child_offset() {
            if self.flags().contains(Flags::CHILD_INITIALIZED) {
                unsafe {
                    let child = self.ptr.offset(offset) as *mut Self;
                    child_result.replace(&mut *child);
                }
            }
        }

        if let Some(offset) = self.sibling_offset() {
            if self.flags().contains(Flags::SIBLING_INITIALIZED) {
                unsafe {
                    let sibling = self.ptr.offset(offset) as *mut Self;
                    sibling_result.replace(&mut *sibling);
                }
            }
        }

        if let Some(offset) = self.value_offset() {
            if self.flags().contains(Flags::VALUE_INITIALIZED) {
                unsafe {
                    let value = self.ptr.offset(offset) as *mut V;
                    value_result.replace(&mut *value);
                }
            }
        }

        NodeMut {
            label: self.label(),
            sibling: sibling_result,
            child: child_result,
            value: value_result,
        }
    }

    /// Takes the value out of this node.
    pub fn take_value(&mut self) -> Option<V> {
        if let Some(offset) = self.value_offset() {
            if self.flags().contains(Flags::VALUE_INITIALIZED) {
                self.set_flags(Flags::VALUE_INITIALIZED, false);
                unsafe {
                    let value = self.ptr.offset(offset) as *const V;
                    return Some(ptr::read(value));
                }
            }
        }
        None
    }

    /// Takes the child out of this node.
    pub fn take_child(&mut self) -> Option<Self> {
        if let Some(offset) = self.child_offset() {
            if self.flags().contains(Flags::CHILD_INITIALIZED) {
                self.set_flags(Flags::CHILD_INITIALIZED, false);
                unsafe {
                    let child = self.ptr.offset(offset) as *mut Self;
                    return Some(ptr::read(child));
                }
            }
        }
        None
    }

    /// Takes the sibling out of this node.
    pub fn take_sibling(&mut self) -> Option<Self> {
        if let Some(offset) = self.sibling_offset() {
            if self.flags().contains(Flags::SIBLING_INITIALIZED) {
                self.set_flags(Flags::SIBLING_INITIALIZED, false);
                unsafe {
                    let sibling = self.ptr.offset(offset) as *mut Self;
                    return Some(ptr::read(sibling));
                }
            }
        }
        None
    }

    /// Sets the value of this node.
    pub fn set_value(&mut self, value: V) {
        self.take_value();
        if let Some(offset) = self.value_offset() {
            self.set_flags(Flags::VALUE_INITIALIZED, true);
            unsafe { ptr::write(self.ptr.offset(offset) as _, value) };
        } else {
            let child = self.take_child();
            let sibling = self.take_sibling();
            let node = Node::new(self.label(), Some(value), child, sibling);
            *self = node;
        }
    }

    /// Sets the child of this node.
    pub fn set_child(&mut self, child: Self) {
        self.take_child();
        if let Some(offset) = self.child_offset() {
            self.set_flags(Flags::CHILD_INITIALIZED, true);
            unsafe { ptr::write(self.ptr.offset(offset) as _, child) };
        } else {
            let value = self.take_value();
            let sibling = self.take_sibling();
            let node = Node::new(self.label(), value, Some(child), sibling);
            *self = node;
        }
    }

    /// Sets the sibling of this node.
    pub fn set_sibling(&mut self, sibling: Self) {
        self.take_sibling();
        if let Some(offset) = self.sibling_offset() {
            self.set_flags(Flags::SIBLING_INITIALIZED, true);
            unsafe { ptr::write(self.ptr.offset(offset) as _, sibling) };
        } else {
            let value = self.take_value();
            let child = self.take_child();
            let node = Node::new(self.label(), value, child, Some(sibling));
            *self = node;
        }
    }

    /// Gets an iterator which traverses the nodes in this tree, in depth first order.
    ///
    /// # Examples
    ///
    /// ```
    /// use patricia_tree::PatriciaSet;
    /// use patricia_tree::node::Node;
    ///
    /// let mut set = PatriciaSet::new();
    /// set.insert("foo");
    /// set.insert("bar");
    /// set.insert("baz");
    ///
    /// let node = Node::from(set);
    /// let nodes = node.iter().map(|(level, node)| (level, node.label())).collect::<Vec<_>>();
    /// assert_eq!(nodes,
    ///            [
    ///                (0, "".as_ref()),
    ///                (1, "ba".as_ref()),
    ///                (2, "r".as_ref()),
    ///                (2, "z".as_ref()),
    ///                (1, "foo".as_ref())
    ///            ]);
    /// ```
    pub fn iter(&self) -> Iter<V> {
        Iter {
            stack: vec![(0, self)],
        }
    }

    /// Gets a mutable iterator which traverses the nodes in this tree, in depth first order.
    ///
    /// # Examples
    ///
    /// ```
    /// use patricia_tree::PatriciaSet;
    /// use patricia_tree::node::Node;
    ///
    /// let mut set = PatriciaSet::new();
    /// set.insert("foo");
    /// set.insert("bar");
    /// set.insert("baz");
    ///
    /// let mut node = Node::from(set);
    /// let nodes = node.iter_mut().map(|(level, node)| (level, node.label())).collect::<Vec<_>>();
    /// assert_eq!(nodes,
    ///            [
    ///                (0, "".as_ref()),
    ///                (1, "ba".as_ref()),
    ///                (2, "r".as_ref()),
    ///                (2, "z".as_ref()),
    ///                (1, "foo".as_ref())
    ///            ]);
    /// ```
    pub fn iter_mut(&mut self) -> IterMut<V> {
        IterMut {
            stack: vec![(0, self)],
        }
    }

    pub(crate) fn iter_descendant(&self) -> Iter<V> {
        Iter {
            stack: vec![(0, self)],
        }
    }

    pub(crate) fn iter_descendant_mut(&mut self) -> IterMut<V> {
        IterMut {
            stack: vec![(0, self)],
        }
    }

    pub(crate) fn common_prefixes<K>(&self, key: K) -> CommonPrefixesIter<K, V>
    where
        K: AsRef<[u8]>,
    {
        CommonPrefixesIter {
            key,
            stack: vec![(0, self)],
        }
    }

    pub(crate) fn get(&self, key: &[u8]) -> Option<&V> {
        let common_prefix_len = self.skip_common_prefix(key);
        let next = &key[common_prefix_len..];
        if common_prefix_len == self.label().len() {
            if next.is_empty() {
                self.value()
            } else {
                self.child().and_then(|child| child.get(next))
            }
        } else if common_prefix_len == 0 && self.label().get(0) <= key.get(0) {
            self.sibling().and_then(|sibling| sibling.get(next))
        } else {
            None
        }
    }
    pub(crate) fn get_mut(&mut self, key: &[u8]) -> Option<&mut V> {
        let common_prefix_len = self.skip_common_prefix(key);
        let next = &key[common_prefix_len..];
        if common_prefix_len == self.label().len() {
            if next.is_empty() {
                self.value_mut()
            } else {
                self.child_mut().and_then(|child| child.get_mut(next))
            }
        } else if common_prefix_len == 0 && self.label().get(0) <= key.get(0) {
            self.sibling_mut().and_then(|sibling| sibling.get_mut(next))
        } else {
            None
        }
    }
    pub(crate) fn get_longest_common_prefix(
        &self,
        key: &[u8],
        offset: usize,
    ) -> Option<(usize, &V)> {
        let common_prefix_len = self.skip_common_prefix(key);
        let next = &key[common_prefix_len..];
        if common_prefix_len == self.label().len() {
            let offset = offset + common_prefix_len;
            if next.is_empty() {
                self.value().map(|v| (offset, v))
            } else {
                self.child()
                    .and_then(|child| child.get_longest_common_prefix(next, offset))
                    .or_else(|| self.value().map(|v| (offset, v)))
            }
        } else if common_prefix_len == 0 && self.label().get(0) <= key.get(0) {
            self.sibling()
                .and_then(|sibling| sibling.get_longest_common_prefix(next, offset))
        } else {
            None
        }
    }

    pub(crate) fn get_prefix_node(&self, key: &[u8], offset: usize) -> Option<(usize, &Self)> {
        let common_prefix_len = self.skip_common_prefix(key);
        let next = &key[common_prefix_len..];
        if next.is_empty() {
            Some((common_prefix_len, self))
        } else if common_prefix_len == self.label().len() {
            let offset = offset + common_prefix_len;
            self.child()
                .and_then(|child| child.get_prefix_node(next, offset))
        } else if common_prefix_len == 0 && self.label().get(0) <= key.get(0) {
            self.sibling()
                .and_then(|sibling| sibling.get_prefix_node(next, offset))
        } else {
            None
        }
    }

    pub(crate) fn get_prefix_node_mut(
        &mut self,
        key: &[u8],
        offset: usize,
    ) -> Option<(usize, &mut Self)> {
        let common_prefix_len = self.skip_common_prefix(key);
        let next = &key[common_prefix_len..];
        if next.is_empty() {
            Some((common_prefix_len, self))
        } else if common_prefix_len == self.label().len() {
            let offset = offset + common_prefix_len;
            self.child_mut()
                .and_then(|child| child.get_prefix_node_mut(next, offset))
        } else if common_prefix_len == 0 && self.label().get(0) <= key.get(0) {
            self.sibling_mut()
                .and_then(|sibling| sibling.get_prefix_node_mut(next, offset))
        } else {
            None
        }
    }

    pub(crate) fn split_by_prefix(&mut self, prefix: &[u8]) -> Option<Self> {
        let common_prefix_len = self.skip_common_prefix(prefix);
        if common_prefix_len == prefix.len() {
            let value = self.take_value();
            let child = self.take_child();
            let node = Node::new(&self.label()[common_prefix_len..], value, child, None);
            if let Some(sibling) = self.take_sibling() {
                *self = sibling;
            }
            Some(node)
        } else if common_prefix_len == self.label().len() {
            let next = &prefix[common_prefix_len..];
            self.child_mut()
                .and_then(|child| child.split_by_prefix(next))
                .map(|old| {
                    self.try_reclaim_child();
                    self.try_merge_with_child();
                    old
                })
        } else if common_prefix_len == 0 && self.label().get(0) <= prefix.get(0) {
            let next = &prefix[common_prefix_len..];
            self.sibling_mut()
                .and_then(|sibling| sibling.split_by_prefix(next))
                .map(|old| {
                    self.try_reclaim_sibling();
                    old
                })
        } else {
            None
        }
    }
    pub(crate) fn remove(&mut self, key: &[u8]) -> Option<V> {
        let common_prefix_len = self.skip_common_prefix(key);
        let next = &key[common_prefix_len..];
        if common_prefix_len == self.label().len() {
            if next.is_empty() {
                self.take_value().map(|old| {
                    self.try_merge_with_child();
                    old
                })
            } else {
                self.child_mut()
                    .and_then(|child| child.remove(next))
                    .map(|old| {
                        self.try_reclaim_child();
                        self.try_merge_with_child();
                        old
                    })
            }
        } else if common_prefix_len == 0 && self.label().get(0) <= key.get(0) {
            self.sibling_mut()
                .and_then(|sibling| sibling.remove(next))
                .map(|old| {
                    self.try_reclaim_sibling();
                    old
                })
        } else {
            None
        }
    }
    pub(crate) fn insert(&mut self, key: &[u8], value: V) -> Option<V> {
        if self.label().get(0) > key.get(0) {
            let this = Node {
                ptr: self.ptr,
                _value: PhantomData,
            };
            let node = Node::new(key, Some(value), None, Some(this));
            self.ptr = node.ptr;
            mem::forget(node);
            return None;
        }

        let common_prefix_len = self.skip_common_prefix(key);
        let next = &key[common_prefix_len..];
        let is_label_matched = common_prefix_len == self.label().len();
        if next.is_empty() {
            if is_label_matched {
                let old = self.take_value();
                self.set_value(value);
                old
            } else {
                self.split_at(common_prefix_len);
                self.set_value(value);
                None
            }
        } else if is_label_matched {
            if let Some(child) = self.child_mut() {
                return child.insert(next, value);
            }
            let child = Node::new(next, Some(value), None, None);
            self.set_child(child);
            None
        } else if common_prefix_len == 0 {
            if let Some(sibling) = self.sibling_mut() {
                return sibling.insert(next, value);
            }
            let sibling = Node::new(next, Some(value), None, None);
            self.set_sibling(sibling);
            None
        } else {
            self.split_at(common_prefix_len);
            assert_some!(self.child_mut()).insert(next, value);
            None
        }
    }

    fn skip_common_prefix(&self, key: &[u8]) -> usize {
        self.label()
            .iter()
            .zip(key.iter())
            .take_while(|x| x.0 == x.1)
            .count()
    }
    pub(crate) fn flags(&self) -> Flags {
        Flags::from_bits_truncate(unsafe { *self.ptr })
    }
    fn set_flags(&mut self, other: Flags, value: bool) {
        let mut flags = self.flags();
        flags.set(other, value);
        unsafe { ptr::write(self.ptr, flags.bits() as u8) };
    }
    fn label_len(&self) -> usize {
        unsafe { *self.ptr.offset(LABEL_LEN_OFFSET) as usize }
    }
    fn value_offset(&self) -> Option<isize> {
        let flags = self.flags();
        if flags.contains(Flags::VALUE_ALLOCATED) {
            let layout = Self::initial_layout(self.label_len());
            let offset = layout.extend(Layout::new::<V>()).expect("unreachable").1;
            Some(offset as isize)
        } else {
            None
        }
    }
    fn child_offset(&self) -> Option<isize> {
        let flags = self.flags();
        if flags.contains(Flags::CHILD_ALLOCATED) {
            let mut layout = Self::initial_layout(self.label_len());
            if flags.contains(Flags::VALUE_ALLOCATED) {
                layout = layout.extend(Layout::new::<V>()).expect("unreachable").0;
            }
            let offset = layout.extend(Layout::new::<Self>()).expect("unreachable").1;
            Some(offset as isize)
        } else {
            None
        }
    }
    fn sibling_offset(&self) -> Option<isize> {
        let flags = self.flags();
        if flags.contains(Flags::SIBLING_ALLOCATED) {
            let mut layout = Self::initial_layout(self.label_len());
            if flags.contains(Flags::VALUE_ALLOCATED) {
                layout = layout.extend(Layout::new::<V>()).expect("unreachable").0;
            }
            if flags.contains(Flags::CHILD_ALLOCATED) {
                layout = layout.extend(Layout::new::<Self>()).expect("unreachable").0;
            }
            let offset = layout.extend(Layout::new::<Self>()).expect("unreachable").1;
            Some(offset as isize)
        } else {
            None
        }
    }
    fn split_at(&mut self, position: usize) {
        debug_assert!(position < self.label_len());
        let value = self.take_value();
        let child = self.take_child();
        let sibling = self.take_sibling();

        let child = Node::new(&self.label()[position..], value, child, None);
        let parent = Node::new(&self.label()[..position], None, Some(child), sibling);
        *self = parent;
    }
    fn try_reclaim_sibling(&mut self) {
        let flags = assert_some!(self.sibling()).flags();
        if flags.intersects(Flags::VALUE_INITIALIZED | Flags::CHILD_INITIALIZED) {
            return;
        }
        if let Some(sibling) = self.take_sibling().and_then(|mut n| n.take_sibling()) {
            self.set_sibling(sibling);
        }
    }
    fn try_reclaim_child(&mut self) {
        let flags = assert_some!(self.child()).flags();
        if flags.intersects(Flags::VALUE_INITIALIZED | Flags::CHILD_INITIALIZED) {
            return;
        }
        if let Some(child) = self.take_child().and_then(|mut n| n.take_sibling()) {
            self.set_child(child);
        }
    }
    pub(crate) fn try_merge_with_child(&mut self) {
        if self.flags().contains(Flags::VALUE_INITIALIZED)
            || !self.flags().contains(Flags::CHILD_INITIALIZED)
        {
            return;
        }

        let flags = assert_some!(self.child()).flags();
        if !flags.contains(Flags::SIBLING_INITIALIZED)
            && (self.label_len() + assert_some!(self.child()).label_len()) <= MAX_LABEL_LEN
        {
            let mut child = assert_some!(self.take_child());
            let sibling = self.take_sibling();
            let value = child.take_value();
            let grandchild = child.take_child();

            let mut label = Vec::with_capacity(self.label_len() + child.label_len());
            label.extend(self.label());
            label.extend(child.label());
            let node = Self::new(&label, value, grandchild, sibling);
            *self = node;
        }
    }

    #[inline]
    fn initial_layout(label_len: usize) -> Layout {
        Layout::from_size_align(LABEL_OFFSET as usize + label_len, 1).expect("unreachable")
    }
}

impl<V> Drop for Node<V> {
    fn drop(&mut self) {
        let _ = self.take_value();
        let _ = self.take_child();
        let _ = self.take_sibling();

        let mut layout = Self::initial_layout(self.label_len());
        if self.flags().contains(Flags::VALUE_ALLOCATED) {
            layout = layout.extend(Layout::new::<V>()).expect("unreachable").0;
        }
        if self.flags().contains(Flags::CHILD_ALLOCATED) {
            layout = layout.extend(Layout::new::<Self>()).expect("unreachable").0;
        }
        if self.flags().contains(Flags::SIBLING_ALLOCATED) {
            layout = layout.extend(Layout::new::<Self>()).expect("unreachable").0;
        }

        unsafe { dealloc(self.ptr, layout.pad_to_align()) }
    }
}
impl<V: Clone> Clone for Node<V> {
    fn clone(&self) -> Self {
        let label = self.label();
        let value = self.value().cloned();
        let child = self.child().cloned();
        let sibling = self.sibling().cloned();
        Node::new(label, value, child, sibling)
    }
}
impl<V> IntoIterator for Node<V> {
    type Item = (usize, Node<V>);
    type IntoIter = IntoIter<V>;
    fn into_iter(self) -> Self::IntoIter {
        IntoIter {
            stack: vec![(0, self)],
        }
    }
}

/// An iterator which traverses the nodes in a tree, in depth first order.
///
/// The first element of an item is the level of the traversing node.
#[derive(Debug)]
pub struct Iter<'a, V: 'a> {
    stack: Vec<(usize, &'a Node<V>)>,
}
impl<'a, V: 'a> Iterator for Iter<'a, V> {
    type Item = (usize, &'a Node<V>);
    fn next(&mut self) -> Option<Self::Item> {
        if let Some((level, node)) = self.stack.pop() {
            if level != 0 {
                if let Some(sibling) = node.sibling() {
                    self.stack.push((level, sibling));
                }
            }
            if let Some(child) = node.child() {
                self.stack.push((level + 1, child));
            }
            Some((level, node))
        } else {
            None
        }
    }
}

/// A mutable iterator which traverses the nodes in a tree, in depth first order.
///
/// The first element of an item is the level of the traversing node.
#[derive(Debug)]
pub struct IterMut<'a, V: 'a> {
    stack: Vec<(usize, &'a mut Node<V>)>,
}

/// A reference to an immediate node (without child or sibling) with its
/// label and a mutable reference to its value, if present.
pub struct NodeMut<'a, V: 'a> {
    label: &'a [u8],
    value: Option<&'a mut V>,
    sibling: Option<&'a mut Node<V>>,
    child: Option<&'a mut Node<V>>,
}
impl<'a, V: 'a> NodeMut<'a, V> {
    /// Makes a new reference to a node's label and mutable value.
    pub fn new(
        label: &'a [u8],
        value: Option<&'a mut V>,
        sibling: Option<&'a mut Node<V>>,
        child: Option<&'a mut Node<V>>,
    ) -> Self {
        NodeMut {
            label,
            value,
            sibling,
            child,
        }
    }

    /// Returns the label of the node.
    pub fn label(&self) -> &'a [u8] {
        self.label
    }

    /// Returns the value of the node, if present.
    pub fn value(&self) -> &Option<&'a mut V> {
        &self.value
    }

    /// Returns the sibling of the node, if present.
    pub fn sibling(&self) -> &Option<&'a mut Node<V>> {
        &self.sibling
    }

    /// Returns the child of the node, if present.
    pub fn child(&self) -> &Option<&'a mut Node<V>> {
        &self.child
    }

    /// Converts into a mutable reference to the value.
    pub fn into_value_mut(self) -> Option<&'a mut V> {
        self.value
    }
}

impl<'a, V: 'a> Iterator for IterMut<'a, V> {
    type Item = (usize, NodeMut<'a, V>);
    fn next(&mut self) -> Option<Self::Item> {
        if let Some((level, node)) = self.stack.pop() {
            let mut node = node.as_mut();
            if level != 0 {
                if let Some(sibling) = node.sibling.take() {
                    self.stack.push((level, sibling));
                }
            }
            if let Some(child) = node.child.take() {
                self.stack.push((level + 1, child));
            }
            Some((level, node))
        } else {
            None
        }
    }
}

/// An iterator over entries in that collects all values up to
/// until the key stops matching.
#[derive(Debug)]
pub(crate) struct CommonPrefixesIter<'a, K, V> {
    key: K,
    stack: Vec<(usize, &'a Node<V>)>,
}

impl<'a, K, V> Iterator for CommonPrefixesIter<'a, K, V>
where
    K: AsRef<[u8]>,
{
    type Item = (usize, &'a Node<V>);
    fn next(&mut self) -> Option<Self::Item> {
        while let Some((offset, node)) = self.stack.pop() {
            let common_prefix_len = node.skip_common_prefix(&self.key.as_ref()[offset..]);
            if common_prefix_len == 0 && node.label().get(0) <= self.key.as_ref().get(offset) {
                if let Some(sibling) = node.sibling() {
                    self.stack.push((offset, sibling));
                }
            }

            if common_prefix_len == node.label().len() {
                let prefix_len = offset + common_prefix_len;
                if let Some(child) = node.child() {
                    self.stack.push((prefix_len, child));
                }
                return Some((prefix_len, node));
            }
        }
        None
    }
}

/// An owning iterator which traverses the nodes in a tree, in depth first order.
///
/// The first element of an item is the level of the traversing node.
#[derive(Debug)]
pub struct IntoIter<V> {
    stack: Vec<(usize, Node<V>)>,
}
impl<V> Iterator for IntoIter<V> {
    type Item = (usize, Node<V>);
    fn next(&mut self) -> Option<Self::Item> {
        if let Some((level, mut node)) = self.stack.pop() {
            if let Some(sibling) = node.take_sibling() {
                self.stack.push((level, sibling));
            }
            if let Some(child) = node.take_child() {
                self.stack.push((level + 1, child));
            }
            Some((level, node))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PatriciaSet;
    use std::str;

    #[test]
    fn long_label_works() {
        let node = Node::new(&[b'a'; 256][..], Some(10), None, None);
        assert_eq!(node.label(), &[b'a'; 255][..]);
        assert_eq!(node.value(), None);
        assert_eq!(node.child().is_some(), true);

        let child = node.child().unwrap();
        assert_eq!(child.label(), b"a");
        assert_eq!(child.value(), Some(&10));
    }

    #[test]
    fn reclaim_works() {
        let mut set = ["123", "123456", "123abc", "123def"]
            .iter()
            .collect::<PatriciaSet>();
        assert_eq!(
            set_to_labels(&set),
            [(0, ""), (1, "123"), (2, "456"), (2, "abc"), (2, "def")]
        );

        set.remove("123def");
        assert_eq!(set_to_labels(&set), [(0, "123"), (1, "456"), (1, "abc")]);

        set.remove("123456");
        assert_eq!(set_to_labels(&set), [(0, "123"), (1, "abc")]);

        set.remove("123");
        assert_eq!(set_to_labels(&set), [(0, "123abc")]);
    }

    #[test]
    fn get_longest_common_prefix_works() {
        let set = ["123", "123456", "1234_67", "123abc", "123def"]
            .iter()
            .collect::<PatriciaSet>();

        let lcp = |key| set.get_longest_common_prefix(key);
        assert_eq!(lcp(""), None);
        assert_eq!(lcp("12"), None);
        assert_eq!(lcp("123"), Some("123".as_bytes()));
        assert_eq!(lcp("1234"), Some("123".as_bytes()));
        assert_eq!(lcp("123456"), Some("123456".as_bytes()));
        assert_eq!(lcp("1234_6"), Some("123".as_bytes()));
        assert_eq!(lcp("123456789"), Some("123456".as_bytes()));
    }

    fn set_to_labels(set: &PatriciaSet) -> Vec<(usize, &str)> {
        set.as_ref()
            .iter()
            .map(|(level, n)| (level, str::from_utf8(n.label()).unwrap()))
            .collect()
    }
}
