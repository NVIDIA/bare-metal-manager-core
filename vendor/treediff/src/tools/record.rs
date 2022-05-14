use crate::traitdef::Delegate;

/// Identifies a type of change at a given Key path, for use with the `Recorder`.
///
/// The Key path is followed to know what happened with the Value `V` contained in the variants.
#[derive(Debug, PartialEq)]
pub enum ChangeType<'a, K, V: 'a> {
    /// The Value was removed
    Removed(Vec<K>, &'a V),
    /// The Value was added
    Added(Vec<K>, &'a V),
    /// No change was performed to the Value
    Unchanged(Vec<K>, &'a V),
    /// The first Value was modified and became the second Value
    Modified(Vec<K>, &'a V, &'a V),
}

/// A `Delegate` to record all calls made to it.
///
/// It can be useful if you don't want to implement your own custom delegate, but instead just want
/// to quickly see a flat list of all results of the `diff` run.
///
/// # Examples
/// Please see the [tests][tests] for how to use this type.
/// [tests]: https://github.com/Byron/treediff-rs/blob/master/tests/diff.rs#L21
#[derive(Debug, PartialEq)]
pub struct Recorder<'a, K, V: 'a> {
    cursor: Vec<K>,
    /// A list of all calls the `diff` function made on us.
    pub calls: Vec<ChangeType<'a, K, V>>,
}

impl<'a, K, V> Default for Recorder<'a, K, V> {
    fn default() -> Self {
        Recorder {
            cursor: Vec::new(),
            calls: Vec::new(),
        }
    }
}

fn mk<'b, K>(c: &Vec<K>, k: Option<&'b K>) -> Vec<K>
where
    K: Clone,
{
    let mut c = c.clone();
    match k {
        Some(k) => {
            c.push(k.clone());
            c
        }
        None => c,
    }
}

impl<'a, K, V> Delegate<'a, K, V> for Recorder<'a, K, V>
where
    K: Clone,
{
    fn push<'b>(&mut self, k: &'b K) {
        self.cursor.push(k.clone())
    }
    fn pop(&mut self) {
        self.cursor.pop();
    }
    fn removed<'b>(&mut self, k: &'b K, v: &'a V) {
        self.calls
            .push(ChangeType::Removed(mk(&self.cursor, Some(k)), v));
    }
    fn added<'b>(&mut self, k: &'b K, v: &'a V) {
        self.calls
            .push(ChangeType::Added(mk(&self.cursor, Some(k)), v));
    }
    fn unchanged<'b>(&mut self, v: &'a V) {
        self.calls
            .push(ChangeType::Unchanged(self.cursor.clone(), v));
    }
    fn modified<'b>(&mut self, v1: &'a V, v2: &'a V) {
        self.calls
            .push(ChangeType::Modified(mk(&self.cursor, None), v1, v2));
    }
}
