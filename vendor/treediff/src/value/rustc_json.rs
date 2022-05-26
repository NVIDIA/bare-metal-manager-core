use super::Key;
use crate::traitdef::{Mutable, Value};
use rustc_serialize::json::{Json as RustcJson, Object};
use std::{collections::btree_map::Entry::*, mem};

impl Value for RustcJson {
    type Item = RustcJson;
    type Key = Key;
    fn items<'a>(&'a self) -> Option<Box<dyn Iterator<Item = (Self::Key, &'a Self::Item)> + 'a>> {
        match *self {
            RustcJson::String(_)
            | RustcJson::U64(_)
            | RustcJson::I64(_)
            | RustcJson::F64(_)
            | RustcJson::Boolean(_)
            | RustcJson::Null => None,
            RustcJson::Array(ref inner) => Some(Box::new(
                inner.iter().enumerate().map(|(i, v)| (Key::Index(i), v)),
            )),
            RustcJson::Object(ref inner) => Some(Box::new(
                inner.iter().map(|(s, v)| (Key::String(s.clone()), v)),
            )),
        }
    }
}

impl Mutable for RustcJson {
    type Key = Key;
    type Item = RustcJson;

    fn set(&mut self, keys: &[Self::Key], v: &Self::Item) {
        if keys.len() == 0 {
            *self = v.clone();
        } else {
            let mut c = self;
            let last_key_index = keys.len() - 1;
            let object_or_value = |index| {
                if index == last_key_index {
                    v.clone()
                } else {
                    RustcJson::Object(Object::new())
                }
            };
            fn runup_array_or_value<'a>(
                array: &'a mut Vec<RustcJson>,
                target_index: usize,
                key_index: usize,
                last_key_index: usize,
                v: &RustcJson,
            ) -> &'a mut RustcJson {
                for _ in array.len()..target_index {
                    array.push(RustcJson::Null);
                }
                let value = if key_index == last_key_index {
                    v.clone()
                } else {
                    RustcJson::Null
                };
                if target_index == array.len() {
                    array.push(value);
                } else {
                    array[target_index] = value;
                }
                &mut array[target_index]
            };
            for (i, k) in keys.iter().enumerate() {
                c = match *k {
                    Key::String(ref k) => match { c } {
                        &mut RustcJson::Object(ref mut obj) => match obj.entry(k.clone()) {
                            Vacant(e) => e.insert(object_or_value(i)),
                            Occupied(e) => {
                                if i == last_key_index {
                                    *e.into_mut() = v.clone();
                                    return;
                                } else {
                                    e.into_mut()
                                }
                            }
                        },
                        c @ &mut RustcJson::String(_)
                        | c @ &mut RustcJson::F64(_)
                        | c @ &mut RustcJson::Boolean(_)
                        | c @ &mut RustcJson::Null
                        | c @ &mut RustcJson::U64(_)
                        | c @ &mut RustcJson::Array(_)
                        | c @ &mut RustcJson::I64(_) => {
                            mem::replace(
                                c,
                                RustcJson::Object({
                                    let mut o = Object::new();
                                    o.insert(k.clone(), object_or_value(i));
                                    o
                                }),
                            );
                            if i == last_key_index {
                                return;
                            }
                            match c {
                                &mut RustcJson::Object(ref mut obj) => {
                                    obj.get_mut(k).expect("previous insertion")
                                }
                                _ => unreachable!(),
                            }
                        }
                    },
                    Key::Index(idx) => match { c } {
                        &mut RustcJson::Array(ref mut a) => {
                            runup_array_or_value(a, idx, i, last_key_index, v)
                        }
                        c @ &mut RustcJson::String(_)
                        | c @ &mut RustcJson::F64(_)
                        | c @ &mut RustcJson::Boolean(_)
                        | c @ &mut RustcJson::Null
                        | c @ &mut RustcJson::U64(_)
                        | c @ &mut RustcJson::Object(_)
                        | c @ &mut RustcJson::I64(_) => {
                            let mut a = Vec::new();
                            runup_array_or_value(&mut a, idx, i, last_key_index, v);
                            mem::replace(c, RustcJson::Array(a));
                            if i == last_key_index {
                                return;
                            }
                            match c {
                                &mut RustcJson::Array(ref mut a) => {
                                    a.get_mut(idx).expect("previous insertion")
                                }
                                _ => unreachable!(),
                            }
                        }
                    },
                }
            }
        }
    }

    fn remove(&mut self, keys: &[Self::Key]) {
        let mut c = self;
        let last_key_index = keys.len().checked_sub(1).expect("at least one key");
        for (i, k) in keys.iter().enumerate() {
            c = match *k {
                Key::String(ref k) => match { c } {
                    &mut RustcJson::Object(ref mut obj) => {
                        if i == last_key_index {
                            obj.remove(k);
                            return;
                        } else {
                            match obj.get_mut(k) {
                                Some(json) => json,
                                None => return,
                            }
                        }
                    }
                    _ => return,
                },
                Key::Index(idx) => match { c } {
                    &mut RustcJson::Array(ref mut a) => {
                        if i == last_key_index {
                            a.remove(idx);
                            return;
                        } else {
                            match a.get_mut(idx) {
                                Some(json) => json,
                                None => return,
                            }
                        }
                    }
                    _ => return,
                },
            }
        }
    }
}
