use super::Key;
use crate::traitdef::{Mutable, Value};
use serde_json::{map, Map, Value as SerdeJson};
use std::mem;

impl Value for SerdeJson {
    type Item = SerdeJson;
    type Key = Key;
    fn items<'a>(&'a self) -> Option<Box<dyn Iterator<Item = (Self::Key, &'a Self::Item)> + 'a>> {
        match *self {
            SerdeJson::String(_) | SerdeJson::Number(_) | SerdeJson::Bool(_) | SerdeJson::Null => {
                None
            }
            SerdeJson::Array(ref inner) => Some(Box::new(
                inner.iter().enumerate().map(|(i, v)| (Key::Index(i), v)),
            )),
            SerdeJson::Object(ref inner) => Some(Box::new(
                inner.iter().map(|(s, v)| (Key::String(s.clone()), v)),
            )),
        }
    }
}

impl Mutable for SerdeJson {
    type Key = Key;
    type Item = SerdeJson;

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
                    SerdeJson::Object(Map::new())
                }
            };
            fn runup_array_or_value<'a>(
                array: &'a mut Vec<SerdeJson>,
                target_index: usize,
                key_index: usize,
                last_key_index: usize,
                v: &SerdeJson,
            ) -> &'a mut SerdeJson {
                for _ in array.len()..target_index {
                    array.push(SerdeJson::Null);
                }
                let value = if key_index == last_key_index {
                    v.clone()
                } else {
                    SerdeJson::Null
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
                        &mut SerdeJson::Object(ref mut obj) => match obj.entry(k.clone()) {
                            map::Entry::Vacant(e) => e.insert(object_or_value(i)),
                            map::Entry::Occupied(e) => {
                                if i == last_key_index {
                                    *e.into_mut() = v.clone();
                                    return;
                                } else {
                                    e.into_mut()
                                }
                            }
                        },
                        c @ &mut SerdeJson::String(_)
                        | c @ &mut SerdeJson::Number(_)
                        | c @ &mut SerdeJson::Bool(_)
                        | c @ &mut SerdeJson::Null
                        | c @ &mut SerdeJson::Array(_) => {
                            mem::replace(
                                c,
                                SerdeJson::Object({
                                    let mut o = Map::new();
                                    o.insert(k.clone(), object_or_value(i));
                                    o
                                }),
                            );
                            if i == last_key_index {
                                return;
                            }
                            match c {
                                &mut SerdeJson::Object(ref mut obj) => {
                                    obj.get_mut(k).expect("previous insertion")
                                }
                                _ => unreachable!(),
                            }
                        }
                    },
                    Key::Index(idx) => match { c } {
                        &mut SerdeJson::Array(ref mut a) => {
                            runup_array_or_value(a, idx, i, last_key_index, v)
                        }
                        c @ &mut SerdeJson::String(_)
                        | c @ &mut SerdeJson::Number(_)
                        | c @ &mut SerdeJson::Bool(_)
                        | c @ &mut SerdeJson::Null
                        | c @ &mut SerdeJson::Object(_) => {
                            let mut a = Vec::new();
                            runup_array_or_value(&mut a, idx, i, last_key_index, v);
                            mem::replace(c, SerdeJson::Array(a));
                            if i == last_key_index {
                                return;
                            }
                            match c {
                                &mut SerdeJson::Array(ref mut a) => {
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
                    &mut SerdeJson::Object(ref mut obj) => {
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
                    &mut SerdeJson::Array(ref mut a) => {
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
