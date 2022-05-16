use super::Key;
use crate::traitdef::{Mutable, Value};
use serde_yaml::{self, to_string, Mapping, Value as SerdeYaml};
use std::mem;

fn from_str(s: &str) -> SerdeYaml {
    serde_yaml::from_str(s).expect("valid yaml document, we created the key via to_string")
}

impl Value for SerdeYaml {
    type Item = SerdeYaml;
    type Key = Key;
    fn items<'a>(&'a self) -> Option<Box<dyn Iterator<Item = (Self::Key, &'a Self::Item)> + 'a>> {
        match *self {
            SerdeYaml::String(_) | SerdeYaml::Number(_) | SerdeYaml::Bool(_) | SerdeYaml::Null => {
                None
            }
            SerdeYaml::Sequence(ref inner) => Some(Box::new(
                inner.iter().enumerate().map(|(i, v)| (Key::Index(i), v)),
            )),
            SerdeYaml::Mapping(ref inner) => Some(Box::new(inner.iter().map(|(k, v)| {
                (
                    Key::String(
                        to_string(k).expect("yaml value to serialize into yaml correctly")[4..]
                            .to_owned(),
                    ),
                    v,
                )
            }))),
        }
    }
}

impl Mutable for SerdeYaml {
    type Key = Key;
    type Item = SerdeYaml;

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
                    SerdeYaml::Mapping(Mapping::new())
                }
            };
            fn runup_array_or_value<'a>(
                array: &'a mut Vec<SerdeYaml>,
                target_index: usize,
                key_index: usize,
                last_key_index: usize,
                v: &SerdeYaml,
            ) -> &'a mut SerdeYaml {
                for _ in array.len()..target_index {
                    array.push(SerdeYaml::Null);
                }
                let value = if key_index == last_key_index {
                    v.clone()
                } else {
                    SerdeYaml::Null
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
                    Key::String(ref k) => {
                        let k = from_str(&k);
                        match { c } {
                            &mut SerdeYaml::Mapping(ref mut obj) => {
                                if obj.contains_key(&k) {
                                    let obj = obj.get_mut(&k).expect("map to work");
                                    if i == last_key_index {
                                        *obj = v.clone();
                                        return;
                                    }
                                    obj
                                } else {
                                    obj.insert(k.clone(), object_or_value(i));
                                    obj.get_mut(&k).expect("map to work")
                                }
                            }
                            c @ &mut SerdeYaml::String(_)
                            | c @ &mut SerdeYaml::Number(_)
                            | c @ &mut SerdeYaml::Bool(_)
                            | c @ &mut SerdeYaml::Null
                            | c @ &mut SerdeYaml::Sequence(_) => {
                                mem::replace(
                                    c,
                                    SerdeYaml::Mapping({
                                        let mut o = Mapping::new();
                                        o.insert(k.clone(), object_or_value(i));
                                        o
                                    }),
                                );
                                if i == last_key_index {
                                    return;
                                }
                                match c {
                                    &mut SerdeYaml::Mapping(ref mut obj) => {
                                        obj.get_mut(&k).expect("previous insertion")
                                    }
                                    _ => unreachable!(),
                                }
                            }
                        }
                    }
                    Key::Index(idx) => match { c } {
                        &mut SerdeYaml::Sequence(ref mut a) => {
                            runup_array_or_value(a, idx, i, last_key_index, v)
                        }
                        c @ &mut SerdeYaml::String(_)
                        | c @ &mut SerdeYaml::Number(_)
                        | c @ &mut SerdeYaml::Bool(_)
                        | c @ &mut SerdeYaml::Null
                        | c @ &mut SerdeYaml::Mapping(_) => {
                            let mut a = Vec::new();
                            runup_array_or_value(&mut a, idx, i, last_key_index, v);
                            mem::replace(c, SerdeYaml::Sequence(a));
                            if i == last_key_index {
                                return;
                            }
                            match c {
                                &mut SerdeYaml::Sequence(ref mut a) => {
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
                Key::String(ref k) => {
                    let k = from_str(&k);
                    match { c } {
                        &mut SerdeYaml::Mapping(ref mut obj) => {
                            if i == last_key_index {
                                obj.remove(&k);
                                return;
                            } else {
                                match obj.get_mut(&k) {
                                    Some(json) => json,
                                    None => return,
                                }
                            }
                        }
                        _ => return,
                    }
                }
                Key::Index(idx) => match { c } {
                    &mut SerdeYaml::Sequence(ref mut a) => {
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
