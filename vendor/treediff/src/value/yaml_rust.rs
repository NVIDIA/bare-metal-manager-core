use super::Key;
use crate::traitdef::{Mutable, Value};
use std::mem;
use yaml_rust::{yaml::Hash, Yaml, YamlEmitter, YamlLoader};

fn from_str(s: &str) -> Yaml {
    let mut v = YamlLoader::load_from_str(s)
        .expect("valid yaml value - we serialized it beforehand after all");
    assert!(
        v.len() == 1,
        "need exactly one document - multi-document keys are just not possible"
    );
    v.pop().unwrap()
}

fn to_string(v: &Yaml) -> String {
    let mut buf = String::new();
    YamlEmitter::new(&mut buf)
        .dump(v)
        .expect("valid yaml value");
    buf[4..].to_owned()
}

impl Value for Yaml {
    type Item = Yaml;
    type Key = Key;
    fn items<'a>(&'a self) -> Option<Box<dyn Iterator<Item = (Self::Key, &'a Self::Item)> + 'a>> {
        match *self {
            Yaml::String(_)
            | Yaml::Integer(_)
            | Yaml::Real(_)
            | Yaml::Boolean(_)
            | Yaml::Null
            | Yaml::Alias(_)
            | Yaml::BadValue => None,
            Yaml::Array(ref inner) => Some(Box::new(
                inner.iter().enumerate().map(|(i, v)| (Key::Index(i), v)),
            )),
            Yaml::Hash(ref inner) => Some(Box::new(
                inner.iter().map(|(k, v)| (Key::String(to_string(k)), v)),
            )),
        }
    }
}

impl Mutable for Yaml {
    type Key = Key;
    type Item = Yaml;

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
                    Yaml::Hash(Hash::new())
                }
            };
            fn runup_array_or_value<'a>(
                array: &'a mut Vec<Yaml>,
                target_index: usize,
                key_index: usize,
                last_key_index: usize,
                v: &Yaml,
            ) -> &'a mut Yaml {
                for _ in array.len()..target_index {
                    array.push(Yaml::Null);
                }
                let value = if key_index == last_key_index {
                    v.clone()
                } else {
                    Yaml::Null
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
                            &mut Yaml::Hash(ref mut obj) => {
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
                            c @ &mut Yaml::String(_)
                            | c @ &mut Yaml::Integer(_)
                            | c @ &mut Yaml::Real(_)
                            | c @ &mut Yaml::Boolean(_)
                            | c @ &mut Yaml::Null
                            | c @ &mut Yaml::Alias(_)
                            | c @ &mut Yaml::BadValue
                            | c @ &mut Yaml::Array(_) => {
                                mem::replace(
                                    c,
                                    Yaml::Hash({
                                        let mut o = Hash::new();
                                        o.insert(k.clone(), object_or_value(i));
                                        o
                                    }),
                                );
                                if i == last_key_index {
                                    return;
                                }
                                match c {
                                    &mut Yaml::Hash(ref mut obj) => {
                                        obj.get_mut(&k).expect("previous insertion")
                                    }
                                    _ => unreachable!(),
                                }
                            }
                        }
                    }
                    Key::Index(idx) => match { c } {
                        &mut Yaml::Array(ref mut a) => {
                            runup_array_or_value(a, idx, i, last_key_index, v)
                        }
                        c @ &mut Yaml::String(_)
                        | c @ &mut Yaml::Alias(_)
                        | c @ &mut Yaml::BadValue
                        | c @ &mut Yaml::Integer(_)
                        | c @ &mut Yaml::Real(_)
                        | c @ &mut Yaml::Boolean(_)
                        | c @ &mut Yaml::Null
                        | c @ &mut Yaml::Hash(_) => {
                            let mut a = Vec::new();
                            runup_array_or_value(&mut a, idx, i, last_key_index, v);
                            mem::replace(c, Yaml::Array(a));
                            if i == last_key_index {
                                return;
                            }
                            match c {
                                &mut Yaml::Array(ref mut a) => {
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
                        &mut Yaml::Hash(ref mut obj) => {
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
                    &mut Yaml::Array(ref mut a) => {
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
