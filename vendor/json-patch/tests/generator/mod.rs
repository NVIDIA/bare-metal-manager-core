use super::rand::distributions::Alphanumeric;
use super::rand::Rng;
use super::{AddOperation, Patch, PatchOperation, RemoveOperation};
use serde_json::{Map, Value};
use std::fmt::Write;

pub struct Params {
    pub array_size: usize,
    pub map_size: usize,
    pub value_size: usize,
    pub depth: usize,
    pub key_size: usize,
}

impl Default for Params {
    fn default() -> Self {
        Params {
            array_size: 6,
            map_size: 6,
            value_size: 100,
            depth: 8,
            key_size: 20,
        }
    }
}

fn rand_str<R: Rng>(rng: &mut R, max_len: usize) -> String {
    let len = rng.gen::<usize>() % max_len + 1;
    rng.sample_iter(&Alphanumeric).take(len).collect()
}

fn rand_literal<R: Rng>(rng: &mut R, value_size: usize) -> Value {
    match rng.gen::<u32>() % 4 {
        0 => Value::Null,
        1 => Value::String(rand_str(rng, value_size)),
        2 => Value::Bool(false),
        3 => Value::from(rng.gen::<u64>()),
        _ => panic!(),
    }
}

impl Params {
    pub fn gen<R: Rng>(&self, rng: &mut R) -> Value {
        self.gen_internal(self.depth, rng)
    }

    fn gen_internal<R: Rng>(&self, depth: usize, rng: &mut R) -> Value {
        if depth == 0 {
            rand_literal(rng, self.value_size)
        } else if rng.gen::<bool>() {
            // Generate random array
            let len = (rng.gen::<usize>() % self.array_size) + 1;
            let vec: Vec<Value> = (0..len)
                .map(|_| self.gen_internal(depth - 1, rng))
                .collect();
            Value::from(vec)
        } else {
            // Generate random object
            let len = (rng.gen::<usize>() % self.map_size) + 1;
            let map: Map<String, Value> = (0..len)
                .map(|_| {
                    (
                        rand_str(rng, self.key_size),
                        self.gen_internal(depth - 1, rng),
                    )
                })
                .collect();
            Value::from(map)
        }
    }
}

pub fn gen_add_remove_patches<R: Rng>(
    value: &Value,
    rnd: &mut R,
    patches: usize,
    operations: usize,
) -> Vec<Patch> {
    let leafs = all_leafs(value);
    let mut vec = Vec::new();
    for _ in 0..patches {
        let mut ops = Vec::new();
        for _ in 0..operations {
            let path = &rnd.choose(&leafs).unwrap();
            ops.push(PatchOperation::Remove(RemoveOperation {
                path: (*path).clone(),
            }));
            ops.push(PatchOperation::Add(AddOperation {
                path: (*path).clone(),
                value: Value::Null,
            }));
        }
        vec.push(Patch(ops));
    }
    vec
}

fn all_leafs(value: &Value) -> Vec<String> {
    let mut result = Vec::new();
    collect_leafs(value, &mut String::new(), &mut result);
    result
}

fn collect_leafs(value: &Value, prefix: &mut String, result: &mut Vec<String>) {
    match *value {
        Value::Array(ref arr) => {
            for (idx, val) in arr.iter().enumerate() {
                let l = prefix.len();
                write!(prefix, "/{}", idx).unwrap();
                collect_leafs(val, prefix, result);
                prefix.truncate(l);
            }
        }
        Value::Object(ref map) => {
            for (key, val) in map.iter() {
                let l = prefix.len();
                write!(prefix, "/{}", key).unwrap();
                collect_leafs(val, prefix, result);
                prefix.truncate(l);
            }
        }
        _ => {
            result.push(prefix.clone());
        }
    }
}
