#![feature(test)]
#![cfg(feature = "nightly")]
extern crate json_patch;
extern crate rand;
extern crate serde_json;
extern crate test;

use self::rand::SeedableRng;
use self::test::Bencher;
use json_patch::*;

mod generator;

#[bench]
fn bench_add_removes(b: &mut Bencher) {
    let mut rng = rand::StdRng::from_seed(Default::default());
    let params = generator::Params {
        ..Default::default()
    };
    let doc = params.gen(&mut rng);
    let patches = generator::gen_add_remove_patches(&doc, &mut rng, 10, 10);

    b.iter(|| {
        let mut doc = doc.clone();
        let mut result = Ok(());
        for ref p in &patches {
            // Patch mutable
            result = result.and_then(|_| patch(&mut doc, p));
        }
    });
}

#[cfg(feature = "nightly")]
#[bench]
fn bench_add_removes_unsafe(b: &mut Bencher) {
    let mut rng = rand::StdRng::from_seed(Default::default());
    let params = generator::Params {
        ..Default::default()
    };
    let doc = params.gen(&mut rng);
    let patches = generator::gen_add_remove_patches(&doc, &mut rng, 10, 10);

    b.iter(|| {
        let mut doc = doc.clone();
        let mut result = Ok(());
        for ref p in &patches {
            // Patch mutable
            result = result.and_then(|_| patch_unsafe(&mut doc, p));
        }
    });
}
