#![feature(test)]
extern crate slug;
extern crate test;

#[bench]
fn bench_slug(b: &mut test::Bencher) {
    use slug::slugify;
    b.iter(|| {
        test::black_box(slugify(test::black_box("My test Slug!!")));
        test::black_box(slugify(test::black_box("Test Slug2!!")));
        test::black_box(slugify(test::black_box("Æúűűűű--cool?")));
        test::black_box(slugify(test::black_box("long long long long      long")));
    })
}

#[bench]
fn bench_slug_normal(b: &mut test::Bencher) {
    use slug::slugify;
    b.iter(|| {
        test::black_box(slugify(test::black_box("My test Slug!!")));
    })
}

#[bench]
fn bench_unicode(b: &mut test::Bencher) {
    use slug::slugify;
    b.iter(|| {
        test::black_box(slugify(test::black_box("Æúűűűű--cool?")));
    })
}
