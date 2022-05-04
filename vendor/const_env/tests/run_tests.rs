use std::env::set_var;
use std::path::PathBuf;

use compiletest_rs as ct;

fn run_test(mode: &str) {
    let mut config = ct::Config::default();
    config.mode = mode.parse().expect("Invalid mode");
    config.src_base = PathBuf::from(format!("tests/{}", mode));
    config.link_deps();
    config.clean_rmeta();

    ct::run_tests(&config);
}

#[test]
fn smoke() {
    set_var("EXPLICIT_OVERRIDE_ISIZE", "123");
    set_var("EXPLICIT_OVERRIDE_F64", "123.0");
    set_var("IMPLICIT_ISIZE", "123");
    set_var("IMPLICIT_F64", "123.0");
    set_var("NEGATIVE_I16", "-123");
    set_var("NEGATIVE_ISIZE", "-321");
    set_var("NEGATIVE_F32", "-456f32");
    set_var("SMOKE_STR", "bar");
    set_var("SMOKE_U32", "321");
    run_test("run-pass");
}