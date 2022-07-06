use std::env;
/// check and make sure libipmiconsole and libipmiconsole headers are installed
fn main() {
    let statik = env::var("CARGO_FEATURE_STATIC").is_ok();

    let _libipmiconsole = pkg_config::Config::new()
        .cargo_metadata(false)
        .statik(statik)
        .probe("libipmiconsole")
        .unwrap();

}
