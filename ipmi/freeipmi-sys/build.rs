use std::env;

/// check and make sure libfreeipmi and libfreeipmi headers are installed
fn main() {
    let statik = env::var("CARGO_FEATURE_STATIC").is_ok();

    let _libfreeipmi = pkg_config::Config::new()
        .cargo_metadata(false)
        .statik(statik)
        .probe("libfreeipmi")
        .unwrap();
}
