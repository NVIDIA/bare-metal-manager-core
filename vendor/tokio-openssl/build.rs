use std::env;

fn main() {
    if let Ok(version) = env::var("DEP_OPENSSL_VERSION_NUMBER") {
        let version = u64::from_str_radix(&version, 16).unwrap();

        if version >= 0x1_01_01_00_0 {
            println!("cargo:rustc-cfg=ossl111");
        }
    }
}
