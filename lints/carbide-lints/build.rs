fn main() {
    let rustc = std::env::var("RUSTC").unwrap();
    let output = std::process::Command::new(rustc).arg("--print=sysroot").output();
    let stdout = String::from_utf8(output.unwrap().stdout).unwrap();
    let sysroot = stdout.trim_end();
    println!("cargo:rustc-link-arg=-Wl,-rpath={sysroot}/lib")
}
