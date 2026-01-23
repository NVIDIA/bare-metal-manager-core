use std::path::PathBuf;
use std::process::Command;

#[test]
fn driver_runs_and_emits_expected_lint() {
    // Path to the fixture crate
    let manifest_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("app")
        .join("Cargo.toml");

    let stderr_fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("app")
        .join("src")
        .join("main.stderr");

    let expected_stderr =
        std::fs::read_to_string(&stderr_fixture_path).expect("Could not read main.stderr");

    // Path to the just-built compiler driver binary
    let driver = env!("CARGO_BIN_EXE_carbide-lints");

    // Optionally isolate target dir so we don't fight with main workspace targets
    let target_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("driver_tests");

    let cargo = std::env::var("CARGO").expect("Cargo should set $CARGO to the running binary");

    let output = Command::new(cargo)
        .arg("check")
        .arg("--manifest-path")
        .arg(&manifest_path)
        .env("RUSTC", driver)
        .env("CARGO_TARGET_DIR", &target_dir)
        .output()
        .expect("failed to run cargo check with carbide-lints");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let relevant_stderr = stderr
        .lines()
        .skip_while(|l| !l.contains("Checking sqlx_app ")) // last line before our stderr
        .skip(1) // skip that line
        .collect::<Vec<_>>()
        .join("\n");

    let diff = similar::TextDiff::from_lines(&expected_stderr, &relevant_stderr)
        .unified_diff()
        .context_radius(3)
        .header("expected", "output")
        .to_string();

    // Now assert on stderr
    assert!(
        diff.is_empty(),
        "Compiler output did not match expected. Diff:\n\n{diff}"
    );
}
