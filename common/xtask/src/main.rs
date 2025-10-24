mod move_deps_to_workspace;

use std::env::args;

use crate::move_deps_to_workspace::move_deps_to_workspace;

fn main() -> eyre::Result<()> {
    match args().nth(1).as_deref() {
        Some("move-deps-to-workspace") => move_deps_to_workspace()?,
        _ => eprintln!("Usage: cargo xtask move-deps-to-workspace"),
    };

    Ok(())
}
