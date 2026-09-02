# Like crate-binary.nix but for cdylib crates (Kea hooks, FFI libraries).
# The outer call (in flake.nix) captures the workspace-wide build context
# once; the inner call is made once per library with per-library arguments.
#
# The crane build phase reuses cargoArtifacts for caching (same as binary
# builds), but the install phase copies the .so directly instead of running
# `cargo install`, which does not support cdylib targets.
{
  craneLib,
  commonArgs,
  cargoArtifacts,
  allBuildInputs,
  targetOciArch,
}:

{
  pname,
  version ? commonArgs.version,
  # File name cargo produces for this cdylib (lib<name> from [lib] name in Cargo.toml).
  # Example: "libdhcp.so" for `[lib] name = "dhcp"`.
  libFileName,
  # Path relative to $out where the .so is installed.
  # Example: "usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp.so"
  installPath,
  meta ? { },
  extraArgs ? { },
}:
let
  extraBuildInputs = extraArgs.buildInputs or [ ];
in
craneLib.buildPackage (
  commonArgs
  // {
    inherit
      pname
      version
      cargoArtifacts
      meta
      ;
    # --lib restricts the build to the cdylib target only.
    cargoExtraArgs = "--package ${pname} --lib";
    doInstallCargoArtifacts = false;
    buildInputs = allBuildInputs ++ extraBuildInputs;
    passthru = (extraArgs.passthru or { }) // {
      inherit targetOciArch;
    };
    # `cargo install` does not handle cdylib targets; find and copy the .so directly.
    # The glob covers both native (target/release/) and cross (target/<triple>/release/).
    installPhaseCommand = ''
      for f in target/release/${libFileName} target/*/release/${libFileName}; do
        [ -f "$f" ] || continue
        install -Dm755 "$f" "$out/${installPath}"
        break
      done
      [ -f "$out/${installPath}" ] || { echo "ERROR: ${libFileName} not found in target/"; exit 1; }
    '';
  }
  // builtins.removeAttrs extraArgs [
    "buildInputs"
    "passthru"
  ]
)
