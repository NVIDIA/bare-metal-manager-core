# This file is a curried function: a function that returns a function.
# The outer call (in flake.nix) captures the workspace-wide build context —
# craneLib, commonArgs, cargoArtifacts, allBuildInputs — once. The result,
# `mkCrateBinary`, is the inner function, which is called once per binary with
# just the per-binary arguments (pname, meta, etc.).
#
# Currying keeps the per-binary call sites concise: callers only supply what
# varies, and the shared context is bound in the closure.
{
  craneLib,
  commonArgs,
  cargoArtifacts,
  allBuildInputs,
}:

# Default helper for native workspace binaries. The deps phase is shared via
# `cargoArtifacts`, so each package derivation only rebuilds workspace crates.
{
  pname,
  cargoExtraArgs ? "",
  meta ? { },
  extraArgs ? { },
}:
let
  # Extract before merging so it can be concatenated onto allBuildInputs
  # rather than letting // override the full list.
  extraBuildInputs = extraArgs.buildInputs or [ ];
in
craneLib.buildPackage (
  commonArgs
  // {
    inherit pname cargoArtifacts meta;
    cargoExtraArgs = "--package ${pname} ${cargoExtraArgs}";
    doInstallCargoArtifacts = false;
    buildInputs = allBuildInputs ++ extraBuildInputs;
  }
  // builtins.removeAttrs extraArgs [ "buildInputs" ]
)
