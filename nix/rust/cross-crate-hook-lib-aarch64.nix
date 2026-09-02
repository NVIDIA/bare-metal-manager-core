# Like cross-crate-binary-aarch64.nix but for cdylib crates (Kea hooks, FFI libraries).
# The outer call captures the workspace-wide cross-compile context; the inner
# call is made once per library.
#
# Cross builds intentionally do not reuse native cargoArtifacts: x86_64 deps
# cannot be reused for an aarch64 link. Crane derives target-specific deps from
# the cross package args.
{
  pkgs,
  crane,
  rustToolchainFor,
  src,
  version,
  crossPkgs ? pkgs.pkgsCross.aarch64-multiplatform // {
    stdenv = pkgs.pkgsCross.aarch64-multiplatform.gcc13Stdenv;
  },
}:

let
  crossCraneLib = (crane.mkLib crossPkgs).overrideToolchain rustToolchainFor;
in
{
  pname,
  libFileName,
  installPath,
  meta ? { },
  extraArgs ? { },
}:
let
  extraBuildInputs = extraArgs.buildInputs or [ ];
in
crossCraneLib.buildPackage (
  {
    inherit
      meta
      src
      version
      pname
      ;
    strictDeps = true;
    doCheck = false;
    doInstallCargoArtifacts = false;

    cargoExtraArgs = "--package ${pname} --lib";

    CARGO_BUILD_TARGET = "aarch64-unknown-linux-gnu";
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS = "-C link-arg=-Wl,-z,max-page-size=0x10000";

    depsBuildBuild = with pkgs; [
      stdenv.cc
    ];

    buildInputs =
      (with crossPkgs; [
        openssl
        tpm2-tss.dev
        libudev-zero
      ])
      ++ extraBuildInputs;

    runtimeDependencies = [ crossPkgs.stdenv.cc.cc.lib ];
    autoPatchelfIgnoreMissingDeps = [ "libgcc_s.so.1" ];
    passthru = (extraArgs.passthru or { }) // {
      targetOciArch = "arm64";
    };

    nativeBuildInputs = with pkgs; [
      cmake
      clang
      lld
      pkg-config
      protobuf
      autoPatchelfHook
    ];

    SQLX_OFFLINE = "true";
    PROTOC = "${pkgs.protobuf}/bin/protoc";
    PROTOC_INCLUDE = "${pkgs.protobuf}/include";

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
