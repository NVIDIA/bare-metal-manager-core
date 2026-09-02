{
  pkgs,
  container,
}:

let
  elfArchitecture = import ./elf-architecture.nix { inherit pkgs; };
  primaryPackages = container.passthru.primaryPackages;
  packageChecks = pkgs.lib.concatMapStrings (package: ''
    ${elfArchitecture}/bin/check-elf-architecture arm64 ${pkgs.lib.escapeShellArg (toString package)}
    ${pkgs.bash}/bin/bash ${../../scripts/check-aarch64-pagesize.sh} ${pkgs.lib.escapeShellArg (toString package)}
  '') primaryPackages;
in
assert pkgs.lib.assertMsg (
  container.passthru.targetOciArch == "arm64"
) "native ARM container ELF check requires an arm64 image";
assert pkgs.lib.assertMsg (
  primaryPackages != [ ]
) "native ARM container ELF check requires at least one primary package";
pkgs.runCommand "check-native-aarch64-container-elf"
  {
    nativeBuildInputs = with pkgs; [
      bash
      binutils
      findutils
      gawk
    ];
  }
  ''
    set -euo pipefail

    ${packageChecks}
    touch "$out"
  ''
