{
  pkgs,
  amd64Packages,
  arm64Packages,
}:

let
  inherit (pkgs) lib;
  elfArchitecture = import ./elf-architecture.nix { inherit pkgs; };

  tools = [
    pkgs.bash
    pkgs.binutils
    pkgs.findutils
  ];

  renderArchitectureChecks =
    architecture: packages:
    lib.concatStringsSep "\n" (
      lib.mapAttrsToList (name: package: ''
        echo "Checking ${name} (${architecture})"
        ${elfArchitecture}/bin/check-elf-architecture \
          ${lib.escapeShellArg architecture} \
          ${lib.escapeShellArg (toString package)} || failed=1
      '') packages
    );

  renderPageSizeChecks = lib.concatStringsSep "\n" (
    lib.mapAttrsToList (name: package: ''
      echo "Checking ${name} for 64 KiB kernel compatibility"
      ${pkgs.bash}/bin/bash ${../../scripts/check-aarch64-pagesize.sh} \
        ${lib.escapeShellArg (toString package)} || failed=1
    '') arm64Packages
  );
in
assert lib.assertMsg (
  builtins.attrNames amd64Packages != [ ]
) "the ELF architecture check requires amd64 packages";
assert lib.assertMsg (
  builtins.attrNames arm64Packages != [ ]
) "the ELF checks require arm64 packages";
{
  elf-architectures = pkgs.runCommand "check-elf-architectures" { nativeBuildInputs = tools; } ''
    failed=0
    ${renderArchitectureChecks "amd64" amd64Packages}
    ${renderArchitectureChecks "arm64" arm64Packages}

    if [ "$failed" -ne 0 ]; then
      exit 1
    fi
    touch "$out"
  '';

  # https://github.com/NVIDIA/infra-controller/issues/334 requires binaries
  # that load on both 4 KiB and 64 KiB ARM64 kernels. A 64 KiB-aligned PT_LOAD
  # segment remains compatible with 4 KiB kernels, so the larger check proves
  # both cases.
  aarch64-page-size = pkgs.runCommand "check-aarch64-page-size" { nativeBuildInputs = tools; } ''
    failed=0
    ${renderPageSizeChecks}

    if [ "$failed" -ne 0 ]; then
      exit 1
    fi
    touch "$out"
  '';
}
