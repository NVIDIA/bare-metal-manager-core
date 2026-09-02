{
  pkgs,
  # Package sets keyed by OCI architecture. buildGoModule derives GOARCH from
  # its Go toolchain, so selecting the package set is what makes cross builds
  # target the requested architecture.
  goTargetPkgs,
  version,
  meta,
  src,
  # The controller is a standalone Go module and cannot share the rest-api
  # workspace's vendoring hash.
  vendorHash,
}:

# Build the controller as a static Go binary for each published OCI
# architecture. It does not execute helpers or read packaged data at runtime,
# so the resulting binary is the container's only application payload.
let
  elfArchitecture = import ../checks/elf-architecture.nix { inherit pkgs; };

  mkController =
    goarch:
    let
      buildPkgs = goTargetPkgs.${goarch};
    in
    assert pkgs.lib.assertMsg (buildPkgs.go.GOARCH == goarch) ''
      mat-k8s-controller requested ${goarch}, but its package set builds
      ${buildPkgs.go.GOARCH}. Select the matching entry in goTargetPkgs.
    '';
    buildPkgs.buildGo126Module {
      pname = "mat-k8s-controller";
      inherit
        version
        src
        vendorHash
        ;
      subPackages = [ "cmd/mat-k8s-controller" ];

      # The current Docker build also disables CGO. Request internal linking
      # explicitly so cross builds cannot acquire a target-libc interpreter.
      env.CGO_ENABLED = "0";
      nativeBuildInputs = [
        pkgs.binutils
        pkgs.findutils
        pkgs.gawk
      ];
      ldflags = [
        "-linkmode internal"
        "-s"
        "-w"
      ];

      # Validate the actual installed ELF before the container publisher can
      # move a tag. The ARM check also enforces issue #334's 64 KiB kernel
      # compatibility at the producer boundary.
      postInstall = ''
        ${elfArchitecture}/bin/check-elf-architecture ${goarch} "$out"
        ${pkgs.lib.optionalString (goarch == "arm64") ''
          ${pkgs.bash}/bin/bash ${../../scripts/check-aarch64-pagesize.sh} "$out"
        ''}
      '';

      meta = meta // {
        mainProgram = "mat-k8s-controller";
      };
      passthru.targetOciArch = goarch;
    };

  binariesByArch = {
    amd64 = {
      mat-k8s-controller = mkController "amd64";
    };
    arm64 = {
      mat-k8s-controller = mkController "arm64";
    };
  };
in
{
  inherit binariesByArch;

  binariesAmd64 = binariesByArch.amd64;
  binariesArm64 = pkgs.lib.mapAttrs' (
    name: drv: pkgs.lib.nameValuePair "${name}-aarch64" drv
  ) binariesByArch.arm64;
}
