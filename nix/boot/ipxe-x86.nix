# ==============================================================================
# carbide iPXE EFI bootloader for x86_64
#
# Builds two EFI binaries from upstream iPXE with carbide-specific patches
# and config headers applied:
#
#   $out/blobs/x86_64/ipxe.efi    (snponly variant — generic SNP)
#   $out/blobs/x86_64/golan.efi   (Mellanox-specific variant)
#
# Inputs are explicit:
#   - The iPXE upstream source comes from fetchFromGitHub at a pinned
#     commit (NOT the local submodule). Pinning by hash makes the build
#     hermetic and reproducible — Nix verifies the fetched content
#     matches the expected hash, so a force-pushed upstream tag can't
#     silently change behavior.
#   - Patches and config headers are paths from pxe/ipxe/local/, passed
#     in by the caller (flake.nix) so the relative-path arithmetic
#     stays in one place.
#
# Patches applied — matching what pxe/Makefile.toml's `ipxe-x86_64` task
# depends on. The BlueField NIC patch is deliberately absent; it is aarch64
# only:
#   - 0001-efi-Add-TPM-measurement-API (TPM measured boot via TCG v1/v2)
#   - 0003-efi-prevent-load-image-watchdog-timeout (EFI watchdog fix)
# ==============================================================================
{
  pkgs,

  # Upstream commit to build (mirrors the submodule pin in .gitmodules).
  # Bump this and the hash together when iPXE upstream is updated.
  ipxeRev,
  ipxeHash,

  # Patches applied in order via stdenv's patchPhase.
  ipxePatches,

  # Carbide-specific config headers copied into src/config/local/.
  ipxeConfigHeaders,

  # Free-form version string baked into the iPXE banner. Defaults to
  # the carbide git rev when invoked from flake.nix.
  bannerVersion ? "carbide",

  # iPXE boot script to embed in the EFI binary. Without it, the EFI
  # image only runs iPXE's built-in autoboot on each NIC — which falls
  # through to "Nothing to boot" when no DHCP next-server/filename is
  # offered. Mirrors cargo-make's `EMBED=...` flag in the
  # `ipxe-build-efi-x86_64` task.
  embedScript,
}:

# Pin to gcc13Stdenv. Carbide's deploy target is Ubuntu 24.04 (Noble)
# which ships gcc 13 as default — using the same compiler matches the
# environment iPXE binaries will be alongside on the bare-metal host.
pkgs.gcc13Stdenv.mkDerivation {
  pname = "carbide-ipxe-efi-x86_64";
  version = bannerVersion;

  src = pkgs.fetchFromGitHub {
    owner = "ipxe";
    repo = "ipxe";
    rev = ipxeRev;
    hash = ipxeHash;
  };

  patches = ipxePatches;

  # iPXE's build assumes config headers live at src/config/local/. The
  # cargo-make ipxe-config task does this copy; we replicate it here in
  # postPatch (which runs after stdenv applies `patches`, before build).
  #
  # Each header is interpolated as ${header} (not via toString) so Nix
  # adds the proper "this path is a dependency" context, copies the
  # header into the build sandbox, and substitutes the real /nix/store/
  # location into the install command.
  postPatch = ''
    mkdir -p src/config/local
    ${pkgs.lib.concatMapStringsSep "\n" (
      h: "install -m 644 ${h} src/config/local/${baseNameOf (toString h)}"
    ) ipxeConfigHeaders}
  '';

  nativeBuildInputs = with pkgs; [
    perl                # iPXE's makefiles invoke perl for codegen
    xz                  # used by some iPXE compression steps
    binutils            # ld, ranlib, ar
  ];

  # iPXE's makefile lives in src/ and expects to be invoked from there.
  # We don't use the standard configure/build/install phases because
  # iPXE's build doesn't follow autotools conventions.
  dontConfigure = true;

  buildPhase = ''
    runHook preBuild
    cd src

    # Mirror the cargo-make build: produce snponly.efi (generic) and
    # golan.efi (Mellanox-specific). The VERSION= argument shows up
    # in the iPXE startup banner.
    #
    # DEBUG=tls enables iPXE's TLS-layer debug logging. It must match the
    # cargo-make build (pxe/Makefile.toml, ipxe-build-efi-x86_64) — without
    # it the binaries differ from what ships today and TLS failures during
    # PXE boot become undiagnosable in the field.
    make -j$NIX_BUILD_CORES \
      EMBED=${embedScript} \
      DEBUG=tls \
      bin-x86_64-efi/snponly.efi \
      bin-x86_64-efi/golan.efi \
      VERSION=${pkgs.lib.escapeShellArg bannerVersion}

    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall

    # Layout matches the cargo-make output for drop-in compatibility:
    #   pxe/static/blobs/internal/x86_64/ipxe.efi  ←  bin-x86_64-efi/snponly.efi
    #   pxe/static/blobs/internal/x86_64/golan.efi
    mkdir -p $out/blobs/x86_64
    install -m 644 bin-x86_64-efi/snponly.efi $out/blobs/x86_64/ipxe.efi
    install -m 644 bin-x86_64-efi/golan.efi   $out/blobs/x86_64/golan.efi

    runHook postInstall
  '';

  # Outputs are EFI executables, not ELF — autoPatchelfHook would try
  # to inspect them and fail. iPXE binaries don't have RPATH concerns
  # because they're standalone bootloaders.
  dontFixup = true;

  meta = {
    description = "iPXE EFI bootloader for x86_64 with carbide patches";
    homepage = "https://ipxe.org/";
    license = pkgs.lib.licenses.gpl2Plus;
    platforms = [ "x86_64-linux" ];
  };
}
