# ==============================================================================
# carbide iPXE EFI bootloader for aarch64
#
# Builds two EFI binaries from upstream iPXE with carbide-specific patches
# and config headers applied:
#
#   $out/blobs/aarch64/ipxe.efi
#   $out/blobs/aarch64/golan.efi
#
# Cross-compilation: this derivation runs on x86_64 build hosts but
# produces aarch64 output. We use pkgsCross.aarch64-multiplatform.gcc13Stdenv
# which provides a complete cross-toolchain (gcc, binutils, linker hooks).
# nativeBuildInputs (perl, xz) come from pkgs (x86_64) because they're
# host tools; nothing in buildInputs because iPXE is freestanding.
#
# Patches applied — a different set from ipxe-x86.nix, matching what
# pxe/Makefile.toml's `ipxe-aarch64` task depends on:
#   - 0001-fix-update-to-allow-iPXE-to-boot-on-BlueField-NICs (BlueField NIC support)
# ==============================================================================
{
  pkgs,

  # Upstream commit to build (mirrors the submodule pin).
  ipxeRev,
  ipxeHash,

  # Patches applied in order via stdenv's patchPhase.
  ipxePatches,

  # Carbide-specific config headers copied into src/config/local/.
  ipxeConfigHeaders,

  # Free-form version string baked into the iPXE banner.
  bannerVersion ? "carbide",

  # iPXE boot script to embed in the EFI binary. iPXE runs this script
  # right after init, before falling through to the built-in autoboot.
  # Without it, the EFI image is stock-iPXE-with-our-banner and runs
  # only autoboot on each NIC — which is what produces the "Nothing to
  # boot" pattern when no DHCP next-server/filename is offered.
  # Mirrors cargo-make's `EMBED=...` flag in pxe/Makefile.toml's
  # `ipxe-build-efi-aarch64` task.
  embedScript,
}:

let
  # Cross-compile target. The .gcc13Stdenv suffix matches the gcc version
  # used in ipxe-x86.nix so both arches get the same toolchain generation.
  crossStdenv = pkgs.pkgsCross.aarch64-multiplatform.gcc13Stdenv;
in

crossStdenv.mkDerivation rec {
  pname = "carbide-ipxe-efi-aarch64";
  version = bannerVersion;

  src = pkgs.fetchFromGitHub {
    owner = "ipxe";
    repo = "ipxe";
    rev = ipxeRev;
    hash = ipxeHash;
  };

  patches = ipxePatches;

  passthru.ossSources = [ src ] ++ ipxePatches ++ ipxeConfigHeaders ++ [ embedScript ];

  postPatch = ''
    mkdir -p src/config/local
    ${pkgs.lib.concatMapStringsSep "\n" (
      h: "install -m 644 ${h} src/config/local/${baseNameOf (toString h)}"
    ) ipxeConfigHeaders}
  '';

  # nativeBuildInputs run on the build host (x86_64), so they come from
  # `pkgs` not `pkgsCross`. perl + xz are pure-Perl/userspace tools the
  # iPXE makefiles invoke during codegen.
  #
  # gcc13 (host) is needed in addition to the cross compiler because
  # iPXE's makefile builds host-side utilities (notably util/elf2efi64,
  # which converts ELF intermediates to PE32+ EFI). HOST_CC defaults to
  # plain `gcc`, which doesn't exist in a cross-only sandbox — only
  # `aarch64-unknown-linux-gnu-gcc` would be there. Adding pkgs.gcc13
  # provides an x86_64 gcc for HOSTCC.
  nativeBuildInputs = with pkgs; [
    perl
    xz
    gcc13
  ];

  hardeningDisable = [
    "pic"
    "stackprotector"
  ];

  dontConfigure = true;

  # The cross stdenv exports CC/LD/AR that point at the aarch64 toolchain
  # (e.g. CC=aarch64-unknown-linux-gnu-gcc). `CROSS=` is iPXE's public make
  # interface for selecting that prefix; `CROSS_COMPILE=` is ignored.
  buildPhase = ''
    runHook preBuild
    cd src

    # CROSS makes iPXE use the cross toolchain for target code.
    # HOST_CC explicitly points at the x86_64 gcc for build-time tools
    # (elf2efi64, etc.) — without this, iPXE's makefile would invoke
    # plain `gcc`, which the cross-stdenv sandbox doesn't expose.
    #
    # DEBUG=snp,tls enables iPXE debug logging for the Simple Network
    # Protocol and TLS layers. It must match the cargo-make build
    # (pxe/Makefile.toml, ipxe-build-efi-aarch64) — without it the binaries
    # differ from what ships today and SNP/TLS failures during PXE boot
    # become undiagnosable in the field.
    make -j$NIX_BUILD_CORES \
      ECHO_E_BIN_ECHO=echo \
      ECHO_E_BIN_ECHO_E=echo \
      CROSS=${crossStdenv.cc.targetPrefix} \
      HOST_CC=${pkgs.gcc13}/bin/gcc \
      EMBED=${embedScript} \
      DEBUG=snp,tls \
      bin-arm64-efi/snponly.efi \
      bin-arm64-efi/golan.efi \
      VERSION=${pkgs.lib.escapeShellArg bannerVersion}

    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall

    # Layout matches cargo-make output. As on x86, the shipped ipxe.efi is
    # built from the snponly target — the SNP-only driver set, which is what
    # ipxe-install-efi-aarch64 renames into place — not iPXE's own ipxe.efi.
    #   pxe/static/blobs/internal/aarch64/ipxe.efi
    #   pxe/static/blobs/internal/aarch64/golan.efi
    mkdir -p $out/blobs/aarch64
    install -m 644 bin-arm64-efi/snponly.efi $out/blobs/aarch64/ipxe.efi
    install -m 644 bin-arm64-efi/golan.efi $out/blobs/aarch64/golan.efi

    runHook postInstall
  '';

  # EFI binaries don't need fixup hooks — they're standalone bootloaders
  # with no RPATHs or ELF interpreter.
  dontFixup = true;

  meta = {
    description = "iPXE EFI bootloader for aarch64 with carbide patches";
    homepage = "https://ipxe.org/";
    license = pkgs.lib.licenses.gpl2Plus;
    # Cross-compiled, so an x86_64 host builds this too.
    platforms = [
      "x86_64-linux"
      "aarch64-linux"
    ];
  };
}
