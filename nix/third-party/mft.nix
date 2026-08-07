# Mellanox Firmware Tools (MFT), prebuilt, for x86_64 hosts and aarch64.
#
# The scout discovery image ships the full MFT suite — 57 binaries including
# flint, mst, mlxconfig, mlxlink, mlxfwreset and mlxcables. nixpkgs' `mstflint`
# is the open-source subset and provides only a handful of those, so a scout
# built on mstflint alone loses NIC firmware management and link diagnostics
# with nothing more informative than "command not found".
#
# MFT arrives in the mkosi profile as a bare `mft` at the end of the NV_PACKAGES
# list in mkosi.postinst.chroot, which is easy to miss when reading the package
# list in mkosi.conf.
#
# forge-dpu-agent consumes the same tree through crates/libmlx, which looks for
# flint on PATH or at /usr/bin/flint and /opt/mellanox/mft/bin/flint, and for
# mlxfwreset at /opt/mellanox/mft/bin/mlxfwreset (hardcoded in
# libmlx/firmware/reset.rs). mlxfwreset is a shell script driving Python tools,
# so any runtime carrying it also needs Python 3.
#
# Architecture is read from stdenv rather than passed in, so a caller selects it
# by choosing the package set: `pkgs.callPackage` for the host, or the aarch64
# cross set for the DPU. Under cross the tools in nativeBuildInputs splice to
# the build platform on their own, which is why this takes no crossPkgs
# argument the way the aarch64 file it replaces did.
{
  lib,
  stdenv,
  fetchurl,
  dpkg,
  patchelf,
  file,
  # Not `bash`, which is bash-interactive in this nixpkgs: these are wrapper
  # scripts, and the readline/ncurses closure that comes with the interactive
  # build has no business in a boot image.
  bashNonInteractive,
  python3,
}:

let
  version = "4.35.0-159";

  # Three names differ per architecture and none can be derived from another:
  # the tarball says x86_64/aarch64, the deb inside it says amd64/arm64, and
  # glibc's loader is .so.2 on x86 but .so.1 on aarch64.
  sel =
    if stdenv.hostPlatform.isAarch64 then
      {
        tar = "aarch64";
        deb = "arm64";
        ld = "ld-linux-aarch64.so.1";
        hash = "sha256-7bn/4qrBSGdIFs2Tw9iyYO8rSpvg4nHavNFKAwC6diM=";
      }
    else
      {
        tar = "x86_64";
        deb = "amd64";
        ld = "ld-linux-x86-64.so.2";
        hash = "sha256-anwF1gyMSBkRCjVvcsvGaevhjfiiqCefDe2IrEKdrvk=";
      };

  interp = "${stdenv.cc.libc}/lib/${sel.ld}";
  # The MFT binaries link against glibc and libstdc++ only.
  rpath = "${stdenv.cc.libc}/lib:${stdenv.cc.cc.lib}/lib";
in

stdenv.mkDerivation {
  pname = "mft-${sel.tar}";
  inherit version;

  src = fetchurl {
    url = "https://www.mellanox.com/downloads/MFT/mft-${version}-${sel.tar}-deb.tgz";
    inherit (sel) hash;
  };

  nativeBuildInputs = [
    dpkg
    patchelf
    file
  ];

  # Named as a host input so patchShebangs below resolves the bash that will
  # run these wrappers on the target, not the one running the build.
  buildInputs = [ bashNonInteractive ];

  # mlxfwreset is a shell script that locates a python interpreter at run time
  # (`which python3`, and a find over /usr/bin) and drives the .py files under
  # lib64/mft/python_tools, whose shebangs are `#!/usr/bin/env python`.
  # Propagated rather than left to each caller: every runtime that carries MFT
  # needs it, and the failure is a "command not found" from inside a firmware
  # reset rather than anything the build would catch.
  propagatedBuildInputs = [ python3 ];

  unpackPhase = ''
    tar xzf $src
    dpkg-deb -x mft-${version}-${sel.tar}-deb/DEBS/mft_${version}_${sel.deb}.deb extracted
  '';

  installPhase = ''
    # Several MFT entry points are shell or Python wrappers that locate their
    # real ELF alongside themselves — flint calls flint_ext, mlxfwreset calls
    # into usr/lib64/mft. Copy the whole tree rather than cherry-picking, or
    # the wrappers resolve to nothing.
    mkdir -p $out/usr/bin $out/usr/lib64/mft
    cp -r extracted/usr/bin/. $out/usr/bin/
    cp -r extracted/usr/lib64/mft/. $out/usr/lib64/mft/

    # Tools that hardcode /opt/mellanox/mft/bin find their companions here.
    # Store-relative rather than /usr/bin: an absolute target resolves against
    # whatever root the link is read from, so in the store — or anywhere the
    # image root is not in play — it escapes the package and lands on the
    # host's /usr/bin.
    mkdir -p $out/opt/mellanox/mft
    ln -sf ../../../usr/bin $out/opt/mellanox/mft/bin

    # Patch ELF executables: interpreter + RPATH. Shared objects get RPATH
    # only — setting an interpreter on a .so is meaningless and patchelf will
    # refuse. Non-ELF files (the wrapper scripts, Python, static archives) are
    # skipped by the file(1) check; a patchelf failure on something that *is*
    # ELF is a real error and should not be swallowed.
    find $out -type f | while IFS= read -r f; do
      type=$(file -b "$f") || continue
      case "$type" in
        *"ELF"*"executable"*)
          patchelf --set-interpreter "${interp}" --set-rpath "${rpath}" "$f"
          ;;
        *"ELF"*"shared object"*)
          patchelf --set-rpath "${rpath}" "$f"
          ;;
      esac
    done

    # MFT's wrappers ship with `#!/bin/bash`, which exists on Ubuntu but not on
    # NixOS, where /bin holds only sh. The default fixupPhase would rewrite
    # these, but it resolves nothing under cross and leaves /bin/bash in place,
    # so do it explicitly against the host bash.
    #
    # Getting this wrong is quiet rather than loud. Before this was explicit,
    # the aarch64 build ran natively on x86 and patchShebangs baked an *x86_64*
    # bash into flint — a wrapper that cannot exec at all on a DPU, and which
    # nothing catches until someone queries NIC firmware.
    patchShebangs --host $out/usr/bin $out/usr/lib64/mft

    # The suite is meant to arrive whole. Spot-check the tools carbide reaches
    # for, so a tarball that reorganises fails here rather than at discovery.
    for bin in flint flint_ext mst mlxconfig mlxlink mlxfwreset; do
      if [ ! -e "$out/usr/bin/$bin" ]; then
        echo "ERROR: $bin missing from the MFT tarball — layout has changed."
        exit 1
      fi
    done
  '';

  meta = {
    description = "Mellanox Firmware Tools";
    homepage = "https://network.nvidia.com/products/adapter-software/firmware-tools/";
    license = lib.licenses.unfree;
    platforms = [
      "x86_64-linux"
      "aarch64-linux"
    ];
  };
}
