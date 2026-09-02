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
# Carbide consumers reach the same tree through crates/libmlx, which looks for
# flint on PATH or at /usr/bin/flint and /opt/mellanox/mft/bin/flint, and for
# mlxfwreset at /opt/mellanox/mft/bin/mlxfwreset. mlxfwreset is a shell script
# driving Python tools; it is patched to the Nix Python store path below so a
# container does not depend on a distro-style `/usr/bin/env python3`.
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

  unpackPhase = ''
    tar xzf $src
    dpkg-deb -x mft-${version}-${sel.tar}-deb/DEBS/mft_${version}_${sel.deb}.deb extracted
  '';

  installPhase = ''
    # Several MFT entry points are shell or Python wrappers that locate their
    # real ELF alongside themselves — flint calls flint_ext, mlxfwreset calls
    # into usr/lib64/mft. Copy the whole tree rather than cherry-picking, or
    # the wrappers resolve to nothing.
    mkdir -p \
      $out/etc/mft \
      $out/usr/bin \
      $out/usr/lib64/mft \
      $out/usr/share/mft
    cp -r extracted/etc/mft/. $out/etc/mft/
    cp -r extracted/usr/bin/. $out/usr/bin/
    cp -r extracted/usr/lib64/mft/. $out/usr/lib64/mft/
    cp -r extracted/usr/share/mft/. $out/usr/share/mft/

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
    find $out/usr/bin $out/usr/lib64/mft -type f | while IFS= read -r f; do
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

    # The vendor wrappers search conventional distro locations and ultimately
    # assign `/usr/bin/env python3`. buildEnv does not link propagated inputs,
    # so that approach fails in a Nix-created root. Patch every launcher that
    # has the shared assignment: Scout calls mlxfwreset and the DPU agent calls
    # mlxprivhost, while other MFT entry points use the same wrapper pattern.
    # Replace both discovery and its conventional-path fallbacks. Some
    # launchers do not share the later SCRIPT_PATH block, so patching that
    # marker would leave tools such as `mst` broken. Literal store references
    # retain Python in the resulting image closure.
    python_wrappers=$(grep -rlF "PYTHON_EXEC='/usr/bin/env python3'" "$out/usr/bin")
    if [ -z "$python_wrappers" ]; then
      echo "ERROR: no MFT Python wrappers found — launcher layout has changed."
      exit 1
    fi
    while IFS= read -r wrapper; do
      substituteInPlace "$wrapper" \
        --replace-fail "PYTHON_EXEC=\`find /usr/bin /bin/ /usr/local/bin -iname 'python*' 2>&1 | grep -e='*python[0-9,.]*' | sort -d | head -n 1\`" \
        "PYTHON_EXEC='${python3}/bin/python3'" \
        --replace-fail "PYTHON_EXEC='/usr/bin/env python3'" \
        "PYTHON_EXEC='${python3}/bin/python3'"
      sed -i \
        "s|PYTHON_EXEC='/usr/bin/env python2'|PYTHON_EXEC='${python3}/bin/python3'|g" \
        "$wrapper"
      if grep -qF 'PYTHON_EXEC=`find ' "$wrapper"; then
        echo "ERROR: unpatched Python discovery remains in $wrapper"
        exit 1
      fi
      if grep -qF "PYTHON_EXEC='/usr/bin/env python" "$wrapper"; then
        echo "ERROR: conventional Python path remains in $wrapper"
        exit 1
      fi
    done <<< "$python_wrappers"
    for wrapper in mlxfwreset mlxprivhost; do
      grep -F "PYTHON_EXEC='${python3}/bin/python3'" "$out/usr/bin/$wrapper"
    done

    # The suite is meant to arrive whole. Spot-check the tools carbide reaches
    # for, so a tarball that reorganises fails here rather than at discovery.
    for bin in flint flint_ext mst mlxconfig mlxlink mlxfwreset; do
      if [ ! -e "$out/usr/bin/$bin" ]; then
        echo "ERROR: $bin missing from the MFT tarball — layout has changed."
        exit 1
      fi
    done
    if [ ! -s "$out/etc/mft/mft.conf" ]; then
      echo "ERROR: MFT configuration is missing — mlxfwreset cannot start."
      exit 1
    fi
    if [ -z "$(find "$out/usr/share/mft" -mindepth 1 -print -quit)" ]; then
      echo "ERROR: MFT hardware data is missing — device lookup cannot work."
      exit 1
    fi
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
