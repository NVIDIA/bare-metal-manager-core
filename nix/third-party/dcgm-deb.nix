# NVIDIA Data Center GPU Manager, from NVIDIA's published Debian packages.
#
# scout runs DCGM diagnostics on GPU nodes, so the plugin set has to match the
# CUDA version those diagnostics were qualified against — cuda13. nixpkgs
# builds DCGM from source and pins a release whose CMake only knows about CUDA
# 12; building it ourselves means carrying a rebased fix-paths patch and
# redoing that work on every DCGM release until nixpkgs bumps. Taking NVIDIA's
# binaries instead gives the exact artifacts carbide has qualified and leaves
# the maintenance at "bump a hash".
#
# The three packages mirror what the mkosi scout profiles installed:
#
#   core                 the daemon (nv-hostengine) and dcgmi
#   cuda13               diagnostic plugins built against CUDA 13
#   proprietary-cuda13   closed-source plugins the open set does not cover
#
# Their versions must match exactly — the -cuda13 package declares
# `Depends: datacenter-gpu-manager-4-core (= <same version>)`, and mixing
# versions across the plugin boundary is not something DCGM checks at runtime.
#
# Both architectures are deliberately held to one version. A scout that reports
# different diagnostic results depending on which CPU the host has is not
# something anyone can support in the field.
#
# Hashes come straight from the repository index rather than from a build
# failure. Note that the index reports an epoch (`1:4.6.1-1`) that the filename
# does not carry, so read `Filename:` rather than composing a URL from
# `Version:`. The index publishes hex, so convert rather than transcribe:
#
#   curl -sSL https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2404/<repo>/Packages.gz \
#     | gunzip | grep -A12 '^Package: datacenter-gpu-manager-4-cuda13$'
#   nix hash convert --hash-algo sha256 --to sri <hex>
{
  lib,
  stdenv,
  fetchurl,
  dpkg,
  patchelf,
  file,
  autoPatchelfHook,
  jsoncpp,
  libevent,
  numactl,
  version ? "4.6.1-1",
}:

let
  # NVIDIA calls the aarch64 server repository "sbsa" while the deb inside it
  # is still tagged arm64. Neither name can be derived from the other, so both
  # are spelled out.
  repoArch = if stdenv.hostPlatform.isAarch64 then "sbsa" else "x86_64";
  debArch = if stdenv.hostPlatform.isAarch64 then "arm64" else "amd64";

  baseUrl = "https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2404/${repoArch}";

  # Keyed by repository rather than by package, because a version bump moves
  # all six together and splitting them by package makes a half-applied bump
  # look plausible.
  hashes = {
    x86_64 = {
      core = "sha256-JGfxXvg98/zIM0p9D/uM+wozFO6t0huNRjrf3b9NR6A=";
      cuda13 = "sha256-lUfz0rgmF9i37JNPGmdQS5jatzEULntq+MaEoDmsu94=";
      proprietary = "sha256-qu8f4ptIFEyaDu5/9/VKbuJ7BsV22+91fEjhamvlKg0=";
    };
    sbsa = {
      core = "sha256-o5BSTcctw9zenmlFir18S/XSNhGZTD7bzEs3bsHzYoY=";
      cuda13 = "sha256-YowMDWhYQJtJ6Pd9SSR6iMYqu7ggkirF25fqydORcMs=";
      proprietary = "sha256-hc75jyinDAMpUl2XYVgtczyge+4aJmQ6IwCtfIoWx9U=";
    };
  };

  fetchDeb =
    pkgName: attr:
    fetchurl {
      url = "${baseUrl}/${pkgName}_${version}_${debArch}.deb";
      hash = hashes.${repoArch}.${attr};
    };

  debs = {
    core = fetchDeb "datacenter-gpu-manager-4-core" "core";
    cuda13 = fetchDeb "datacenter-gpu-manager-4-cuda13" "cuda13";
    proprietary = fetchDeb "datacenter-gpu-manager-4-proprietary-cuda13" "proprietary";
  };
in

stdenv.mkDerivation {
  pname = "dcgm";
  version = lib.removeSuffix "-1" version;

  # Three .debs rather than one source, so they are unpacked by hand in
  # installPhase below; $srcs carries the list.
  srcs = builtins.attrValues debs;
  dontUnpack = true;

  nativeBuildInputs = [
    dpkg
    patchelf
    file
    autoPatchelfHook
  ];

  # autoPatchelfHook resolves DT_NEEDED against these. The Depends field only
  # names libc6 and lshw, but the binaries pull in rather more than dpkg
  # tracks — jsoncpp and libevent are DCGM's own dependencies, and the plugins
  # want libnuma (Recommends, not Depends, so easy to miss).
  buildInputs = [
    stdenv.cc.cc.lib # libstdc++
    jsoncpp
    libevent
    numactl
  ];

  # libcuda.so.1 and libnvidia-ml.so.1 come from the driver at runtime, not
  # from a package here. On NixOS they live in /run/opengl-driver/lib, which
  # is why that path leads the plugins' runpath.
  autoPatchelfIgnoreMissingDeps = [
    "libcuda.so.1"
    "libnvidia-ml.so.1"
  ];

  installPhase = ''
    runHook preInstall

    for deb in $srcs; do
      dpkg-deb -x "$deb" unpacked
    done

    mkdir -p $out
    cp -r unpacked/usr/. $out/

    # The packages install under /usr/libexec and expect to find each other by
    # relative path from the nv-hostengine binary, so the layout is preserved
    # rather than flattened into bin/ and lib/.
    runHook postInstall
  '';

  # A missing plugin does not fail a diagnostic — DCGM reports the test as
  # skipped, which reads as a pass in aggregate. The mkosi postinst checked for
  # these by path for that reason; the same check belongs here, where it fails
  # the build instead of silently under-reporting a GPU node.
  postInstall = ''
    for f in \
      $out/bin/dcgmi \
      $out/bin/nv-hostengine \
      $out/libexec/datacenter-gpu-manager-4/nvvs \
      $out/libexec/datacenter-gpu-manager-4/plugins/cuda13/BwChecker_13
    do
      if [ ! -e "$f" ]; then
        echo "ERROR: expected $f in the DCGM packages — layout has changed."
        exit 1
      fi
    done
  '';

  meta = {
    description = "NVIDIA Data Center GPU Manager (CUDA 13 plugins), from NVIDIA's Debian packages";
    homepage = "https://developer.nvidia.com/dcgm";
    license = lib.licenses.unfree;
    platforms = [
      "x86_64-linux"
      "aarch64-linux"
    ];
  };
}
