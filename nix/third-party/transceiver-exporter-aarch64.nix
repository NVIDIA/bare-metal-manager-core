# Pre-built wobcom transceiver-exporter for aarch64 DPUs.
#
# Prometheus exporter for optical transceiver (SFP/QSFP) metrics, scraped by
# the prometheus/transceiver receiver in the nico-otelcol collector.
#
# `version` is read from bluefield/transceiver_exporter/version.txt so the two
# cannot drift. URL template from bluefield/transceiver_exporter/url.txt.
#
# Hash update (TOFU workflow), after changing `version`:
#   1. Replace the `hash` below with pkgs.lib.fakeHash.
#   2. Build anything that pulls this in — the fetch fails with a
#      "hash mismatch" error reporting the real value.
#   3. Paste the "got:" value back into `hash`.
{ pkgs, crossPkgs }:

let
  version = pkgs.lib.trim (
    builtins.readFile ../../bluefield/transceiver_exporter/version.txt
  );
in
pkgs.stdenv.mkDerivation {
  pname = "transceiver-exporter-aarch64";
  inherit version;

  src = pkgs.fetchurl {
    url = "https://github.com/wobcom/transceiver-exporter/releases/download/v${version}/transceiver-exporter-v${version}-linux-arm64.tar.gz";
    hash = "sha256-uDlML2+DgCnJD7c5BrZf4RAxs26mW3BDhHCW6XrA7RE=";
  };

  nativeBuildInputs = [ pkgs.patchelf ];

  unpackPhase = ''
    mkdir extract
    tar xzf $src -C extract
  '';

  installPhase = ''
    mkdir -p $out/usr/bin $out/usr/share/licenses/transceiver-exporter

    install -m755 extract/transceiver-exporter $out/usr/bin/transceiver-exporter
    install -m644 extract/LICENSE.md $out/usr/share/licenses/transceiver-exporter/LICENSE.md

    # Patch ELF interpreter and RPATH in case the binary uses CGO (links glibc).
    # This is a no-op for fully-static Go binaries (patchelf exits cleanly).
    interp="${crossPkgs.stdenv.cc.libc}/lib/ld-linux-aarch64.so.1"
    rpath="${crossPkgs.stdenv.cc.libc}/lib:${crossPkgs.stdenv.cc.cc.lib}/lib"
    patchelf --set-interpreter "$interp" --set-rpath "$rpath" \
      $out/usr/bin/transceiver-exporter || true
  '';
}
