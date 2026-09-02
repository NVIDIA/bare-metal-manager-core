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
  elfArchitecture = import ../checks/elf-architecture.nix { inherit pkgs; };
  version = pkgs.lib.trim (builtins.readFile ../../bluefield/transceiver_exporter/version.txt);
  binaryUrl = builtins.replaceStrings [ "\${VERSION}" ] [ version ] (
    pkgs.lib.trim (builtins.readFile ../../bluefield/transceiver_exporter/url.txt)
  );
  binaryArchive = pkgs.fetchurl {
    name = "transceiver-exporter-${version}-linux-arm64.tar.gz";
    url = binaryUrl;
    hash = "sha256-uDlML2+DgCnJD7c5BrZf4RAxs26mW3BDhHCW6XrA7RE=";
  };
  sourceArchive = pkgs.fetchurl {
    name = "transceiver-exporter-${version}-source.tar.gz";
    url = "https://github.com/wobcom/transceiver-exporter/archive/refs/tags/v${version}.tar.gz";
    hash = "sha256-CI8v9siZEVaXeI51ZSQZ179UtVYcu+rJk99ldmlIIv0=";
  };
in
assert pkgs.lib.assertMsg (crossPkgs.go.GOARCH == "arm64") ''
  transceiver-exporter requires an aarch64 package set.
'';
crossPkgs.stdenv.mkDerivation {
  pname = "transceiver-exporter";
  inherit version;

  src = binaryArchive;

  unpackPhase = ''
    mkdir extract
    tar xzf $src -C extract
  '';

  installPhase = ''
    mkdir -p $out/usr/bin $out/usr/share/licenses/transceiver-exporter

    install -m755 extract/transceiver-exporter $out/usr/bin/transceiver-exporter
    install -m644 extract/LICENSE.md $out/usr/share/licenses/transceiver-exporter/LICENSE.md

  '';

  doInstallCheck = true;
  nativeInstallCheckInputs = [
    pkgs.bash
    pkgs.binutils
  ];
  installCheckPhase = ''
    runHook preInstallCheck
    ${elfArchitecture}/bin/check-elf-architecture arm64 "$out"
    ${pkgs.bash}/bin/bash ${../../scripts/check-aarch64-pagesize.sh} "$out"
    runHook postInstallCheck
  '';

  meta = {
    description = "Prometheus exporter for optical transceiver diagnostics";
    homepage = "https://github.com/wobcom/transceiver-exporter";
    license = pkgs.lib.licenses.gpl3Only;
    mainProgram = "transceiver-exporter";
    platforms = [ "aarch64-linux" ];
  };

  passthru = {
    # The release artifact contains only the binary and license.  Ship the
    # matching tagged source archive in the container's OSS source directory.
    ossSource = sourceArchive;
    targetOciArch = "arm64";
  };
}
