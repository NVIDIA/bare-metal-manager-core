# Custom OpenTelemetry Collector for aarch64 DPUs.
#
# The repository owns the collector composition and three custom components,
# while OCB supplies the generated main package.  Keep the canonical builder
# template and version files as the single source of truth: the Nix build only
# renders that template, then replaces OCB's incomplete module files with the
# committed, reproducible module graph under bluefield/otel/ocb-generated.
{
  pkgs,
  crossPkgs,
}:

let
  lib = pkgs.lib;
  elfArchitecture = import ../checks/elf-architecture.nix { inherit pkgs; };
  otelDir = ../../bluefield/otel;

  otelcolVersion = lib.trim (builtins.readFile (otelDir + "/otelcol_version.txt"));

  # Each in-tree component publishes its module version beside its Go source.
  # Reading those constants here prevents the OCB config from drifting from
  # the modules it actually compiles.
  readComponentVersion =
    component:
    let
      prefix = ''const Version = "'';
      versionLines = builtins.filter (lib.hasPrefix prefix) (
        lib.splitString "\n" (builtins.readFile (component + "/version.go"))
      );
    in
    assert lib.assertMsg (builtins.length versionLines == 1) ''
      Expected exactly one `const Version` declaration in ${toString component}/version.go.
    '';
    lib.removeSuffix ''"'' (lib.removePrefix prefix (builtins.head versionLines));

  fileresourceprocessor = otelDir + "/fileresourceprocessor";
  telemetrystatsprocessor = otelDir + "/telemetrystatsprocessor";
  puntstatsreceiver = otelDir + "/puntstatsreceiver";

  substitutions = {
    VERSION = otelcolVersion;
    FILERESOURCE_VERSION = readComponentVersion fileresourceprocessor;
    TELEMETRYSTATS_VERSION = readComponentVersion telemetrystatsprocessor;
    PUNTSTATS_VERSION = readComponentVersion puntstatsreceiver;
  };

  # The flake's nixpkgs revision predates the collector pin by a few releases.
  # Pin OCB independently so generated code is never produced by a mismatched
  # builder while retaining the repository's locked package set everywhere
  # else.
  ocbBuilder = pkgs.buildGo126Module rec {
    pname = "ocb";
    version = otelcolVersion;

    src = pkgs.fetchFromGitHub {
      owner = "open-telemetry";
      repo = "opentelemetry-collector";
      rev = "cmd/builder/v${version}";
      hash = "sha256-EG//ddcXolvILucKYWZSoeqgFCE7u3/h8v/oX3pzafk=";
    };
    sourceRoot = "source/cmd/builder";
    vendorHash = "sha256-SeLEg/xwSEr3uPZbjlLFny+OpfovcmKVD6BxCgoosz8=";
    # Two init-command tests invoke `go mod tidy` against the public proxy,
    # which is intentionally disabled in a pure Nix build. The generated
    # collector is verified below against the committed module graph.
    doCheck = false;
    ldflags = [
      "-s"
      "-w"
      "-X go.opentelemetry.io/collector/cmd/builder/internal.version=${version}"
    ];
    postInstall = ''
      mv "$out/bin/builder" "$out/bin/ocb"
    '';
    meta = {
      description = "OpenTelemetry Collector distribution builder";
      homepage = "https://github.com/open-telemetry/opentelemetry-collector/tree/main/cmd/builder";
      license = lib.licenses.asl20;
      mainProgram = "ocb";
    };
  };

  ocbConfig = pkgs.writeText "otelcol-contrib-ocb-config.yaml" (
    builtins.replaceStrings
      [
        "\${VERSION}"
        "\${FILERESOURCE_VERSION}"
        "\${TELEMETRYSTATS_VERSION}"
        "\${PUNTSTATS_VERSION}"
      ]
      [
        substitutions.VERSION
        substitutions.FILERESOURCE_VERSION
        substitutions.TELEMETRYSTATS_VERSION
        substitutions.PUNTSTATS_VERSION
      ]
      (builtins.readFile (otelDir + "/otelcol_builder_config_yaml.txt"))
  );

  # Generate only the small distribution-specific main package.  Language
  # dependencies remain governed by the committed go.mod/go.sum and the
  # buildGoModule vendor hash; they are intentionally outside the container's
  # primary-workload source archive.
  ocbSource =
    pkgs.runCommand "otelcol-contrib-source-${otelcolVersion}"
      {
        nativeBuildInputs = [ ocbBuilder ];
      }
      ''
        mkdir -p "$out"

        cp -r ${fileresourceprocessor} "$out/fileresourceprocessor"
        cp -r ${telemetrystatsprocessor} "$out/telemetrystatsprocessor"
        cp -r ${puntstatsreceiver} "$out/puntstatsreceiver"
        cp ${../../LICENSE} "$out/LICENSE"

        cd "$out"
        ocb \
          --config ${ocbConfig} \
          --skip-compilation \
          --skip-get-modules

        # OCB deliberately skips module resolution above.  The checked-in files
        # are the reviewed module graph used by the Docker and cargo-make builds.
        cp -f ${otelDir}/ocb-generated/go.mod ocb-build/go.mod
        cp -f ${otelDir}/ocb-generated/go.sum ocb-build/go.sum
      '';

  # These repository-owned scripts are part of the NICo integration rather
  # than third-party runtime content, so service wiring adds them as first-
  # party files while the collector source is handled separately below.
  wrapperScripts = pkgs.runCommand "otelcol-contrib-wrapper-scripts" { } ''
    install -Dm755 ${otelDir}/otelcol-wrapper \
      "$out/etc/otelcol-contrib/otelcol-wrapper"
    install -Dm755 ${otelDir}/otelcol-wrapper-imports-dpf \
      "$out/etc/otelcol-contrib/otelcol-wrapper-imports"
    install -Dm755 ${otelDir}/otelcol-wrapper-validate \
      "$out/etc/otelcol-contrib/otelcol-wrapper-validate"
    mkdir -p \
      "$out/etc/otelcol-contrib/config-fragments" \
      "$out/run/otelcol-contrib" \
      "$out/var/lib/otelcol-contrib/cursors"
  '';
in
assert lib.assertMsg
  (lib.versions.majorMinor crossPkgs.go_1_26.version == "1.26" && crossPkgs.go_1_26.GOARCH == "arm64")
  ''
    otelcol-contrib requires the aarch64 Go 1.26 package set.
  '';
crossPkgs.buildGo126Module {
  pname = "otelcol-contrib";
  version = otelcolVersion;

  src = ocbSource;
  modRoot = "ocb-build";
  vendorHash = "sha256-MFvpifJFf7rOahJYFJONKgiSEMuTcawu7jaqFgT0YG8=";

  # The supported build path uses a static Go binary.  Go's arm64 internal
  # linker emits 64 KiB-aligned PT_LOAD segments; the install check below
  # enforces Issue #334's 4K/64K host compatibility contract.
  env.CGO_ENABLED = "0";
  ldflags = [ "-linkmode internal" ];

  # Cross-built Go tests cannot run on the build host.  The component modules
  # retain their normal native test suites; this derivation verifies the final
  # ELF architecture and loader contract instead.
  doCheck = false;

  postInstall = ''
    mkdir -p "$out/usr/bin"
    mv "$out/bin/otelcol-contrib" "$out/usr/bin/otelcol-contrib"
    rmdir "$out/bin"
    install -Dm644 ${../../LICENSE} "$out/usr/share/licenses/otelcol-contrib/LICENSE"
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
    description = "Custom OpenTelemetry Collector distribution for NICo DPUs";
    homepage = "https://opentelemetry.io/docs/collector/";
    license = lib.licenses.asl20;
    mainProgram = "otelcol-contrib";
    platforms = [ "aarch64-linux" ];
  };

  passthru = {
    inherit wrapperScripts;
    # The generated distribution source is the corresponding source for this
    # separately added OSS workload.  Go dependency inventories are excluded
    # by policy and remain represented only by the module graph/vendor hash.
    ossSource = ocbSource;
    targetOciArch = "arm64";
  };
}
