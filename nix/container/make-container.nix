{
  pkgs,
  nix2containerLib,
  containerCopyHelpers,
  # Default image tag — typically the git revision of the workspace.
  version,
  mkOssSources,
}:

# Build an OCI container image from a set of Nix packages.
#
# Two-phase build:
#   Phase 1 — assemble the container root (binaries + runtime + OSS sources +
#              attribution notices).
#   Phase 2 — bake the assembled root into the final OCI image.
#
# OSRB compliance is handled by two artifacts baked into the image:
#   /usr/share/oss-sources/   — OSS source tarballs (via mkOssSources)
#   /usr/share/carbide/attributions.txt — notices file listing package name,
#                                         license, and homepage for all OSS in
#                                         `runtime` and `packages`.
#
# Everything below that varies by service — runtime, extraCommands, entrypoint,
# cmd, optCarbide* — is declared once per service in nix/services/default.nix.
{
  name,
  packages,
  runtime ? [ ],
  tag ? version,
  # Required, not defaulted: the obvious default (pkgs.go.GOARCH) reads from
  # the package set this file was imported with, which is always the native
  # one — so a cross-built arm64 image would silently be labelled amd64.
  arch,
  extraContents ? [ ],
  extraCommands ? "",
  meta ? { },
  # OCI Entrypoint and Cmd. Both are optional; when omitted the image has no
  # default entry point and the k8s PodSpec `command:`/`args:` fields drive
  # execution. Set Entrypoint for containers that run standalone (DPU images,
  # sidecar containers) where the image itself must declare what to run.
  entrypoint ? null,
  cmd ? null,
  # Legacy /opt/carbide/ compatibility for PodSpecs not yet updated to /bin.
  #
  # optCarbideAliases — list of { alias, target } attrsets. Creates a symlink
  # /opt/carbide/<alias> → /bin/<target> for each entry. Use when a binary was
  # renamed and the PodSpec still references the old name.
  #   [ { alias = "forge-admin-cli"; target = "nico-admin-cli"; } ]
  #
  # optCarbideDirs — list of paths to mkdir -p under /opt/carbide/. Use for
  # directories the service expects to exist at startup (mount points, etc.).
  #   [ "pxe/templates" "migrations" "static" ]
  optCarbideAliases ? [ ],
  optCarbideDirs ? [ ],
}:
let
  ossSources = mkOssSources name runtime;

  extraCommandsPath = pkgs.lib.optional (extraCommands != "") (
    pkgs.runCommand "${name}-container-extra-root" { } ''
      mkdir -p "$out"
      cd "$out"
      ${extraCommands}
    ''
  );

  # Backward-compat layer for /opt/carbide/:
  #   1. Symlink every /bin/* binary so PodSpecs referencing /opt/carbide/<name> work.
  #   2. Create legacy name aliases for renamed binaries.
  #   3. Create directory stubs expected at runtime (mount points, path checks).
  optCarbideCompat = pkgs.runCommand "${name}-opt-carbide-compat" { } ''
    mkdir -p $out/opt/carbide

    ${pkgs.lib.concatMapStrings (pkg: ''
      if [ -d "${pkg}/bin" ]; then
        for bin in "${pkg}"/bin/*; do
          bname=$(basename "$bin")
          ln -sf "/bin/$bname" "$out/opt/carbide/$bname"
        done
      fi
    '') packages}

    ${pkgs.lib.concatMapStrings ({ alias, target }: ''
      ln -sf "/bin/${target}" "$out/opt/carbide/${alias}"
    '') optCarbideAliases}

    ${pkgs.lib.concatMapStrings (dir: ''
      mkdir -p "$out/opt/carbide/${dir}"
    '') optCarbideDirs}
  '';

  # OSRB attribution notices file.
  # Lists every package from `packages`, `runtime`, and `extraContents` that
  # carries nixpkgs license metadata, satisfying the binary-release notices
  # requirement. Source tarballs are in /usr/share/oss-sources/ via ossSources.
  attributionText =
    let
      allPkgs = packages ++ runtime ++ extraContents;
      pkgsWithLicense = builtins.filter (p: p ? meta && p.meta ? license) allPkgs;
    in
    pkgs.runCommand "${name}-attribution" { } ''
      mkdir -p $out/usr/share/carbide
      {
        printf "Third Party Notices — %s\n" "${name}"
        printf "Source code is available in /usr/share/oss-sources/\n"
        printf "\n"
        ${pkgs.lib.concatMapStrings (
          p:
          let
            lics =
              if builtins.isList p.meta.license then p.meta.license else [ p.meta.license ];
            pname_ = p.pname or p.name or "unknown";
            ver = p.version or "";
          in
          pkgs.lib.concatMapStrings (
            lic:
            let
              # nixpkgs allows meta.license to be a plain SPDX string as well as
              # a licence attrset. Attribute access on a string does not throw —
              # `or` yields the fallback — so an unhandled string would silently
              # print "Unknown" in a file whose purpose is to name the licence.
              licName =
                if builtins.isString lic then lic else lic.fullName or lic.spdxId or "Unknown";
            in
            ''
              printf "%s\n" "${pname_}${pkgs.lib.optionalString (ver != "") " ${ver}"}"
              printf "  License: %s\n" "${licName}"
              ${pkgs.lib.optionalString (lic ? url && builtins.isString lic.url) ''
                printf "  License URL: %s\n" "${lic.url}"
              ''}
              ${pkgs.lib.optionalString (p.meta ? homepage && builtins.isString p.meta.homepage) ''
                printf "  Homepage: %s\n" "${p.meta.homepage}"
              ''}
              printf "\n"
            ''
          ) lics
        ) pkgsWithLicense}
      } > $out/usr/share/carbide/attributions.txt
    '';

  # buildEnv links only these, so a directory an extraCommands script creates
  # outside the list is silently dropped from the image. /tmp is here because
  # services declare working directories under it (machine-a-tron).
  pathsToLink = [
    "/bin"
    "/sbin"
    "/etc"
    "/lib"
    "/lib64"
    "/opt"
    "/share"
    "/tmp"
    "/usr"
    "/var"
  ];

  imageConfig =
    {
      Env = [
        "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
        "PATH=/bin:/usr/bin"
      ];
    }
    // pkgs.lib.optionalAttrs (entrypoint != null) { Entrypoint = entrypoint; }
    // pkgs.lib.optionalAttrs (cmd != null) { Cmd = cmd; };

  # Phase 1: assemble the full container root.
  root = pkgs.buildEnv {
    name = "${name}-container-root";
    paths =
      packages
      ++ runtime
      ++ [ pkgs.cacert ossSources optCarbideCompat attributionText ]
      ++ extraContents
      ++ extraCommandsPath;
    inherit pathsToLink;
  };

  # Phase 2: bake into an OCI image.
  # maxLayers = 100 gives nix2container room to split the closure into
  # fine-grained layers for better registry cache reuse.
  rawImage = nix2containerLib.buildImage {
    inherit name tag arch;
    maxLayers = 100;
    copyToRoot = root;
    config = imageConfig;
  };

  image = rawImage.overrideAttrs (old: {
    inherit meta;
    passthru =
      builtins.removeAttrs (old.passthru or { }) [
        "copyToDockerDaemon"
        "copyToRegistry"
        "copyToPodman"
        "copyTo"
      ]
      // {
        copyToDockerDaemon = containerCopyHelpers.copyToDockerDaemon rawImage;
        copyToRegistry = containerCopyHelpers.copyToRegistry rawImage;
        copyTo = containerCopyHelpers.copyTo rawImage;
      };
  });
in
image
