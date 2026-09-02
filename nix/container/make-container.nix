{
  pkgs,
  nix2containerLib,
  containerCopyHelpers,
  # Default image tag — typically the git revision of the workspace.
  version,
  # Reproducible source metadata shared by every generated image.
  revision,
  created,
  mkOssSources,
}:

# Build an OCI container image from a set of Nix packages.
#
# Two-phase, base-image-free build:
#   Phase 1 — assemble the container root (binaries + runtime + OSS sources +
#              attribution notices).
#   Phase 2 — bake the assembled root into the final OCI image.
#
# OSRB compliance is handled by two artifacts baked into the image:
#   /usr/share/oss-sources/   — OSS source tarballs (via mkOssSources)
#   /usr/share/carbide/attributions.txt — notices file listing package name,
#                                         license, and homepage for separately
#                                         added open-source runtime content.
#
# Everything below that varies by service — runtime, extraCommands, entrypoint,
# cmd, optCarbide* — is declared once per service in nix/services/default.nix.
{
  name,
  # Human-facing OCI title. Defaults to the Nix service name; callers whose
  # public image repository has a different name set it explicitly.
  ociTitle ? name,
  packages,
  # Repository-owned files that form the payload of a data-only image. They
  # are copied into the root but deliberately excluded from OSS source policy.
  firstPartyContents ? [ ],
  # Third-party workload images (for example transceiver-exporter) opt in so
  # their primary package participates in source and attribution generation.
  includePrimarySources ? false,
  # Separately added OSS whose source must ship even though its package output
  # is not linked into the runtime root (for example iPXE bytes carried as
  # externally staged boot artifacts).
  sourcePackages ? [ ],
  runtime ? [ ],
  tag ? version,
  # Required, not defaulted: the obvious default (pkgs.go.GOARCH) reads from
  # the package set this file was imported with, which is always the native
  # one — so a cross-built arm64 image would silently be labelled amd64.
  arch,
  extraCommands ? "",
  meta ? { },
  # OCI Entrypoint and Cmd. Both are optional; when omitted the image has no
  # default entry point and the k8s PodSpec `command:`/`args:` fields drive
  # execution. Set Entrypoint for containers that run standalone (DPU images,
  # sidecar containers) where the image itself must declare what to run.
  entrypoint ? null,
  cmd ? null,
  user ? null,
  workingDir ? null,
  env ? [ ],
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
  # A package can be named both globally and by a service. De-duplicate before
  # generating source archives so one runtime input cannot collide with itself.
  sourceCandidates = pkgs.lib.unique (
    runtime ++ sourcePackages ++ pkgs.lib.optionals includePrimarySources packages ++ [ pkgs.cacert ]
  );

  licensesFor =
    pkg: if builtins.isList pkg.meta.license then pkg.meta.license else [ pkg.meta.license ];
  isOpenSourceLicense = license: builtins.isAttrs license && (license.free or false);
  isOpenSourcePackage =
    pkg: pkg ? meta && pkg.meta ? license && builtins.any isOpenSourceLicense (licensesFor pkg);
  openSourcePackages = builtins.filter isOpenSourcePackage sourceCandidates;

  ossSources = mkOssSources name sourceCandidates;

  packageArchitectures = map (package: package.targetOciArch or null) packages;
  packagesWithoutArchitecture = builtins.filter (target: target == null) packageArchitectures;
  wrongArchitectures = builtins.filter (
    target: target != null && target != arch
  ) packageArchitectures;

  rootPolicy = import ./root-policy.nix { inherit pkgs; };

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

  # The root filesystem is created by Nix rather than inherited from a base
  # image. Supply the small set of conventional files needed by static Go
  # binaries and by services that run as the production `nvs` UID.
  baseFilesystem = pkgs.runCommand "${name}-base-filesystem" { } ''
        mkdir -p "$out/etc" "$out/root" "$out/tmp"
        ${pkgs.lib.optionalString (workingDir != null) ''
          mkdir -p "$out/${pkgs.lib.removePrefix "/" workingDir}"
        ''}
        chmod 1777 "$out/tmp"
        cat > "$out/etc/passwd" <<'EOF'
    root:x:0:0:root:/root:/sbin/nologin
    nvs:x:65534:65534:nvs:/tmp:/sbin/nologin
    EOF
        cat > "$out/etc/group" <<'EOF'
    root:x:0:
    nvs:x:65534:
    EOF
        cat > "$out/etc/nsswitch.conf" <<'EOF'
    hosts: files dns
    networks: files
    passwd: files
    group: files
    EOF
  '';

  # OSRB attribution notices file.
  # Primary applications and embedded language dependencies are intentionally
  # excluded. Source tarballs for the same separately added OSS package set are
  # in /usr/share/oss-sources/ via ossSources.
  attributionText = pkgs.runCommand "${name}-attribution" { } ''
    mkdir -p $out/usr/share/carbide
    {
      printf "Third Party Notices — %s\n" "${name}"
      printf "Source code is available in /usr/share/oss-sources/\n"
      printf "\n"
      ${pkgs.lib.concatMapStrings (
        p:
        let
          lics = builtins.filter isOpenSourceLicense (licensesFor p);
          pname_ = p.pname or p.name or "unknown";
          ver = p.version or "";
        in
        pkgs.lib.concatMapStrings (
          lic:
          let
            licName = lic.fullName or lic.spdxId or "Unknown";
          in
          ''
            printf "%s\n" "${pname_}${pkgs.lib.optionalString (ver != "") " ${ver}"}"
            printf "  License: %s\n" "${licName}"
            ${pkgs.lib.optionalString (builtins.isAttrs lic && lic ? url && builtins.isString lic.url) ''
              printf "  License URL: %s\n" "${lic.url}"
            ''}
            ${pkgs.lib.optionalString (p.meta ? homepage && builtins.isString p.meta.homepage) ''
              printf "  Homepage: %s\n" "${p.meta.homepage}"
            ''}
            printf "\n"
          ''
        ) lics
      ) openSourcePackages}
    } > $out/usr/share/carbide/attributions.txt
  '';

  envKey = entry: builtins.head (pkgs.lib.splitString "=" entry);
  envKeys = map envKey env;
  defaultEnv = [
    "HOME=${if user != null then "/tmp" else "/root"}"
    "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
    "PATH=/bin:/usr/bin"
  ];
  effectiveEnv = builtins.filter (entry: !(builtins.elem (envKey entry) envKeys)) defaultEnv ++ env;

  imageConfig = {
    Labels = {
      "org.opencontainers.image.created" = created;
      "org.opencontainers.image.revision" = revision;
      # These labels describe the canonical source distribution. Keeping them
      # independent from the CI checkout URL makes a clean revision produce
      # byte-identical images in the upstream repository and a fork.
      "org.opencontainers.image.source" = "https://github.com/NVIDIA/infra-controller";
      "org.opencontainers.image.title" = ociTitle;
      "org.opencontainers.image.url" = meta.homepage or "https://github.com/NVIDIA/infra-controller";
      "org.opencontainers.image.version" = tag;
    };
    Env = effectiveEnv;
  }
  // pkgs.lib.optionalAttrs (entrypoint != null) { Entrypoint = entrypoint; }
  // pkgs.lib.optionalAttrs (cmd != null) { Cmd = cmd; }
  // pkgs.lib.optionalAttrs (user != null) {
    User = user;
  }
  // pkgs.lib.optionalAttrs (workingDir != null) { WorkingDir = workingDir; };

  # Phase 1: assemble the full container root.
  root =
    assert rootPolicy.assertShallow;
    assert rootPolicy.assertDisjoint;
    let
      generated = [
        pkgs.cacert
        baseFilesystem
        ossSources
        optCarbideCompat
        attributionText
      ]
      ++ extraCommandsPath;
      classifiedPaths = {
        inherit
          packages
          runtime
          firstPartyContents
          generated
          ;
      };
      paths = packages ++ runtime ++ firstPartyContents ++ generated;
    in
    pkgs.buildEnv {
      name = "${name}-container-root";
      inherit paths;
      inherit (rootPolicy) pathsToLink;
      postBuild = rootPolicy.mkRootInventoryGuard { inherit name classifiedPaths; };
    };

  # Phase 2: bake into an OCI image.
  # maxLayers = 100 gives nix2container room to split the closure into
  # fine-grained layers for better registry cache reuse.
  rawImage = nix2containerLib.buildImage {
    inherit name tag arch;
    maxLayers = 100;
    copyToRoot = root;
    # Nix store canonicalisation makes directories read-only. Override the tar
    # metadata for the conventional scratch directory used by non-root
    # services; this does not mutate the immutable store path itself.
    perms = [
      {
        path = root;
        regex = "/tmp$";
        mode = "1777";
      }
    ];
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
        containerRoot = root;
        inherit firstPartyContents imageConfig;
        # Release checks inspect the exact store outputs referenced by the
        # image. `buildEnv` exposes them as symlinks in containerRoot, which is
        # useful for assembly but unsuitable for `find -type f` validation.
        primaryPackages = packages;
        targetOciArch = arch;
        copyToDockerDaemon = containerCopyHelpers.copyToDockerDaemon rawImage;
        copyToRegistry = containerCopyHelpers.copyToRegistry rawImage;
        copyTo = containerCopyHelpers.copyTo rawImage;
      };
  });
in
assert pkgs.lib.assertMsg (
  packages != [ ] || firstPartyContents != [ ]
) "${name}: a container requires a primary package or first-party contents";
assert pkgs.lib.assertMsg (packagesWithoutArchitecture == [ ]) ''
  ${name}: every primary package must declare targetOciArch in passthru.
'';
assert pkgs.lib.assertMsg (wrongArchitectures == [ ]) ''
  ${name}: primary package architecture does not match OCI architecture ${arch}.
'';
assert pkgs.lib.assertMsg (builtins.all (entry: builtins.match "[^=]+=.*" entry != null) env) ''
  ${name}: every OCI environment entry must use NAME=value form.
'';
assert pkgs.lib.assertMsg (builtins.length envKeys == builtins.length (pkgs.lib.unique envKeys)) ''
  ${name}: OCI environment overrides must have unique names.
'';
image
