{ pkgs }:

# Collect source tarballs for separately added open-source packages into
# /usr/share/oss-sources/<original-filename> so containers satisfy
# the source-distribution policy for their runtime contents. The primary
# application package is intentionally not passed to this helper, nor are its
# embedded Cargo or Go dependencies.
#
# Nix store paths for fetched sources take the form
# /nix/store/<hash>-<original-filename>, so stripping the hash prefix
# recovers the human-readable filename (e.g. ipmitool-1.8.19.tar.bz2).
# Directory sources (fetchFromGitHub etc.) are repacked as .tar.gz. Packages
# with more than one source (notably tzdata's data and code archives) retain
# every declared source. A package may override the generic Nix source with
# `ossSource` or `ossSources`; this is used when a distributed prebuilt binary
# has a separate corresponding-source archive.
# Candidate packages without open-source license metadata are ignored. Once a
# package is identified as open source, however, a missing source is an error:
# silently omitting it would make the generated directory look complete when
# it is not.
name: candidatePkgs:
let
  licensesFor =
    pkg: if builtins.isList pkg.meta.license then pkg.meta.license else [ pkg.meta.license ];

  # A free-form string does not carry nixpkgs' reviewed `free` classification;
  # values such as "proprietary" are valid strings too. Require structured
  # metadata so an unknown licence cannot accidentally trigger redistribution.
  isOpenSourceLicense = license: builtins.isAttrs license && (license.free or false);

  isOpenSourcePackage =
    pkg: pkg ? meta && pkg.meta ? license && builtins.any isOpenSourceLicense (licensesFor pkg);

  ossPkgs = builtins.filter isOpenSourcePackage candidatePkgs;
  sourcesFor =
    pkg:
    if pkg ? ossSources then
      pkg.ossSources
    else if pkg ? ossSource then
      [ pkg.ossSource ]
    else if pkg ? srcs then
      pkg.srcs
    else if pkg ? src then
      [ pkg.src ]
    else
      [ ];
  missingSources = builtins.filter (pkg: sourcesFor pkg == [ ]) ossPkgs;
  missingSourceNames = map (pkg: pkg.pname or pkg.name or "unknown") missingSources;
  sourceRecords = pkgs.lib.concatMap (
    pkg:
    pkgs.lib.imap0 (index: source: {
      inherit index pkg source;
      sourceCount = builtins.length (sourcesFor pkg);
    }) (sourcesFor pkg)
  ) ossPkgs;
in
assert pkgs.lib.assertMsg (missingSources == [ ]) ''
  Open-source runtime packages are missing a source input:
    ${builtins.concatStringsSep ", " missingSourceNames}
  Add an explicit source-bearing package or document why it is not distributed.
'';
pkgs.runCommand "${name}-oss-sources"
  {
    nativeBuildInputs = with pkgs; [
      gnutar
      gzip
    ];
  }
  (
    ''
      mkdir -p $out/usr/share/oss-sources
    ''
    + pkgs.lib.concatMapStrings (
      record:
      let
        inherit (record) pkg source;
        pname = pkg.pname or pkg.name or "unknown";
        version = pkg.version or "";
        outBase = pname + pkgs.lib.optionalString (version != "") "-${version}";
        directoryArchive =
          outBase
          + pkgs.lib.optionalString (record.sourceCount > 1) "-source-${toString (record.index + 1)}"
          + ".tar.gz";
      in
      ''
        src="${source}"
        destdir="$out/usr/share/oss-sources"
        if [ -f "$src" ]; then
          # Tarball: strip the Nix hash prefix to recover the original filename.
          origname=$(basename "$src")
          filename="''${origname#*-}"
          if [ -e "$destdir/$filename" ]; then
            echo "oss-sources: collision on $filename — two packages map to the same filename" >&2
            exit 1
          fi
          cp "$src" "$destdir/$filename"
        elif [ -d "$src" ]; then
          if [ -e "$destdir/${directoryArchive}" ]; then
            echo "oss-sources: collision on ${directoryArchive}; two sources map to the same archive name" >&2
            exit 1
          fi
          tar czf "$destdir/${directoryArchive}" -C "$src" .
        else
          echo "oss-sources: source path does not contain a file or directory: $src" >&2
          exit 1
        fi
      ''
    ) sourceRecords
  )
