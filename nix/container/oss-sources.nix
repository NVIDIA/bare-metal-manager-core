{ pkgs }:

# Collect source tarballs for a list of nixpkgs packages into
# /usr/share/oss-sources/<original-filename> so containers satisfy
# the OSRB requirement that source code for all OSS shipped in the
# container be accessible to users who download it.
#
# Nix store paths for fetched sources take the form
# /nix/store/<hash>-<original-filename>, so stripping the hash prefix
# recovers the human-readable filename (e.g. ipmitool-1.8.19.tar.bz2).
# Directory sources (fetchFromGitHub etc.) are repacked as .tar.gz.
# Packages without a `.src` attribute are silently skipped.
name: ossPkgs:
let
  pkgsWithSrc = builtins.filter (p: p ? src) ossPkgs;
in
pkgs.runCommand "${name}-oss-sources"
  { nativeBuildInputs = with pkgs; [ gnutar gzip ]; }
  (
    ''
      mkdir -p $out/usr/share/oss-sources
    ''
    + pkgs.lib.concatMapStrings (
      pkg:
      let
        pname = pkg.pname or pkg.name or "unknown";
        version = pkg.version or "";
        outBase = pname + pkgs.lib.optionalString (version != "") "-${version}";
      in
      ''
        src="${pkg.src}"
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
          if [ -e "$destdir/${outBase}.tar.gz" ]; then
            echo "oss-sources: collision on ${outBase}.tar.gz — two packages map to the same archive name" >&2
            exit 1
          fi
          tar czf "$destdir/${outBase}.tar.gz" -C "$src" .
        fi
      ''
    ) pkgsWithSrc
  )
