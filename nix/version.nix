let
  # Pure flake evaluation exposes a revision and reachable revision count, but
  # not the nearest Git tag. This anchor supplies that missing release context
  # when no git-describe string was passed in.
  tag = "v2.2.0-pr";
  tagRevision = "e90c19b24dc70537338220e112254c5e57dfa2e5";
  tagRevCount = 2712;

  removeSuffix =
    suffix: str:
    let
      sufLen = builtins.stringLength suffix;
      sLen = builtins.stringLength str;
    in
    if sufLen <= sLen && builtins.substring (sLen - sufLen) sufLen str == suffix then
      builtins.substring 0 (sLen - sufLen) str
    else
      str;

  trimDescribe =
    s:
    removeSuffix "\n" (removeSuffix "\r" (removeSuffix "\n" (removeSuffix " " s)));

  revisionFromSource =
    sourceRevision:
    let
      hasRevision = sourceRevision != null && builtins.match "[0-9a-f]{40}" sourceRevision != null;
    in
    {
      inherit hasRevision;
      revision = if hasRevision then builtins.substring 0 8 sourceRevision else "00000000";
    };

  # Dirty trees can still expose revCount. Ordered describe is only for a
  # clean history we can count. Upgrade policy (BuildVersion) ignores the
  # git hash and -dirty, so a fabricated `${tag}-0-g<hash>` compares equal
  # to the tag and can suppress upgrades.
  forSource =
    {
      sourceRevision ? null,
      sourceRevCount ? null,
      sourceDirty ? false,
    }:
    let
      bits = revisionFromSource sourceRevision;
      inherit (bits) hasRevision revision;
      hasOrderedRevision = hasRevision && sourceRevCount != null && !sourceDirty;
      commitDistance = if hasOrderedRevision then sourceRevCount - tagRevCount else 0;
      unorderedVersion =
        if hasRevision && !sourceDirty then
          "v0.0.0-0-g${revision}"
        else
          "v0.0.0-0-g${revision}-dirty";
    in
    if hasOrderedRevision && commitDistance < 0 then
      throw "nix/version.nix: git revCount ${toString sourceRevCount} is before release anchor ${tag} (revCount ${toString tagRevCount})"
    else
      {
        inherit commitDistance hasOrderedRevision revision;
        version =
          if hasOrderedRevision && commitDistance == 0 && sourceRevision == tagRevision then
            tag
          else if hasOrderedRevision && commitDistance > 0 then
            "${tag}-${toString commitDistance}-g${revision}"
          else
            unorderedVersion;
      };

  # Turn a `git describe --tags --first-parent --always` string into the
  # VERSION contract. `--long` on a tagged commit emits `TAG-0-gHEX`; collapse
  # that to TAG so it matches CI (which omits `--long`) and so BuildVersion
  # does not treat it as a distinct release.
  parseDescribe =
    text:
    let
      core = removeSuffix "-dirty" text;
      atTag = builtins.match "(.*)-0-g[0-9a-f]+" core;
      bareSha = builtins.match "[0-9a-f]+" core;
    in
    if atTag != null then
      builtins.head atTag
    else if bareSha != null then
      "v0.0.0-0-g${core}"
    else
      core;

  fromDescribe =
    describe:
    {
      sourceRevision ? null,
      sourceDirty ? false,
    }:
    let
      bits = revisionFromSource sourceRevision;
      inherit (bits) revision;
      text = trimDescribe describe;
      parsed = parseDescribe text;
      version =
        if sourceDirty && builtins.match ".*-dirty" parsed == null then "${parsed}-dirty" else parsed;
    in
    {
      inherit revision version;
      hasOrderedRevision = !sourceDirty && builtins.match "v0\\.0\\.0-0-g.*" version == null;
      commitDistance = 0;
    };
in
{
  inherit
    forSource
    fromDescribe
    tag
    tagRevCount
    tagRevision
    trimDescribe
    ;
}
