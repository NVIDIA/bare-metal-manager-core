{
  pkgs,
  versionAnchor,
}:

let
  revisionAtTag = versionAnchor.tagRevision;
  revisionAfterTag = "1111111111111111111111111111111111111111";
  unorderedAfter = "v0.0.0-0-g11111111";
  atTag = versionAnchor.forSource {
    sourceRevision = revisionAtTag;
    sourceRevCount = versionAnchor.tagRevCount;
  };
  afterTag = versionAnchor.forSource {
    sourceRevision = revisionAfterTag;
    sourceRevCount = versionAnchor.tagRevCount + 1;
  };
  sameCountDifferentRevision = versionAnchor.forSource {
    sourceRevision = revisionAfterTag;
    sourceRevCount = versionAnchor.tagRevCount;
  };
  shallowClone = versionAnchor.forSource {
    sourceRevision = revisionAfterTag;
  };
  dirtyWorktree = versionAnchor.forSource {
    sourceRevision = revisionAfterTag;
    sourceDirty = true;
  };
  dirtyWithRevCount = versionAnchor.forSource {
    sourceRevision = revisionAfterTag;
    sourceRevCount = versionAnchor.tagRevCount + 10;
    sourceDirty = true;
  };
  archiveInput = versionAnchor.forSource { };
  beforeTag = builtins.tryEval (
    versionAnchor.forSource {
      sourceRevision = revisionAtTag;
      sourceRevCount = versionAnchor.tagRevCount - 1;
    }
  );
  describeTag = versionAnchor.fromDescribe versionAnchor.tag {
    sourceRevision = revisionAtTag;
  };
  describeLong = versionAnchor.fromDescribe "${versionAnchor.tag}-3-gabcdef1" {
    sourceRevision = revisionAfterTag;
  };
  describeAtTagLong = versionAnchor.fromDescribe "${versionAnchor.tag}-0-gabcdef1" {
    sourceRevision = revisionAtTag;
  };
  describeBareSha = versionAnchor.fromDescribe "abcdef1" {
    sourceRevision = revisionAfterTag;
  };
  describeDirty = versionAnchor.fromDescribe versionAnchor.tag {
    sourceRevision = revisionAtTag;
    sourceDirty = true;
  };
  describeTrimmed = versionAnchor.fromDescribe "${versionAnchor.tag}\n" {
    sourceRevision = revisionAtTag;
  };
in
assert atTag.version == versionAnchor.tag;
assert afterTag.version == "${versionAnchor.tag}-1-g11111111";
# Distance 0 on a different commit, and a clean shallow clone, must not emit
# `${tag}-0-g…`. BuildVersion ignores the hash, so that form equals the tag.
assert sameCountDifferentRevision.version == unorderedAfter;
assert shallowClone.version == unorderedAfter;
assert dirtyWorktree.version == "v0.0.0-0-g11111111-dirty";
assert dirtyWithRevCount.version == "v0.0.0-0-g11111111-dirty";
assert archiveInput.version == "v0.0.0-0-g00000000-dirty";
assert !beforeTag.success;
assert describeTag.version == versionAnchor.tag;
assert describeLong.version == "${versionAnchor.tag}-3-gabcdef1";
assert describeAtTagLong.version == versionAnchor.tag;
assert describeBareSha.version == "v0.0.0-0-gabcdef1";
assert describeDirty.version == "${versionAnchor.tag}-dirty";
assert describeTrimmed.version == versionAnchor.tag;
pkgs.runCommand "check-nix-version-contract" { } ''
  touch "$out"
''
