{
  pkgs,
  configDir,
  imagesDir,
  scriptsDir,
  skopeoNix2container,
}:

# Machine-validation images contain repository data rather than a compiled
# application. Keep those trees as explicit first-party contents so container
# assembly does not accidentally treat them as third-party OSS inputs.
{
  runnerFiles = pkgs.runCommand "machine-validation-runner-files" { } ''
    mkdir -p "$out/machine-validation"
    cp -r ${scriptsDir} "$out/machine-validation/scripts"
  '';

  # Machines download every name from images/list.json as <name>.tar and pass
  # it directly to `ctr images import`. Export the Nix-built image in Docker's
  # archive format and give it the reference the machine-validation runtime
  # returns after import.
  mkRunnerArchive =
    runnerImage:
    pkgs.runCommand "machine-validation-runner-docker-archive"
      {
        nativeBuildInputs = [
          pkgs.gnutar
          pkgs.jq
          skopeoNix2container
        ];
      }
      ''
        runner_reference='nvcr.io/nvidian/nvforge/machine-validation-runner:latest'
        skopeo \
          --tmpdir "$TMPDIR" \
          --insecure-policy \
          copy \
          "nix:${runnerImage}" \
          "docker-archive:$TMPDIR/machine-validation-runner.tar:$runner_reference"

        # Fail while producing the payload if the exporter ever changes format
        # or drops the reference that the runtime expects after import.
        mkdir "$TMPDIR/archive"
        tar --extract \
          --file "$TMPDIR/machine-validation-runner.tar" \
          --directory "$TMPDIR/archive"
        jq --exit-status \
          --arg expected "$runner_reference" \
          'any(.[].RepoTags[]?; . == $expected)' \
          "$TMPDIR/archive/manifest.json" >/dev/null

        # Nix supplies the output path to every derivation.
        # shellcheck disable=SC2154
        cp "$TMPDIR/machine-validation-runner.tar" "$out"
      '';

  # The archive set is keyed by the names in images/list.json. Keeping the
  # relationship data-driven makes adding another payload explicit and lets
  # the build reject a list entry whose archive was forgotten.
  mkConfigFiles =
    imageArchives:
    pkgs.runCommand "machine-validation-config-files"
      {
        nativeBuildInputs = [
          pkgs.gnutar
          pkgs.jq
        ];
      }
      ''
        mkdir -p "$out/machine-validation"
        cp -r ${configDir} "$out/machine-validation/config"
        cp -r ${imagesDir} "$out/machine-validation/images"
        chmod -R u+w "$out/machine-validation/images"

        ${pkgs.lib.concatStringsSep "\n" (
          pkgs.lib.mapAttrsToList (name: archive: ''
            install -m 0444 \
              ${archive} \
              "$out/machine-validation/images"/${pkgs.lib.escapeShellArg "${name}.tar"}
          '') imageArchives
        )}

        # Archive the pristine input so config.tar cannot recursively contain
        # itself. Stable ordering and metadata make repeated builds byte-identical.
        chmod -R u+w "$out/machine-validation/config"
        tar --create \
          --file "$out/machine-validation/config/config.tar" \
          --sort=name \
          --mtime=@0 \
          --owner=0 \
          --group=0 \
          --numeric-owner \
          --directory ${configDir} \
          .

        image_list="$out/machine-validation/images/list.json"
        jq --exit-status '
          .images as $images
          | ($images | type == "array")
            and ($images | length > 0)
            and ($images | all(.[]; type == "string"
              and test("^[A-Za-z0-9][A-Za-z0-9._-]*$")))
            and (($images | unique | length) == ($images | length))
        ' "$image_list" >/dev/null

        while IFS= read -r image_name; do
          archive="$out/machine-validation/images/$image_name.tar"
          if [ ! -s "$archive" ]; then
            echo "machine-validation: list.json names missing archive $image_name.tar" >&2
            exit 1
          fi
        done < <(jq --raw-output '.images[]' "$image_list")
      '';
}
