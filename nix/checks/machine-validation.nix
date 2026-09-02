{
  pkgs,
  configContainers,
}:

let
  inherit (pkgs) lib;

  renderCarrierCheck =
    image:
    let
      root = image.passthru.containerRoot;
    in
    ''
      check_machine_validation_payloads ${lib.escapeShellArg root}
    '';
in
assert lib.assertMsg (configContainers != [ ]) (
  "machine-validation payload check requires at least one config carrier"
);
pkgs.runCommand "check-machine-validation-payloads"
  {
    nativeBuildInputs = [
      pkgs.gnutar
      pkgs.jq
    ];
  }
  ''
    set -euo pipefail

    check_machine_validation_payloads() {
      local root=$1
      local images_dir="$root/machine-validation/images"
      local image_list="$images_dir/list.json"

      if [ ! -s "$image_list" ]; then
        echo "machine-validation: missing nonempty $image_list" >&2
        return 1
      fi

      jq --exit-status '
        .images as $images
        | ($images | type == "array")
          and ($images | length > 0)
          and ($images | all(.[]; type == "string"
            and test("^[A-Za-z0-9][A-Za-z0-9._-]*$")))
          and (($images | unique | length) == ($images | length))
      ' "$image_list" >/dev/null

      while IFS= read -r image_name; do
        local archive="$images_dir/$image_name.tar"
        if [ ! -s "$archive" ]; then
          echo "machine-validation: list.json names missing archive $image_name.tar" >&2
          return 1
        fi

        # Provisioned machines feed the payload directly to containerd. Make
        # sure a nonempty placeholder cannot satisfy the file-list contract.
        tar --list --file "$archive" >/dev/null
      done < <(jq --raw-output '.images[]' "$image_list")
    }

    ${lib.concatMapStrings renderCarrierCheck configContainers}

    # Nix supplies the output path to every derivation.
    # shellcheck disable=SC2154
    touch "$out"
  ''
