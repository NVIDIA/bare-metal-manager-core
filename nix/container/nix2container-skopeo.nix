{
  pkgs,
  # Pre-patched skopeo from the nix2container flake, which already includes
  # the `nix:` transport. Using this avoids having to re-patch nixpkgs'
  # skopeo against its own vendor tree, which breaks across skopeo upgrades.
  skopeoNix2container,
}:

let
  # Shell application with skopeo (nix: transport) + docker client.
  writeSkopeoApp =
    name: text:
    pkgs.writeShellApplication {
      inherit name text;
      runtimeInputs = [
        pkgs.jq
        pkgs.docker-client
        skopeoNix2container
      ];
      excludeShellChecks = [ "SC2068" ];
    };

in
{
  copyToDockerDaemon =
    image:
    writeSkopeoApp "copy-to-docker-daemon" ''
      echo "Copy to Docker daemon image ${image.imageName}:${image.imageTag}"
      skopeo --insecure-policy copy nix:${image} docker-daemon:${image.imageName}:${image.imageTag} "$@"
      docker tag "${image.imageName}:${image.imageTag}" "${image.imageName}:latest"
    '';

  copyToRegistry =
    image:
    writeSkopeoApp "copy-to-registry" ''
      echo "Copy to Docker registry image ${image.imageName}:${image.imageTag}"
      skopeo --insecure-policy copy nix:${image} docker://${image.imageName}:${image.imageTag} "$@"
    '';

  copyTo =
    image:
    writeSkopeoApp "copy-to" ''
      echo "Running skopeo --insecure-policy copy nix:${image}" "$@"
      copy_args=(--retry-times "''${COPY_RETRY_TIMES:-3}")
      if [[ -n "''${DIGEST_FILE:-}" ]]; then
        copy_args+=(--digestfile "$DIGEST_FILE")
      fi
      skopeo --insecure-policy copy "''${copy_args[@]}" nix:${image} "$@"
    '';

}
