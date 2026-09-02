# `nix run .#<name>-copy-to-docker` loads a container into the local Docker
# daemon. The caller chooses the container set deliberately so architecture
# policy remains in flake.nix rather than being inferred from output names.
{
  pkgs,
  containers,
}:

pkgs.lib.mapAttrs' (
  name: container:
  pkgs.lib.nameValuePair "${name}-copy-to-docker" {
    type = "app";
    program = "${container.passthru.copyToDockerDaemon}/bin/copy-to-docker-daemon";
  }
) containers
