# `nix run .#sbom-<name>` inventories the Nix store closure of a container.
# This is an operational SBOM helper, not the source-compliance mechanism:
# Cargo and Go dependencies embedded in the primary application are outside
# its scope, while Nix-provided runtime dependencies are represented directly.
{
  pkgs,
  containers,
}:

let
  mkSbomScript =
    name: container:
    pkgs.writeShellApplication {
      name = "sbom-${name}";
      runtimeInputs = [ pkgs.sbomnix ];
      text = ''
        sbomnix \
          --cdx "./${name}.cdx.json" \
          --spdx "./${name}.spdx.json" \
          --csv "./${name}.csv" \
          "${container}"

        echo "Wrote ${name}.cdx.json, ${name}.spdx.json, and ${name}.csv"
      '';
    };
in
pkgs.lib.mapAttrs' (
  name: container:
  pkgs.lib.nameValuePair "sbom-${name}" {
    type = "app";
    program = "${mkSbomScript name container}/bin/sbom-${name}";
  }
) containers
