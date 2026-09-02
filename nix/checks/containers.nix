{
  pkgs,
  containers,
}:

let
  inherit (pkgs) lib;

  renderRequiredExecutable = root: path: ''
    require_container_executable \
      ${lib.escapeShellArg root} \
      ${lib.escapeShellArg path}
  '';

  renderContainerCheck =
    name: image:
    let
      root = image.passthru.containerRoot;
      config = image.passthru.imageConfig;
      entrypoint = config.Entrypoint or [ ];
      command = config.Cmd or [ ];
      # OCI appends Cmd to Entrypoint when both are present. Cmd names an
      # executable only when the image has no Entrypoint of its own.
      executablePaths =
        if entrypoint != [ ] then
          [ (builtins.head entrypoint) ]
        else
          lib.optional (command != [ ]) (builtins.head command);
    in
    assert lib.assertMsg (lib.all (lib.hasPrefix "/") executablePaths) ''
      ${name}: OCI Entrypoint/Cmd executable paths must be absolute.
    '';
    ''
      echo "Checking generic container contract: ${name}"
      test -f ${lib.escapeShellArg "${root}/etc/passwd"}
      test -f ${lib.escapeShellArg "${root}/etc/nsswitch.conf"}
      test -d ${lib.escapeShellArg "${root}/usr/share/oss-sources"}
      test -f ${lib.escapeShellArg "${root}/usr/share/carbide/attributions.txt"}
      ${lib.concatMapStrings (renderRequiredExecutable root) executablePaths}
      ${lib.optionalString (config ? WorkingDir) ''
        test -d ${lib.escapeShellArg "${root}${config.WorkingDir}"}
      ''}
    '';

  apiImage = containers."rest-api-api-container";
  apiRoot = apiImage.passthru.containerRoot;
  dhcpRoot = containers."carbide-dhcp-container".passthru.containerRoot;
  flowRoot = containers."rest-api-flow-container".passthru.containerRoot;
  machineATronRoot = containers."machine-a-tron-container".passthru.containerRoot;
  matK8sControllerImage = containers."mat-k8s-controller-container";
  matK8sControllerRoot = matK8sControllerImage.passthru.containerRoot;
  machineValidationConfigRoot =
    containers."machine-validation-config-container".passthru.containerRoot;
  machineValidationRunnerRoot =
    containers."machine-validation-runner-container".passthru.containerRoot;
  otelRoot = containers."otelcol-contrib-container-arm64".passthru.containerRoot;
  scoutRoot = containers."carbide-scout-container".passthru.containerRoot;
  transceiverRoot = containers."transceiver-exporter-container-arm64".passthru.containerRoot;
  compatibilityRoot = containers."nvmetal-carbide-container".passthru.containerRoot;
in
pkgs.runCommand "check-container-layouts"
  {
    nativeBuildInputs = [
      pkgs.gnutar
      pkgs.jq
    ];
  }
  ''
    set -euo pipefail

    # buildEnv preserves absolute links that are valid inside the container.
    # Follow those links relative to the assembled root instead of accidentally
    # resolving them against the build host's /bin or /usr.
    resolve_container_path() {
      local root="$1"
      local path="$2"
      local candidate="$root$path"
      local target

      for _ in {1..16}; do
        if [ ! -L "$candidate" ]; then
          printf '%s\n' "$candidate"
          return 0
        fi
        target=$(readlink "$candidate")
        case "$target" in
          /nix/store/*) candidate="$target" ;;
          /*) candidate="$root$target" ;;
          *) candidate="$(dirname "$candidate")/$target" ;;
        esac
      done

      echo "container layout: symlink chain too deep for $path under $root" >&2
      return 1
    }

    require_container_executable() {
      local resolved
      resolved=$(resolve_container_path "$1" "$2") || return 1
      if [ -x "$resolved" ]; then
        return 0
      fi

      echo "container layout: missing executable $2 under $1" >&2
      return 1
    }

    ${lib.concatStringsSep "\n" (lib.mapAttrsToList renderContainerCheck containers)}

    # The API image exercises the common image builder. Every layer must come
    # from a Nix path; an inherited base image would introduce an opaque layer
    # without this path inventory.
    jq -e '
      .arch == "amd64"
      and .["image-config"].User == "65534:65534"
      and .["image-config"].WorkingDir == "/app"
      and .["image-config"].Labels["org.opencontainers.image.source"]
          == "https://github.com/NVIDIA/infra-controller"
      and .["image-config"].Labels["org.opencontainers.image.title"]
          == "nico-rest-api"
      and .["image-config"].Labels["org.opencontainers.image.url"]
          == "https://github.com/NVIDIA/infra-controller"
      and (.["image-config"].Labels["org.opencontainers.image.revision"]
          | test("^[0-9a-f]{8}$"))
      and (.["image-config"].Labels["org.opencontainers.image.version"] | length > 0)
      and all(.layers[]; ((.paths // []) | length) > 0)
      and ([.. | objects
            | select(.regex? == "/tmp$" and .mode? == "1777")]
          | length == 1)
    ' ${apiImage}

    require_container_executable ${apiRoot} /app/api
    require_container_executable ${apiRoot} /app/nicocli
    require_container_executable ${apiRoot} /bin/sh

    # Primary NICo applications and their embedded Cargo/Go libraries are not
    # part of the separately added runtime-source policy.
    api_source_dir=${apiRoot}/usr/share/oss-sources
    for forbidden in \
      "$api_source_dir"/*carbide* \
      "$api_source_dir"/*infra-controller* \
      "$api_source_dir"/*rest-api*; do
      if [ -e "$forbidden" ]; then
        echo "container layout: primary application source was bundled: $forbidden" >&2
        exit 1
      fi
    done

    require_container_executable ${otelRoot} /etc/otelcol-contrib/otelcol-wrapper
    require_container_executable ${otelRoot} /usr/bin/otelcol-contrib
    require_container_executable ${otelRoot} /usr/bin/env
    require_container_executable ${otelRoot} /bin/bash
    require_container_executable ${otelRoot} /bin/journalctl
    test -d ${otelRoot}/run/otelcol-contrib
    otel_sources=( ${otelRoot}/usr/share/oss-sources/otelcol-contrib-*.tar.gz )
    test "''${#otel_sources[@]}" -eq 1
    test -f "''${otel_sources[0]}"

    require_container_executable ${transceiverRoot} /usr/bin/transceiver-exporter
    test -f \
      ${transceiverRoot}/usr/share/oss-sources/transceiver-exporter-1.5.0-source.tar.gz

    require_container_executable ${flowRoot} /app/flow
    # buildEnv collapses /usr/share/zoneinfo onto the extraCommands root when
    # nothing else provides that path, so assert what time.LoadLocation needs:
    # the link resolves to the tzdata tree the image ships at /share/zoneinfo.
    test -f "$(resolve_container_path ${flowRoot} /usr/share/zoneinfo)/America/Los_Angeles"
    test -f ${flowRoot}/share/zoneinfo/America/Los_Angeles
    tzdata_sources=( ${flowRoot}/usr/share/oss-sources/tzdata*.tar.gz )
    tzcode_sources=( ${flowRoot}/usr/share/oss-sources/tzcode*.tar.gz )
    test "''${#tzdata_sources[@]}" -eq 1
    test "''${#tzcode_sources[@]}" -eq 1
    test -f "''${tzdata_sources[0]}"
    test -f "''${tzcode_sources[0]}"

    require_container_executable ${scoutRoot} /usr/bin/dd
    require_container_executable ${scoutRoot} /bin/bash
    require_container_executable ${scoutRoot} /bin/lspci
    require_container_executable ${scoutRoot} /bin/mokutil
    require_container_executable ${scoutRoot} /bin/setpci
    require_container_executable ${scoutRoot} /usr/sbin/nvme
    require_container_executable ${scoutRoot} /opt/mellanox/mft/bin/mlxfwreset
    require_container_executable ${scoutRoot} /opt/mellanox/mft/bin/mlxprivhost
    grep -F "PYTHON_EXEC='/nix/store/" \
      ${scoutRoot}/opt/mellanox/mft/bin/mlxfwreset
    grep -F "PYTHON_EXEC='/nix/store/" \
      ${scoutRoot}/opt/mellanox/mft/bin/mlxprivhost
    test -s ${scoutRoot}/etc/mft/mft.conf
    # buildEnv leaves /usr/share/mft as a link to the mft package, so -L is
    # what makes find descend into the database tree instead of stopping.
    test -n "$(find -L ${scoutRoot}/usr/share/mft -mindepth 1 -print -quit)"

    require_container_executable ${machineATronRoot} /opt/machine-a-tron/bin/machine-a-tron
    require_container_executable ${machineATronRoot} /bin/ipmi_sim
    test -d ${machineATronRoot}/tmp/machine-a-tron-data

    require_container_executable ${matK8sControllerRoot} /bin/mat-k8s-controller
    test '${builtins.toJSON matK8sControllerImage.passthru.imageConfig.Entrypoint}' = \
      '["/bin/mat-k8s-controller"]'
    test '${matK8sControllerImage.passthru.imageConfig.User}' = '65534:65534'

    test -d ${machineValidationRunnerRoot}/machine-validation/scripts
    test -f ${machineValidationConfigRoot}/machine-validation/config/config.tar
    test -d ${machineValidationConfigRoot}/machine-validation/images

    machine_validation_image_list=${machineValidationConfigRoot}/machine-validation/images/list.json
    jq --exit-status '
      .images
      | type == "array"
        and length > 0
        and all(.[]; type == "string"
          and test("^[A-Za-z0-9][A-Za-z0-9._-]*$"))
    ' "$machine_validation_image_list" >/dev/null
    while IFS= read -r image_name; do
      image_archive=${machineValidationConfigRoot}/machine-validation/images/"$image_name.tar"
      if [ ! -s "$image_archive" ]; then
        echo "container layout: list.json names missing archive $image_name.tar" >&2
        exit 1
      fi

      # The downloader passes these bytes straight to `ctr images import`.
      # A nonempty but malformed placeholder must not satisfy the release gate.
      tar --list --file "$image_archive" >/dev/null
    done < <(jq --raw-output '.images[]' "$machine_validation_image_list")

    dhcp_hook=$(readlink ${dhcpRoot}/usr/lib/kea/hooks/libdhcp.so)
    test "$dhcp_hook" = "/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp.so"
    test -e "${dhcpRoot}$dhcp_hook"

    require_container_executable ${compatibilityRoot} /opt/carbide/carbide-api
    require_container_executable ${compatibilityRoot} /usr/bin/ipmitool
    require_container_executable ${compatibilityRoot} /usr/bin/forge-dpu-agent
    require_container_executable \
      ${compatibilityRoot} /var/support/forge-dhcp/bin/forge-dhcp-server

    touch "$out"
  ''
