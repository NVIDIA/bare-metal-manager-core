#!/usr/bin/env bash
set -euo pipefail

# Build and run the containerized otel-agent to renew mTLS certs for the
# OpenTelemetry collector.
#
# - The container is needed on machines that do not have the version of glibc
#   expected by the agent.
# - The otel-agent service builds the container on the fly at `systemctl
#   start`, which requires access to docker hub (to satisfy a dependency on the
#   "ca-certificates" module). On machines where docker cannot reach docker
#   hub, you can install pre-built
#     /usr/lib/otel-agent/docker/otel-agent-image.tar
#   and the service will load that instead.
# - The service Dockerfile specifies an "otel.agent.version" label. If the
#   image is already present and its version matches the Dockerfile, no
#   building or loading of the image is needed. If you bump the version in
#   bluefield/otel/site-controller/otel-agent/Dockerfile, the service will
#   rebuild or reload the image on the next package install.
#
IMAGE_TAG=otel-agent:latest
IMAGE_TAR=/usr/lib/otel-agent/docker/otel-agent-image.tar.gz
FORCE_REBUILD=false
STATE_FILE="${XDG_CACHE_HOME:-$HOME/.cache}/otel-agent-build.hash"
CARBIDE_API=carbide-api.forge

# Parse optional flags
while [[ "$#" -gt 0 ]]; do
    case "$1" in
    --rebuild)
        FORCE_REBUILD=true
        shift
        ;;
    *)
        break
        ;;
    esac
done

mkdir -p "$(dirname "$STATE_FILE")"

CARBIDE_API_IP_ADDR=$(getent hosts "$CARBIDE_API" | awk '{print $1}')
status=$?

if [[ $status -ne 0 || -z "$CARBIDE_API_IP_ADDR" ]]; then
    echo "Failed to resolve $CARBIDE_API" >&2
    exit 1
fi

BUILD_DIR=$(mktemp -d /tmp/otel-agent-build.XXXXXX)
trap 'rm -rf "$BUILD_DIR"' EXIT

OTEL_AGENT=/usr/bin/otel-agent
DOCKERFILE=/usr/share/otelcol-contrib/docker/otel-agent/Dockerfile

if [[ ! -f "$OTEL_AGENT" ]]; then
    echo "Expected $OTEL_AGENT is missing" >&2
    exit 1
fi

if [[ ! -f "$DOCKERFILE" ]]; then
    echo "Expected $DOCKERFILE is missing" >&2
    exit 1
fi

image_exists() {
    docker image inspect "$IMAGE_TAG" > /dev/null 2>&1
}

get_image_label() {
    local image=$1
    local key=$2

    docker image inspect \
        --format "{{ index .Config.Labels \"$key\" }}" \
        "$image" 2>/dev/null || echo "unknown"
}

cp "$OTEL_AGENT" "$BUILD_DIR"/
cp "$DOCKERFILE" "$BUILD_DIR/Dockerfile"

OLD_VERSION=""
[[ -f "$STATE_FILE" ]] && OLD_VERSION=$(cat "$STATE_FILE")

VERSION=$(get_image_label "$IMAGE_TAG" "otel.agent.version")

if [[ "${FORCE_REBUILD:-false}" == true ]]; then
    echo "Forcing rebuild of $IMAGE_TAG..."
    docker build --no-cache -t "$IMAGE_TAG" "$BUILD_DIR"/
    VERSION=$(get_image_label "$IMAGE_TAG" "otel.agent.version")
    echo "$VERSION" > "$STATE_FILE"
elif ! image_exists; then
    if [[ -r "$IMAGE_TAR" ]]; then
        echo "Preloading $IMAGE_TAG from $IMAGE_TAR..."
        if ! docker load -i "$IMAGE_TAR"; then
            echo "docker load failed, will try build" >&2
        fi
    else
        echo "Image $IMAGE_TAG missing, no preload tarball; building..."
    fi

    if ! image_exists; then
        echo "Building $IMAGE_TAG..."
        docker build -t "$IMAGE_TAG" "$BUILD_DIR"/
    fi

    VERSION=$(get_image_label "$IMAGE_TAG" "otel.agent.version")
    echo "$VERSION" > "$STATE_FILE"
elif [[ "$VERSION" != "$OLD_VERSION" ]]; then
    echo "Detected version change: old=$OLD_VERSION, new=$VERSION"

    if [[ -r "$IMAGE_TAR" ]]; then
        echo "Preloading updated $IMAGE_TAG from $IMAGE_TAR..."
        if ! docker load -i "$IMAGE_TAR"; then
            echo "docker load failed, will try build" >&2
        fi
    else
        echo "No preload tarball for updated image; rebuilding $IMAGE_TAG..."
    fi

    if ! image_exists; then
        echo "Building $IMAGE_TAG..."
        docker build -t "$IMAGE_TAG" "$BUILD_DIR"/
    fi

    VERSION=$(get_image_label "$IMAGE_TAG" "otel.agent.version")
    echo "$VERSION" > "$STATE_FILE"
else
    echo "Reusing existing $IMAGE_TAG; no rebuild needed."
fi

ip vrf exec mgmt docker run --rm \
    --name otel-agent \
    --network host \
    --add-host ${CARBIDE_API}:${CARBIDE_API_IP_ADDR} \
    --mount type=bind,source=/etc/otelcol-contrib/certs,target=/etc/otelcol-contrib/certs \
    --mount type=bind,source=/etc/otelcol-contrib/otel-agent.toml,target=/config/config.toml,readonly \
    otel-agent --config-path /config/config.toml run
