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
# - The otel-agent container is run by the same `crictl` runtime as the
#   doca-hbn container so there's a single container runtime on the DPU. This
#   is done by generating a static‑pod YAML and installing it into
#   /etc/kubelet.d and waiting for kubelet/containerd to start the pod.
#
DOCKER=/usr/bin/docker
CTR=/usr/bin/ctr
CRICTL=/usr/bin/crictl
IMAGE_TAG=otel-agent:latest
IMAGE_TAR=/usr/lib/otel-agent/docker/otel-agent-image.tar.gz
FORCE_REBUILD=false
STATE_DIR=/var/lib/otel-agent
STATE_FILE="$STATE_DIR/otel-agent-build.hash"
CARBIDE_API=carbide-api.forge
TAR_DIR=/var/lib/otelcol-contrib
CERTS_DIR=/etc/otelcol-contrib/certs
TEMPLATE=/usr/share/otelcol-contrib/docker/otel-agent/otel-agent.yaml.template
OTEL_AGENT_CONFIG=/etc/kubelet.d/otel-agent.yaml

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

if [[ ! -f "$CERTS_DIR/private/otel-key.pem" ]]; then
    # mTLS certs are not installed yet. Look for initial certs in a tar file at
    # $TAR_DIR. If they aren't there yet, fail and let the service retry until
    # initial certs are provided.
    if [[ -f "$TAR_DIR/mtls-certs.tar" ]]; then
        cd "$TAR_DIR"
        tar xvf mtls-certs.tar --exclude='._*' --warning=no-unknown-keyword
        if [[ ! -d certs ]]; then
            echo "Expected 'certs' directory missing after extraction" >&2
            exit 1
        fi
        mv certs/ca.pem "$CERTS_DIR/"
        mv certs/client-cert.pem "$CERTS_DIR/otel-cert.pem"
        mv certs/client-key.pem "$CERTS_DIR/private/otel-key.pem"
        rm mtls-certs.tar
        rmdir certs 2>/dev/null || true
        cd - >/dev/null
        if [[ -z "$(find "$TAR_DIR" -mindepth 1 -maxdepth 1 2>/dev/null)" ]]; then
            rmdir "$TAR_DIR"
        fi
    else
        echo "Initial mTLS certs not found at $TAR_DIR/mtls-certs.tar" >&2
        exit 1
    fi
fi

mkdir -p "$STATE_DIR"

CARBIDE_API_IP_ADDR=$(getent hosts "$CARBIDE_API" | awk '{print $1}') || true

if [[ -z "$CARBIDE_API_IP_ADDR" ]]; then
    echo "Failed to resolve $CARBIDE_API" >&2
    exit 1
fi

BUILD_DIR=$(mktemp -d /tmp/otel-agent-build.XXXXXX)
SAVED_IMAGE=$(mktemp /tmp/otel-agent-image.XXXXXX.tar)
GENERATED_YAML=$(mktemp /tmp/otel-agent-config.XXXXXX.yaml)

cleanup() {
    [[ -n "${BUILD_DIR:-}" ]] && rm -rf "$BUILD_DIR"
    [[ -n "${SAVED_IMAGE:-}" ]] && rm -f "$SAVED_IMAGE"
    [[ -n "${GENERATED_YAML:-}" ]] && rm -f "$GENERATED_YAML"
}

trap cleanup EXIT

OTEL_AGENT=/usr/bin/otel-agent
DOCKERFILE=/usr/share/otelcol-contrib/docker/otel-agent/Dockerfile

if [[ ! -f "$OTEL_AGENT" ]]; then
    echo "Expected binary not found: $OTEL_AGENT" >&2
    exit 1
fi

if [[ ! -f "$DOCKERFILE" ]]; then
    echo "Expected Dockerfile not found: $DOCKERFILE" >&2
    exit 1
fi

image_exists() {
    "$DOCKER" image inspect "$IMAGE_TAG" > /dev/null 2>&1
}

get_image_label() {
    local image=$1
    local key=$2

    "$DOCKER" image inspect \
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
    "$DOCKER" build --no-cache -t "$IMAGE_TAG" "$BUILD_DIR"/
    VERSION=$(get_image_label "$IMAGE_TAG" "otel.agent.version")
    echo "$VERSION" > "$STATE_FILE"
elif ! image_exists; then
    if [[ -r "$IMAGE_TAR" ]]; then
        echo "Preloading $IMAGE_TAG from $IMAGE_TAR..."
        if ! "$DOCKER" load -i "$IMAGE_TAR"; then
            echo "docker load failed, will try build" >&2
        fi
    else
        echo "Image $IMAGE_TAG missing, no preload tarball; building..."
    fi

    if ! image_exists; then
        echo "Building $IMAGE_TAG..."
        "$DOCKER" build -t "$IMAGE_TAG" "$BUILD_DIR"/
    fi

    VERSION=$(get_image_label "$IMAGE_TAG" "otel.agent.version")
    echo "$VERSION" > "$STATE_FILE"
elif [[ "$VERSION" != "$OLD_VERSION" ]]; then
    echo "Detected version change: old=$OLD_VERSION, new=$VERSION"

    if [[ -r "$IMAGE_TAR" ]]; then
        echo "Preloading updated $IMAGE_TAG from $IMAGE_TAR..."
        if ! "$DOCKER" load -i "$IMAGE_TAR"; then
            echo "docker load failed, will try build" >&2
        fi
    else
        echo "No preload tarball for updated image; rebuilding $IMAGE_TAG..."
    fi

    if ! image_exists; then
        echo "Building $IMAGE_TAG..."
        "$DOCKER" build -t "$IMAGE_TAG" "$BUILD_DIR"/
    fi

    VERSION=$(get_image_label "$IMAGE_TAG" "otel.agent.version")
    echo "$VERSION" > "$STATE_FILE"
else
    echo "Reusing existing $IMAGE_TAG; no rebuild needed."
fi

# Check whether the service is already running
if [[ -f "$OTEL_AGENT_CONFIG" ]]; then
    if "$CRICTL" ps --name otel-agent | grep -q otel-agent; then
        echo "otel-agent already started"
        exit 0
    else
        echo "Config present but container not running; re-installing config" >&2
    fi
fi

# Import the otel-agent image from docker into crictl image store
"$DOCKER" save -o "$SAVED_IMAGE" "$IMAGE_TAG"
"$CTR" -n k8s.io images import "$SAVED_IMAGE"

# Generate and verify the container config and install it in /etc/kubelet.d where
# crictl will pick it up and run it automatically.
sed "s|\${CARBIDE_API_IP_ADDR}|${CARBIDE_API_IP_ADDR}|g" "$TEMPLATE" > "$GENERATED_YAML"
python3 -c 'import sys, yaml; yaml.safe_load(open(sys.argv[1]))' "$GENERATED_YAML"
install -m 0644 "$GENERATED_YAML" "$OTEL_AGENT_CONFIG"

# Wait for `crictl ps` to show the container
timeout=60
interval=2

for i in $(seq 1 $((timeout / interval))); do
    if "$CRICTL" ps --name otel-agent | grep -q otel-agent; then
        exit 0
    fi
    sleep "$interval"
done

echo "otel-agent did not appear in crictl ps output within ${timeout}s" >&2
exit 1
