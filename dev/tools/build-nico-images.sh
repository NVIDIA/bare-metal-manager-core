#!/usr/bin/env bash
# =============================================================================
# build-nico-images.sh
# -----------------------------------------------------------------------------
# Standalone, BUILD-ONLY automation for every Docker image NICo deploys.
# No Kubernetes, no kubeadm, no helm — just `docker`. Drop this on a fresh
# Ubuntu (or any Linux) VM that has Docker installed, check out the repo, and
# run it to validate that all images build, with OR without a Squid proxy.
#
# Images built (in dependency order):
#   1. build-container-localdev   (dev/docker/Dockerfile.build-container-x86_64)
#   2. carbide-runtime-base       (dev/deployment/devspace/Dockerfile.runtime-base)
#   3. <prefix>-api               (Dockerfile.all-services — bundles every
#                                  service binary; falls back to Dockerfile.api)
#   4. <prefix>-bmc-proxy         (Dockerfile.bmc-proxy)
#   5. forge/unbound              (dev/docker/unbound/Dockerfile)
#   6. forge/unbound_exporter     (dev/docker/unbound-exporter/Dockerfile)
#
# <prefix> is auto-detected from helm/charts (carbide-* or nico-*).
#
# Proxy handling
# --------------
# The base build-container runs apt/rustup/cargo/curl and does NOT declare a
# SQUID_PROXY build-arg, so when a proxy is given this script passes Docker's
# predefined http_proxy/https_proxy build-args (honored by apt/cargo/curl) to
# EVERY build, plus --build-arg SQUID_PROXY=<url> for the service Dockerfiles
# that consume it. Proxy values are not baked into the final images.
#
# Usage
# -----
#   # No proxy (VM has direct internet):
#   ./dev/tools/build-nico-images.sh
#
#   # Behind a Squid proxy:
#   ./dev/tools/build-nico-images.sh --squid-proxy http://172.16.0.1:3128
#   # (or)  SQUID_PROXY=http://172.16.0.1:3128 ./dev/tools/build-nico-images.sh
#
#   # Build only some images:
#   ./dev/tools/build-nico-images.sh --only base,api
#   ./dev/tools/build-nico-images.sh --only unbound,unbound-exporter
#
#   # Skip the (slow) base if it already exists, force a clean build, save tars:
#   ./dev/tools/build-nico-images.sh --skip-base --no-cache --save-dir /tmp/nico-images
#
# Options
# -------
#   --squid-proxy URL   Route all builds through this HTTP proxy.
#   --no-proxy          Force no proxy (ignores SQUID_PROXY env).
#   --only LIST         Comma list: base,runtime-base,api,bmc-proxy,unbound,
#                       unbound-exporter  (default: all).
#   --skip-base         Don't (re)build build-container-localdev if present.
#   --tag TAG           Tag for api/bmc-proxy images (default: localdev).
#   --no-cache          Pass --no-cache to docker build.
#   --save-dir DIR      `docker save` each built image as a .tar.gz into DIR.
#   -h | --help         Show this help.
#
# Env overrides: SQUID_PROXY, NICO_NO_PROXY (no_proxy list),
#   UNBOUND_VERSION (1.20.0), EXPORTER_REF (v0.4.6),
#   UNBOUND_TAG (1.20.0-local), EXPORTER_TAG (0.4.6-local).
# =============================================================================
set -euo pipefail

# ---- locate repo root -------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
if [[ ! -f "${REPO_ROOT}/Cargo.toml" ]]; then
  # Fall back to git toplevel if the script was copied elsewhere.
  REPO_ROOT="$(git -C "${SCRIPT_DIR}" rev-parse --show-toplevel 2>/dev/null || echo "${REPO_ROOT}")"
fi

# ---- defaults ---------------------------------------------------------------
SQUID_PROXY="${SQUID_PROXY:-}"
FORCE_NO_PROXY=0
ONLY=""
SKIP_BASE=0
TAG="localdev"
NO_CACHE=""
SAVE_DIR=""
NO_PROXY_LIST="${NICO_NO_PROXY:-localhost,127.0.0.1,::1}"

UNBOUND_VERSION="${UNBOUND_VERSION:-1.20.0}"
EXPORTER_REF="${EXPORTER_REF:-v0.4.6}"
UNBOUND_TAG="${UNBOUND_TAG:-1.20.0-local}"
EXPORTER_TAG="${EXPORTER_TAG:-0.4.6-local}"

# ---- colors / logging -------------------------------------------------------
if [[ -t 1 ]]; then
  C_B=$'\033[1m'; C_R=$'\033[0m'; C_G=$'\033[32m'; C_Y=$'\033[33m'; C_RED=$'\033[31m'; C_BL=$'\033[34m'
else
  C_B=""; C_R=""; C_G=""; C_Y=""; C_RED=""; C_BL=""
fi
log()  { printf '%s[INFO]%s %s\n'  "$C_BL"  "$C_R" "$*"; }
ok()   { printf '%s[ OK ]%s %s\n'  "$C_G"   "$C_R" "$*"; }
warn() { printf '%s[WARN]%s %s\n'  "$C_Y"   "$C_R" "$*"; }
err()  { printf '%s[FAIL]%s %s\n'  "$C_RED" "$C_R" "$*" >&2; }
hdr()  { printf '\n%s===== %s =====%s\n' "$C_B" "$*" "$C_R"; }
die()  { err "$*"; exit 1; }

usage() { sed -n '2,60p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0; }

# ---- arg parsing ------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --squid-proxy) SQUID_PROXY="${2:-}"; shift 2 ;;
    --no-proxy)    FORCE_NO_PROXY=1; shift ;;
    --only)        ONLY="${2:-}"; shift 2 ;;
    --skip-base)   SKIP_BASE=1; shift ;;
    --tag)         TAG="${2:-}"; shift 2 ;;
    --no-cache)    NO_CACHE="--no-cache"; shift ;;
    --save-dir)    SAVE_DIR="${2:-}"; shift 2 ;;
    -h|--help)     usage ;;
    *) die "unknown option: $1 (use --help)" ;;
  esac
done

[[ "${FORCE_NO_PROXY}" == "1" ]] && SQUID_PROXY=""

# ---- preflight --------------------------------------------------------------
command -v docker >/dev/null 2>&1 || die "docker not found — install Docker first."
docker info >/dev/null 2>&1 || die "cannot talk to the Docker daemon (is it running / are you in the docker group?)."
export DOCKER_BUILDKIT=1   # service Dockerfiles use RUN --mount=type=cache

# Detect image-name prefix (carbide-* vs nico-*) from the helm charts present.
if   [[ -d "${REPO_ROOT}/helm/charts/nico-api"    ]]; then PREFIX="nico"
elif [[ -d "${REPO_ROOT}/helm/charts/carbide-api" ]]; then PREFIX="carbide"
else PREFIX="carbide"; fi

# Choose the services Dockerfile: prefer the all-in-one image if present.
SERVICES_DF=""
NEED_RUNTIME_BASE=0
if   [[ -f "${REPO_ROOT}/dev/deployment/devspace/Dockerfile.all-services" ]]; then
  SERVICES_DF="dev/deployment/devspace/Dockerfile.all-services"; NEED_RUNTIME_BASE=1
elif [[ -f "${REPO_ROOT}/dev/deployment/devspace/Dockerfile.api" ]]; then
  SERVICES_DF="dev/deployment/devspace/Dockerfile.api"
fi

# ---- proxy build-args -------------------------------------------------------
# Predefined proxy args (apt/cargo/curl honor these) go to EVERY build.
# SQUID_PROXY goes only to Dockerfiles that declare it (added per-call).
PROXY_ARGS=()
if [[ -n "${SQUID_PROXY}" ]]; then
  PROXY_ARGS=(
    --build-arg "http_proxy=${SQUID_PROXY}"
    --build-arg "https_proxy=${SQUID_PROXY}"
    --build-arg "HTTP_PROXY=${SQUID_PROXY}"
    --build-arg "HTTPS_PROXY=${SQUID_PROXY}"
    --build-arg "no_proxy=${NO_PROXY_LIST}"
    --build-arg "NO_PROXY=${NO_PROXY_LIST}"
  )
fi
squid_arg() { [[ -n "${SQUID_PROXY}" ]] && printf -- '--build-arg\nSQUID_PROXY=%s\n' "${SQUID_PROXY}"; }

# ---- build helpers ----------------------------------------------------------
declare -a RESULTS=()
image_exists() { docker image inspect "$1" >/dev/null 2>&1; }

# dbuild <pretty-name> <image:tag> <dockerfile> <context> [extra build args...]
dbuild() {
  local name="$1" image="$2" df="$3" ctx="$4"; shift 4
  local extra=("$@")
  [[ -f "${REPO_ROOT}/${df}" ]] || { warn "skip ${name}: ${df} not found"; RESULTS+=("SKIP  ${name} (no ${df})"); return 0; }
  hdr "Building ${name} -> ${image}"
  log "dockerfile=${df} context=${ctx} proxy=${SQUID_PROXY:-<none>}"
  local start; start=$(date +%s)
  if ( cd "${REPO_ROOT}" && docker build ${NO_CACHE} \
          "${PROXY_ARGS[@]}" "${extra[@]}" \
          -t "${image}" -f "${df}" "${ctx}" ); then
    local dur=$(( $(date +%s) - start ))
    ok "${name} built in ${dur}s"
    RESULTS+=("OK    ${name} -> ${image} (${dur}s)")
    [[ -n "${SAVE_DIR}" ]] && save_image "${image}"
  else
    RESULTS+=("FAIL  ${name} -> ${image}")
    err "${name} build FAILED"
    return 1
  fi
}

save_image() {
  local image="$1"
  mkdir -p "${SAVE_DIR}"
  local fn; fn="$(echo "${image}" | tr '/:' '__').tar.gz"
  log "saving ${image} -> ${SAVE_DIR}/${fn}"
  docker save "${image}" | gzip > "${SAVE_DIR}/${fn}"
}

want() { [[ -z "${ONLY}" ]] && return 0; [[ ",${ONLY}," == *",$1,"* ]]; }

ensure_base() {
  if image_exists build-container-localdev && [[ "${SKIP_BASE}" == "1" ]]; then
    log "build-container-localdev present — skipping (--skip-base)"; return 0
  fi
  if image_exists build-container-localdev && ! want base; then
    return 0   # present and not explicitly requested
  fi
  dbuild "build-container (base)" "build-container-localdev" \
    "dev/docker/Dockerfile.build-container-x86_64" "."
}

ensure_runtime_base() {
  [[ "${NEED_RUNTIME_BASE}" == "1" ]] || return 0
  if image_exists carbide-runtime-base && ! want runtime-base; then return 0; fi
  mapfile -t sq < <(squid_arg)
  dbuild "runtime-base" "carbide-runtime-base" \
    "dev/deployment/devspace/Dockerfile.runtime-base" "." "${sq[@]}"
}

# ---- plan summary -----------------------------------------------------------
hdr "build-nico-images.sh"
log "repo root     : ${REPO_ROOT}"
log "image prefix  : ${PREFIX}"
log "services file : ${SERVICES_DF:-<none found>}"
log "tag           : ${TAG}"
log "proxy         : ${SQUID_PROXY:-<none>}"
log "targets       : ${ONLY:-all}"
[[ -n "${SAVE_DIR}" ]] && log "save dir      : ${SAVE_DIR}"

# ---- build sequence ---------------------------------------------------------
mapfile -t SQ < <(squid_arg)

# base is a dependency of api + bmc-proxy; build/ensure it when needed.
if want base || want api || want bmc-proxy; then
  ensure_base
fi

if want api; then
  ensure_runtime_base
  [[ -n "${SERVICES_DF}" ]] || die "no services Dockerfile found"
  dbuild "${PREFIX}-api (all services)" "${PREFIX}-api:${TAG}" \
    "${SERVICES_DF}" "." "${SQ[@]}"
fi

if want bmc-proxy; then
  dbuild "${PREFIX}-bmc-proxy" "${PREFIX}-bmc-proxy:${TAG}" \
    "dev/deployment/devspace/Dockerfile.bmc-proxy" "." "${SQ[@]}"
fi

if want unbound; then
  dbuild "unbound" "forge/unbound:${UNBOUND_TAG}" \
    "dev/docker/unbound/Dockerfile" "dev/docker/unbound" \
    "${SQ[@]}" --build-arg "UNBOUND_VERSION=${UNBOUND_VERSION}"
fi

if want unbound-exporter; then
  dbuild "unbound_exporter" "forge/unbound_exporter:${EXPORTER_TAG}" \
    "dev/docker/unbound-exporter/Dockerfile" "dev/docker/unbound-exporter" \
    "${SQ[@]}" --build-arg "EXPORTER_REF=${EXPORTER_REF}"
fi

# ---- summary ----------------------------------------------------------------
hdr "Summary"
rc=0
for line in "${RESULTS[@]}"; do
  case "$line" in
    OK*)   printf '%s  %s%s\n' "$C_G"  "$line" "$C_R" ;;
    SKIP*) printf '%s  %s%s\n' "$C_Y"  "$line" "$C_R" ;;
    FAIL*) printf '%s  %s%s\n' "$C_RED" "$line" "$C_R"; rc=1 ;;
  esac
done

echo
log "Local images:"
docker images --filter 'reference=*-api' --filter 'reference=*-bmc-proxy' \
  --filter 'reference=forge/unbound*' --filter 'reference=build-container-localdev' \
  --filter 'reference=carbide-runtime-base' \
  --format 'table {{.Repository}}:{{.Tag}}\t{{.Size}}\t{{.CreatedSince}}' 2>/dev/null || true

[[ $rc -eq 0 ]] && ok "All requested images built." || err "One or more images FAILED to build."
exit $rc
