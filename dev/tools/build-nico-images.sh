#!/usr/bin/env bash
# =============================================================================
# build-nico-images.sh
# -----------------------------------------------------------------------------
# Standalone, BUILD-ONLY automation for every Docker image NICo deploys.
# No Kubernetes, no kubeadm, no helm — just `docker`. Drop this on a fresh
# Ubuntu (or any Linux) VM that has Docker installed and run it to validate
# that all images build, with OR without a Squid proxy.
#
# Fresh VM in one shot (--clone)
# ------------------------------
# You do NOT have to clone the repo by hand. Copy just this file onto the VM
# and let it fetch the source for you (HTTPS clone needs a GitHub PAT):
#
#   # non-interactive (recommended) — PAT supplied via env, never persisted:
#   GITHUB_USER=mkumarbp GITHUB_TOKEN=<PAT> ./build-nico-images.sh --clone
#
#   # interactive — git prompts for username + PAT (like a manual `git clone`):
#   ./build-nico-images.sh --clone
#
# --clone clones $NICO_REPO_URL (branch $NICO_REPO_BRANCH) into $NICO_CLONE_DIR,
# checks out the branch, copies THIS script into <repo>/dev/tools (in case the
# branch doesn't ship it yet), then builds from the repo root. You don't have to
# move the file or cd into dev/tools yourself. If you run the script from inside
# an already-checked-out repo, omit --clone and it just builds.
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
# If no --squid-proxy is given the script auto-detects one from the environment
# (HTTPS_PROXY/HTTP_PROXY) AND, if not exported there, from /etc/environment —
# so proxy-only VMs work out of the box even from a non-login shell. When a proxy
# is in play it passes the predefined http_proxy/https_proxy build-args (honored
# by apt/cargo/curl) to EVERY build, plus --build-arg SQUID_PROXY=<url> for the
# service Dockerfiles that consume it. Proxy values are not baked into images.
#
# IMPORTANT: build-args only affect RUN steps. Base-image pulls (`FROM ...`,
# e.g. rust:1.95.0-slim-bookworm) are performed by the Docker DAEMON, which must
# be proxy-configured separately or builds fail at "load metadata" with an i/o
# timeout to auth.docker.io. Pass --configure-docker-proxy to set this up: it
# detects snap-vs-systemd Docker (snap IGNORES systemd drop-ins!), applies the
# right config, restarts the daemon, and VERIFIES the proxy actually took effect.
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
#   --clone             Clone/refresh the repo before building (fresh VM).
#   --repo-url URL      Git URL to clone (default: the ncx-core HTTPS URL).
#   --branch BRANCH     Branch to check out  (default: ncx-core-dev-v0.10.0).
#   --clone-dir DIR     Where to clone        (default: $HOME/<repo-name>).
#   --git-user USER     GitHub username for the HTTPS clone (or $GITHUB_USER).
#   --squid-proxy URL   Route all builds through this HTTP proxy (else auto-
#                       detected from HTTPS_PROXY/HTTP_PROXY in the environment).
#   --no-proxy          Force no proxy (ignores SQUID_PROXY + env proxies).
#   --configure-docker-proxy  Write /etc/systemd/system/docker.service.d/
#                       http-proxy.conf for the proxy and restart dockerd so
#                       base-image pulls work (needs root/sudo).
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
#   UNBOUND_TAG (1.20.0-local), EXPORTER_TAG (0.4.6-local),
#   GITHUB_USER, GITHUB_TOKEN (PAT for --clone; or GIT_PAT),
#   NICO_REPO_URL, NICO_REPO_BRANCH, NICO_CLONE_DIR,
#   NICO_CONFIGURE_DOCKER_PROXY (=1 like --configure-docker-proxy).
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
NO_PROXY_LIST="${NICO_NO_PROXY:-${NO_PROXY:-${no_proxy:-localhost,127.0.0.1,::1}}}"
CONFIGURE_DOCKER_PROXY="${NICO_CONFIGURE_DOCKER_PROXY:-0}"

UNBOUND_VERSION="${UNBOUND_VERSION:-1.20.0}"
EXPORTER_REF="${EXPORTER_REF:-v0.4.6}"
UNBOUND_TAG="${UNBOUND_TAG:-1.20.0-local}"
EXPORTER_TAG="${EXPORTER_TAG:-0.4.6-local}"

# ---- fresh-VM clone/bootstrap defaults --------------------------------------
DO_CLONE=0
REPO_URL="${NICO_REPO_URL:-https://github.com/nutanix-core/nurametal-ntnx-ncx-core.git}"
REPO_BRANCH="${NICO_REPO_BRANCH:-ncx-core-dev-v0.10.0}"
CLONE_DIR="${NICO_CLONE_DIR:-}"      # default derived from REPO_URL after parsing
GIT_USER="${GITHUB_USER:-}"
GIT_TOKEN="${GITHUB_TOKEN:-${GIT_PAT:-}}"

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

usage() { awk 'NR>=2 && /^#/ {sub(/^# ?/,""); print; next} NR>=2 {exit}' "${BASH_SOURCE[0]}"; exit 0; }

# ---- arg parsing ------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --clone)       DO_CLONE=1; shift ;;
    --repo-url)    REPO_URL="${2:?}"; shift 2 ;;
    --branch)      REPO_BRANCH="${2:?}"; shift 2 ;;
    --clone-dir)   CLONE_DIR="${2:?}"; shift 2 ;;
    --git-user)    GIT_USER="${2:?}"; shift 2 ;;
    --squid-proxy) SQUID_PROXY="${2:-}"; shift 2 ;;
    --no-proxy)    FORCE_NO_PROXY=1; shift ;;
    --configure-docker-proxy) CONFIGURE_DOCKER_PROXY=1; shift ;;
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

# Auto-detect a proxy from the environment when none was passed. On proxy-only
# VMs this means the build "just works" without remembering --squid-proxy.
# We look in two places, because the env var is frequently set in
# /etc/environment but only loaded at login — a script run from cron, sudo, a
# fresh non-login shell, etc. often won't have it exported.
proxy_from_etc_environment() {
  [[ -r /etc/environment ]] || return 0
  local line val
  for key in HTTPS_PROXY https_proxy HTTP_PROXY http_proxy; do
    line="$(grep -iE "^[[:space:]]*${key}=" /etc/environment 2>/dev/null | tail -1)" || true
    if [[ -n "${line}" ]]; then
      val="${line#*=}"; val="${val%\"}"; val="${val#\"}"   # strip optional quotes
      [[ -n "${val}" ]] && { printf '%s' "${val}"; return 0; }
    fi
  done
}
if [[ -z "${SQUID_PROXY}" && "${FORCE_NO_PROXY}" != "1" ]]; then
  SQUID_PROXY="${HTTPS_PROXY:-${https_proxy:-${HTTP_PROXY:-${http_proxy:-}}}}"
  [[ -n "${SQUID_PROXY}" ]] && PROXY_AUTODETECTED=1
  if [[ -z "${SQUID_PROXY}" ]]; then
    SQUID_PROXY="$(proxy_from_etc_environment)"
    [[ -n "${SQUID_PROXY}" ]] && PROXY_AUTODETECTED=2   # 2 = from /etc/environment
  fi
fi
PROXY_AUTODETECTED="${PROXY_AUTODETECTED:-0}"
# If NO_PROXY wasn't in the shell env either, try to lift it from /etc/environment.
if [[ "${NO_PROXY_LIST}" == "localhost,127.0.0.1,::1" && -r /etc/environment ]]; then
  _np="$(grep -iE '^[[:space:]]*NO_PROXY=' /etc/environment 2>/dev/null | tail -1 || true)"
  if [[ -n "${_np}" ]]; then _np="${_np#*=}"; _np="${_np%\"}"; _np="${_np#\"}"; NO_PROXY_LIST="${_np:-${NO_PROXY_LIST}}"; fi
fi

# Derive a default clone dir from the repo URL (e.g. nurametal-ntnx-ncx-core).
if [[ -z "${CLONE_DIR}" ]]; then
  _repo_name="${REPO_URL##*/}"; _repo_name="${_repo_name%.git}"
  CLONE_DIR="${HOME}/${_repo_name:-ncx-core}"
fi

# ---- fresh-VM prerequisite: clone + checkout --------------------------------
# A valid repo root has Cargo.toml and the devspace build assets.
repo_looks_valid() { [[ -f "${REPO_ROOT}/Cargo.toml" && -d "${REPO_ROOT}/dev/deployment/devspace" ]]; }

bootstrap_repo() {
  hdr "Prerequisite: clone repo + checkout branch"
  command -v git >/dev/null 2>&1 || \
    die "git not found — install it first (e.g. sudo apt-get update && sudo apt-get install -y git)."

  # Optionally inject the PAT for a non-interactive HTTPS clone, then scrub it
  # from the saved remote so the token is never persisted in .git/config.
  local clean_url="${REPO_URL}" auth_url="${REPO_URL}"
  if [[ -n "${GIT_TOKEN}" && "${REPO_URL}" == http* ]]; then
    local host_path="${REPO_URL#http://}"; host_path="${host_path#https://}"
    auth_url="https://${GIT_USER:-git}:${GIT_TOKEN}@${host_path}"
  fi

  if [[ -d "${CLONE_DIR}/.git" ]]; then
    log "repo already present at ${CLONE_DIR} — fetching ${REPO_BRANCH}"
    git -C "${CLONE_DIR}" remote set-url origin "${auth_url}"
    git -C "${CLONE_DIR}" fetch origin "${REPO_BRANCH}"
    git -C "${CLONE_DIR}" checkout "${REPO_BRANCH}" 2>/dev/null \
      || git -C "${CLONE_DIR}" checkout -B "${REPO_BRANCH}" --track "origin/${REPO_BRANCH}"
    git -C "${CLONE_DIR}" pull --ff-only origin "${REPO_BRANCH}" || true
    git -C "${CLONE_DIR}" remote set-url origin "${clean_url}"
  else
    log "cloning ${clean_url} (branch ${REPO_BRANCH}) into ${CLONE_DIR}"
    [[ -n "${GIT_TOKEN}" ]] || warn "no GITHUB_TOKEN/PAT set — git will prompt for username + PAT"
    git clone --branch "${REPO_BRANCH}" "${auth_url}" "${CLONE_DIR}"
    [[ -n "${GIT_TOKEN}" ]] && git -C "${CLONE_DIR}" remote set-url origin "${clean_url}"
  fi

  REPO_ROOT="$(cd "${CLONE_DIR}" && pwd)"
  ok "repo ready at ${REPO_ROOT} (branch: $(git -C "${REPO_ROOT}" rev-parse --abbrev-ref HEAD 2>/dev/null || echo '?'))"

  # Place this script under <repo>/dev/tools so it lives in the conventional
  # spot (the branch may not ship it yet). Building works regardless of where
  # the script physically sits — we always build from ${REPO_ROOT} — so there's
  # no need to cd into dev/tools or re-run.
  local src dest_dir dest
  src="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
  dest_dir="${REPO_ROOT}/dev/tools"
  dest="${dest_dir}/build-nico-images.sh"
  mkdir -p "${dest_dir}"
  if [[ "${src}" -ef "${dest}" ]]; then
    : # already running the in-repo copy
  elif [[ -f "${dest}" ]]; then
    log "in-repo copy already present: ${dest}"
  else
    cp "${src}" "${dest}" && chmod +x "${dest}"
    ok "installed script -> ${dest}"
  fi
  log "future runs:  cd ${REPO_ROOT}/dev/tools && ./build-nico-images.sh"
}

if [[ "${DO_CLONE}" == "1" ]]; then
  bootstrap_repo
elif ! repo_looks_valid; then
  err "this does not look like the ncx-core repo (REPO_ROOT=${REPO_ROOT})."
  cat >&2 <<EOF

Run the script from inside a checked-out repo, OR let it fetch one for you:

  # one-shot, non-interactive (recommended) — PAT via env, never persisted:
  GITHUB_USER=<you> GITHUB_TOKEN=<PAT> ${0##*/} --clone

  # or interactive — git prompts for username + PAT:
  ${0##*/} --clone

Clone target (--clone-dir) defaults to : ${CLONE_DIR}
Branch (--branch) defaults to          : ${REPO_BRANCH}
EOF
  exit 1
fi

# ---- preflight --------------------------------------------------------------
command -v docker >/dev/null 2>&1 || die "docker not found — install Docker first."
docker info >/dev/null 2>&1 || die "cannot talk to the Docker daemon (is it running / are you in the docker group?)."
export DOCKER_BUILDKIT=1   # service Dockerfiles use RUN --mount=type=cache

SUDO=""; [[ "$(id -u)" -ne 0 ]] && command -v sudo >/dev/null 2>&1 && SUDO="sudo"

# Is Docker installed via snap? snap IGNORES /etc/systemd/system/docker.service.d
# drop-ins entirely, so the proxy must be set with `snap set docker proxy.*`.
docker_is_snap() {
  [[ "$(command -v docker)" == /snap/* ]] && return 0
  command -v snap >/dev/null 2>&1 && snap list docker >/dev/null 2>&1
}
daemon_proxy_now() { docker info --format '{{.HTTPProxy}}{{.HTTPSProxy}}' 2>/dev/null | tr -d '[:space:]'; }

# Point the Docker DAEMON at the proxy (snap or systemd), restart it, and VERIFY
# the proxy actually took effect — a silent no-op here is exactly what made the
# "FROM rust:..." pull keep timing out.
configure_docker_proxy() {
  hdr "Configuring Docker daemon proxy -> ${SQUID_PROXY}"
  if docker_is_snap; then
    log "Docker is a snap — configuring via 'snap set docker proxy.*'"
    ${SUDO} snap set docker proxy.http="${SQUID_PROXY}" proxy.https="${SQUID_PROXY}"
    ${SUDO} snap restart docker || true
  else
    local conf="/etc/systemd/system/docker.service.d/http-proxy.conf"
    log "Docker is systemd-managed — writing ${conf}"
    ${SUDO} mkdir -p "$(dirname "${conf}")"
    ${SUDO} tee "${conf}" >/dev/null <<EOF
[Service]
Environment="HTTP_PROXY=${SQUID_PROXY}"
Environment="HTTPS_PROXY=${SQUID_PROXY}"
Environment="NO_PROXY=${NO_PROXY_LIST}"
EOF
    ${SUDO} systemctl daemon-reload
    ${SUDO} systemctl restart docker
  fi
  local i; for i in $(seq 1 15); do docker info >/dev/null 2>&1 && break; sleep 1; done

  local now; now="$(daemon_proxy_now)"
  if [[ -z "${now}" ]]; then
    err "Docker daemon STILL reports no proxy after configuration + restart."
    cat >&2 <<EOF

Diagnose with:
  command -v docker            # $(command -v docker)$(docker_is_snap && echo '  (snap install)')
  docker info | grep -i proxy
  systemctl cat docker | grep -i proxy
  sudo cat /proc/\$(pgrep -nx dockerd)/environ | tr '\0' '\n' | grep -i proxy

If Docker is a snap, systemd drop-ins are ignored — use:
  sudo snap set docker proxy.http=${SQUID_PROXY} proxy.https=${SQUID_PROXY}
  sudo snap restart docker
EOF
    die "could not enable the Docker daemon proxy."
  fi
  ok "Docker daemon proxy active: ${now}"
}

# CRITICAL: --build-arg proxies only affect RUN steps, NOT `FROM`/image pulls.
# Base-image pulls (e.g. rust:1.95.0-slim-bookworm) are done by the daemon, so
# on a proxy-only host the daemon itself must be proxy-configured or every build
# fails at "load metadata" with an i/o timeout to auth.docker.io / registry-1.
if [[ "${CONFIGURE_DOCKER_PROXY}" == "1" && -z "${SQUID_PROXY}" ]]; then
  die "--configure-docker-proxy given but no proxy found in env or /etc/environment — pass --squid-proxy URL."
fi
if [[ -n "${SQUID_PROXY}" ]]; then
  case "${PROXY_AUTODETECTED}" in
    1) log "proxy auto-detected from shell environment: ${SQUID_PROXY}" ;;
    2) log "proxy auto-detected from /etc/environment: ${SQUID_PROXY}" ;;
  esac
  daemon_proxy="$(daemon_proxy_now)"
  if [[ "${CONFIGURE_DOCKER_PROXY}" == "1" ]]; then
    configure_docker_proxy            # explicit request: always (re)configure + verify
  elif [[ -z "${daemon_proxy}" ]]; then
    warn "Docker DAEMON has no proxy configured, but a proxy is in use (${SQUID_PROXY})."
    warn "Base-image pulls (FROM ...) will TIME OUT — build-arg proxies do NOT cover image pulls."
    cat >&2 <<EOF

Fix it one of two ways, then re-run:

  # (a) let this script configure + restart the daemon for you (handles snap too):
  ${0##*/} --configure-docker-proxy [other flags...]

  # (b) systemd Docker — do it manually:
  sudo mkdir -p /etc/systemd/system/docker.service.d
  sudo tee /etc/systemd/system/docker.service.d/http-proxy.conf >/dev/null <<CONF
  [Service]
  Environment="HTTP_PROXY=${SQUID_PROXY}"
  Environment="HTTPS_PROXY=${SQUID_PROXY}"
  Environment="NO_PROXY=${NO_PROXY_LIST}"
  CONF
  sudo systemctl daemon-reload && sudo systemctl restart docker

  # (b') snap Docker — systemd drop-ins are IGNORED, use:
  sudo snap set docker proxy.http=${SQUID_PROXY} proxy.https=${SQUID_PROXY}
  sudo snap restart docker

EOF
    die "Docker daemon proxy not configured (see above)."
  else
    log "Docker daemon proxy already configured: ${daemon_proxy}"
  fi
fi

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
