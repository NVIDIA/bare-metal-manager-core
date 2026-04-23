#!/usr/bin/env bash
# =============================================================================
# preflight.sh — pre-flight checks for setup.sh
#
# Run standalone before setup.sh to catch configuration issues early:
#   source ./preflight.sh
#
# Also sourced automatically at the start of every setup.sh run.
#
# Checks (in order — fails fast so the most actionable issues appear first):
#   1. Environment variables    — presence and format
#   2. Required tools           — helm, helmfile, kubectl, jq, ssh-keygen
#   3. values/metallb-config.yaml — YAML, pools, advertisement mode, ASNs
#   4. Cluster reachability     — kubectl can reach the API server
#   5. Node resources           — at least 3 schedulable (Ready + untainted) nodes
#   6. MetalLB BGPPeer nodes    — hostnames in config exist in the cluster
#   7. Per-node checks          — kernel params (sysctl) and DNS on every node
#   8. Registry connectivity    — registry host is reachable over HTTPS
#   9. NCX REST repo            — found locally or offer to clone from GitHub
#
# Configurable:
#   PREFLIGHT_CHECK_IMAGE — image used for per-node pod checks (default: busybox:1.36)
#                           Override for air-gapped clusters:
#                           export PREFLIGHT_CHECK_IMAGE=my-registry.example.com/busybox:1.36
#
# Exit codes:
#   0 — all checks passed (or user chose to continue despite issues)
#   1 — hard failure or user declined to continue
# =============================================================================

# ---------------------------------------------------------------------------
# 0. Shell compatibility — must run under bash 3.2+ (macOS ships 3.2).
#    Catches `sh preflight.sh` / dash / ancient bash before cryptic errors.
# ---------------------------------------------------------------------------
if [ -z "${BASH_VERSION:-}" ]; then
    echo "ERROR: this script must be run under bash (not sh/dash/zsh)." >&2
    echo "  Try: bash ./setup.sh   (or source it from a bash shell)" >&2
    exit 1
fi
if [ "${BASH_VERSINFO[0]}" -lt 3 ] || \
   { [ "${BASH_VERSINFO[0]}" -eq 3 ] && [ "${BASH_VERSINFO[1]}" -lt 2 ]; }; then
    echo "ERROR: bash 3.2+ required (you have ${BASH_VERSION})." >&2
    echo "  On macOS: /bin/bash is 3.2 and works. If you're on something older," >&2
    echo "  install a newer bash: brew install bash" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Detect whether we are being sourced or executed directly.
# return in a function always returns from the function, not the script —
# so we use _SOURCED inline at every exit point instead.
_SOURCED=false
[[ "${BASH_SOURCE[0]}" != "${0}" ]] && _SOURCED=true

ERRORS=()
WARNINGS=()

# ---------------------------------------------------------------------------
# Cleanup: remove any temp pods created by per-node checks
# ---------------------------------------------------------------------------
_PREFLIGHT_PODS=()
_PREFLIGHT_NS="kube-system"

_cleanup_preflight_pods() {
    [[ ${#_PREFLIGHT_PODS[@]} -eq 0 ]] && return
    kubectl delete pod "${_PREFLIGHT_PODS[@]}" \
        -n "${_PREFLIGHT_NS}" --ignore-not-found --wait=false >/dev/null 2>&1 || true
}

# ---------------------------------------------------------------------------
# 1. Environment variables — presence
# ---------------------------------------------------------------------------
[[ -z "${REGISTRY_PULL_SECRET:-}" ]] && \
    ERRORS+=("REGISTRY_PULL_SECRET is not set  (your registry pull secret / API key)")

[[ -z "${NCX_IMAGE_REGISTRY:-}" ]] && \
    ERRORS+=("NCX_IMAGE_REGISTRY is not set    (container registry, e.g. my-registry.example.com/ncx)")

[[ -z "${NCX_CORE_IMAGE_TAG:-}" ]] && \
    ERRORS+=("NCX_CORE_IMAGE_TAG is not set    (NCX Core image tag, e.g. v2025.12.30)")

[[ -z "${NCX_REST_IMAGE_TAG:-}" ]] && \
    ERRORS+=("NCX_REST_IMAGE_TAG is not set    (NCX REST image tag, e.g. v1.0.4)")

# Environment variables — format validation
_UUID_RE='^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'

# NCX_IMAGE_REGISTRY must not include a protocol prefix
if [[ -n "${NCX_IMAGE_REGISTRY:-}" ]] && [[ "${NCX_IMAGE_REGISTRY}" =~ ^https?:// ]]; then
    ERRORS+=("NCX_IMAGE_REGISTRY must not include a protocol prefix — remove 'https://' or 'http://'")
fi

# Image tags should look like version tags (v<semver>)
for _tag_var in NCX_CORE_IMAGE_TAG NCX_REST_IMAGE_TAG; do
    _tag_val="${!_tag_var:-}"
    if [[ -n "${_tag_val}" && ! "${_tag_val}" =~ ^v[0-9] ]]; then
        WARNINGS+=("${_tag_var}='${_tag_val}' — expected a version tag starting with 'v' (e.g. v2025.12.30)")
    fi
done

# NCX_SITE_UUID must be a valid UUID if set (used as Temporal namespace + CLUSTER_ID)
if [[ -n "${NCX_SITE_UUID:-}" ]]; then
    if [[ ! "${NCX_SITE_UUID}" =~ ${_UUID_RE} ]]; then
        ERRORS+=("NCX_SITE_UUID='${NCX_SITE_UUID}' is not a valid UUID — the site-agent will fatal on startup (generate one with: python3 -c 'import uuid; print(uuid.uuid4())')")
    fi
fi

# REGISTRY_PULL_SECRET should not be an obvious placeholder
if [[ -n "${REGISTRY_PULL_SECRET:-}" ]]; then
    if [[ "${REGISTRY_PULL_SECRET}" =~ ^(<|your|placeholder|changeme|xxx|TODO) ]]; then
        WARNINGS+=("REGISTRY_PULL_SECRET looks like a placeholder value — set it to your actual registry pull secret")
    fi
fi

# KUBECONFIG file must exist if explicitly set
if [[ -n "${KUBECONFIG:-}" && ! -f "${KUBECONFIG}" ]]; then
    ERRORS+=("KUBECONFIG='${KUBECONFIG}' does not exist — check the path to your cluster kubeconfig")
fi

# ---------------------------------------------------------------------------
# 2. Required tools
# ---------------------------------------------------------------------------
for _tool in helm helmfile kubectl jq ssh-keygen; do
    command -v "${_tool}" &>/dev/null || \
        WARNINGS+=("'${_tool}' not found in PATH — install it before running setup.sh")
done

# ---------------------------------------------------------------------------
# 3. values/metallb-config.yaml — static checks (no cluster access needed)
# ---------------------------------------------------------------------------
_METALLB_CFG="${SCRIPT_DIR}/values/metallb-config.yaml"

if [[ ! -f "${_METALLB_CFG}" ]]; then
    ERRORS+=("values/metallb-config.yaml not found — restore from git and fill in your site config")
else
    # YAML syntax — kubectl dry-run with validate=false, but filter out
    # "no matches for kind" errors (MetalLB CRDs are not installed yet, that's expected).
    if command -v kubectl &>/dev/null; then
        _yaml_out="$(kubectl apply --dry-run=client --validate=false \
            -f "${_METALLB_CFG}" 2>&1)" || true
        _yaml_real_errors="$(echo "${_yaml_out}" | \
            grep -vE 'no matches for kind|resource mapping not found|ensure CRDs are installed' || true)"
        if [[ -n "${_yaml_real_errors}" ]] && \
           echo "${_yaml_out}" | grep -qvE 'no matches for kind|resource mapping not found|ensure CRDs are installed'; then
            ERRORS+=("values/metallb-config.yaml: YAML parse error — ${_yaml_real_errors}")
        fi
    fi

    # At least one active IPAddressPool
    if ! grep -qE '^kind: IPAddressPool' "${_METALLB_CFG}"; then
        ERRORS+=("values/metallb-config.yaml: no IPAddressPool defined")
    fi

    # Advertisement mode consistency
    _n_bgp_peer=$(grep -cE '^kind: BGPPeer'          "${_METALLB_CFG}" || true)
    _n_bgp_adv=$( grep -cE '^kind: BGPAdvertisement' "${_METALLB_CFG}" || true)
    _n_l2_adv=$(  grep -cE '^kind: L2Advertisement'  "${_METALLB_CFG}" || true)

    if [[ "${_n_bgp_peer}" -gt 0 && "${_n_l2_adv}" -gt 0 ]]; then
        ERRORS+=("values/metallb-config.yaml: BGPPeer and L2Advertisement are both active — choose one mode only")
    elif [[ "${_n_bgp_peer}" -eq 0 && "${_n_l2_adv}" -eq 0 ]]; then
        ERRORS+=("values/metallb-config.yaml: no advertisement mode configured — add BGPPeer+BGPAdvertisement (BGP) or L2Advertisement (L2)")
    elif [[ "${_n_bgp_peer}" -gt 0 && "${_n_bgp_adv}" -eq 0 ]]; then
        ERRORS+=("values/metallb-config.yaml: BGPPeer defined but no BGPAdvertisement — VIPs will not be announced")
    fi

    # BGP ASNs must be non-zero integers
    while IFS= read -r _line; do
        if [[ "${_line}" =~ ^[[:space:]]*(my|peer)ASN:[[:space:]]*([0-9]+) ]]; then
            [[ "${BASH_REMATCH[2]}" -eq 0 ]] && \
                ERRORS+=("values/metallb-config.yaml: ASN value is 0 — set a valid BGP ASN")
        fi
    done < "${_METALLB_CFG}"
fi

# ---------------------------------------------------------------------------
# 4–7. Cluster checks — all gated on kubectl being available and reachable
# ---------------------------------------------------------------------------
_CLUSTER_REACHABLE=false

if command -v kubectl &>/dev/null; then
    if ! kubectl cluster-info >/dev/null 2>&1; then
        ERRORS+=("Cannot reach the Kubernetes cluster — check KUBECONFIG and cluster connectivity")
    else
        _CLUSTER_REACHABLE=true
    fi
fi

if [[ "${_CLUSTER_REACHABLE}" == "true" ]]; then

    # -----------------------------------------------------------------------
    # 5. Node resources — at least 3 schedulable nodes required
    # -----------------------------------------------------------------------
    _schedulable=$(kubectl get nodes -o json 2>/dev/null | jq -r '
        .items[] |
        select(
            (.status.conditions[] | select(.type == "Ready") | .status) == "True" and
            ((.spec.taints // []) |
             map(select(.effect == "NoSchedule" or .effect == "NoExecute")) |
             length) == 0
        ) | .metadata.name' | wc -l | tr -d '[:space:]')

    _total=$(kubectl get nodes --no-headers 2>/dev/null | wc -l | tr -d '[:space:]')

    if [[ "${_schedulable}" -lt 3 ]]; then
        ERRORS+=("Only ${_schedulable}/${_total} nodes are schedulable (Ready + untainted) — at least 3 required for HA Vault and Postgres")
    fi

    # -----------------------------------------------------------------------
    # 6. MetalLB BGPPeer node hostnames — verify they exist in this cluster
    #
    # Extracts node names listed under kubernetes.io/hostname in BGPPeer
    # nodeSelectors and checks each one against the actual cluster node list.
    # -----------------------------------------------------------------------
    if [[ -f "${_METALLB_CFG}" ]]; then
        _cluster_nodes=$(kubectl get nodes \
            -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)
        # Extract values listed after 'kubernetes.io/hostname' nodeSelector lines
        _peer_nodes=$(awk '
            /kubernetes\.io\/hostname/ { in_vals=1; next }
            in_vals && /operator:/ { in_vals=0 }
            in_vals && /^[[:space:]]*-[[:space:]]+[^-]/ {
                gsub(/^[[:space:]]*-[[:space:]]+/, "")
                gsub(/#.*$/, "")
                gsub(/[[:space:]]/, "")
                if (length > 0) print
            }
        ' "${_METALLB_CFG}")

        for _peer_node in ${_peer_nodes}; do
            if ! echo " ${_cluster_nodes} " | grep -qF " ${_peer_node} "; then
                WARNINGS+=("values/metallb-config.yaml: BGPPeer references node '${_peer_node}' which was not found in the cluster — run: kubectl get nodes")
            fi
        done
    fi

    # -----------------------------------------------------------------------
    # 7. Per-node checks — kernel parameters + DNS
    #
    # One pod per node using:
    #   hostPID: true      — lets nsenter reach host PID 1's namespaces
    #   privileged: true   — required for nsenter -n (network namespace entry)
    #
    # nsenter -t 1 -n reads sysctl values from the host's network namespace,
    # not the container's (which always has ip_forward=0 by default).
    # The DNS lookup runs in the container's own network namespace so it
    # uses cluster DNS (CoreDNS), not the host's /etc/resolv.conf.
    #
    # All pods are deleted on EXIT via trap regardless of outcome.
    # Override the check image for air-gapped clusters:
    #   export PREFLIGHT_CHECK_IMAGE=my-registry.example.com/busybox:1.36
    # -----------------------------------------------------------------------
    _CHECK_IMAGE="${PREFLIGHT_CHECK_IMAGE:-busybox:1.36}"
    _TS="$(date +%s)"
    _node_names=$(kubectl get nodes \
        -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)

    for _node in ${_node_names}; do
        # Lowercase via tr for portability (bash 3.2 on macOS lacks ${var,,}).
        _safe="$(printf '%s' "${_node}" | tr '[:upper:]' '[:lower:]')"
        _safe="${_safe//[^a-z0-9-]/-}"
        _safe="${_safe:0:40}"
        _pod="ncx-pf-${_TS}-${_safe}"
        _PREFLIGHT_PODS+=("${_pod}")

        kubectl apply -f - >/dev/null 2>&1 <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: ${_pod}
  namespace: ${_PREFLIGHT_NS}
  labels:
    ncx-preflight: "true"
spec:
  nodeName: ${_node}
  hostPID: true
  restartPolicy: Never
  tolerations:
  - operator: Exists
  containers:
  - name: check
    image: ${_CHECK_IMAGE}
    securityContext:
      privileged: true
    command:
    - sh
    - -c
    - |
      printf "NODE=${_node}\n"
      printf "bridge_nf=%s\n" "\$(nsenter -t 1 -n -- sysctl -n net.bridge.bridge-nf-call-iptables 2>/dev/null || echo MISSING)"
      printf "ip_forward=%s\n" "\$(nsenter -t 1 -n -- sysctl -n net.ipv4.ip_forward 2>/dev/null || echo MISSING)"
      nslookup kubernetes.default.svc.cluster.local >/dev/null 2>&1 \
        && printf "dns=ok\n" || printf "dns=FAIL\n"
    resources:
      requests:
        cpu: 10m
        memory: 16Mi
EOF
    done

    echo "Running per-node checks (sysctl, DNS) across ${#_PREFLIGHT_PODS[@]} node(s)..."

    # Wait up to 120s for all pods to reach Succeeded or Failed
    _deadline=$(( $(date +%s) + 120 ))
    while [[ $(date +%s) -lt "${_deadline}" ]]; do
        _pending=0
        for _pod in "${_PREFLIGHT_PODS[@]}"; do
            _phase=$(kubectl get pod "${_pod}" -n "${_PREFLIGHT_NS}" \
                -o jsonpath='{.status.phase}' 2>/dev/null || echo "Unknown")
            [[ "${_phase}" != "Succeeded" && "${_phase}" != "Failed" ]] && \
                (( _pending++ )) || true
        done
        [[ "${_pending}" -eq 0 ]] && break
        sleep 5
    done

    # Parse and report results
    for _pod in "${_PREFLIGHT_PODS[@]}"; do
        _logs=$(kubectl logs "${_pod}" -n "${_PREFLIGHT_NS}" 2>/dev/null || true)
        _node_label=$(echo "${_logs}" | grep '^NODE='       | cut -d= -f2-)
        _bridge_nf=$( echo "${_logs}" | grep '^bridge_nf='  | cut -d= -f2-)
        _ip_fwd=$(    echo "${_logs}" | grep '^ip_forward='  | cut -d= -f2-)
        _dns=$(       echo "${_logs}" | grep '^dns='         | cut -d= -f2-)
        _label="${_node_label:-${_pod}}"

        if [[ -z "${_logs}" ]]; then
            WARNINGS+=("Node ${_label}: per-node check produced no output — possible image pull timeout; set PREFLIGHT_CHECK_IMAGE to a pre-pulled local image")
            continue
        fi

        [[ "${_bridge_nf}" != "1" ]] && \
            ERRORS+=("Node ${_label}: net.bridge.bridge-nf-call-iptables=${_bridge_nf:-MISSING}  (fix: sysctl -w net.bridge.bridge-nf-call-iptables=1)")
        [[ "${_ip_fwd}" != "1" ]] && \
            ERRORS+=("Node ${_label}: net.ipv4.ip_forward=${_ip_fwd:-MISSING}  (fix: sysctl -w net.ipv4.ip_forward=1)")
        [[ "${_dns}" != "ok" ]] && \
            WARNINGS+=("Node ${_label}: DNS resolution failed for kubernetes.default.svc.cluster.local — check CoreDNS: kubectl get pods -n kube-system -l k8s-app=kube-dns")
    done

fi  # _CLUSTER_REACHABLE

# ---------------------------------------------------------------------------
# 8. Registry connectivity — treat any HTTP response as reachable;
#    only warn on connection failure (HTTP 000 = could not connect at all)
# ---------------------------------------------------------------------------
if [[ -n "${NCX_IMAGE_REGISTRY:-}" ]] && command -v curl &>/dev/null; then
    _reg_host="${NCX_IMAGE_REGISTRY%%/*}"
    _http_code=$(curl --connect-timeout 5 --max-time 10 \
        -o /dev/null -w "%{http_code}" \
        "https://${_reg_host}/v2/" 2>/dev/null || echo "000")
    if [[ "${_http_code}" == "000" ]]; then
        WARNINGS+=("Registry '${_reg_host}' is not reachable (connection failed) — check network access; image pulls will fail")
    fi
fi

# ---------------------------------------------------------------------------
# 9. NCX REST repo
# ---------------------------------------------------------------------------
NCX_REPO_RESOLVED=""

if [[ -n "${NCX_REPO:-}" ]]; then
    if [[ -d "${NCX_REPO}/helm/charts/carbide-rest" ]]; then
        NCX_REPO_RESOLVED="${NCX_REPO}"
    else
        ERRORS+=("NCX_REPO='${NCX_REPO}' but helm/charts/carbide-rest was not found there")
    fi
else
    for _candidate in \
        "${SCRIPT_DIR}/../../carbide-rest" \
        "${SCRIPT_DIR}/../../ncx-infra-controller-rest" \
        "${SCRIPT_DIR}/../../ncx"; do
        if [[ -d "${_candidate}/helm/charts/carbide-rest" ]]; then
            NCX_REPO_RESOLVED="$(cd "${_candidate}" && pwd)"
            break
        fi
    done
fi

NCX_CLONE_URL="https://github.com/NVIDIA/ncx-infra-controller-rest.git"
NCX_CLONE_PARENT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

if [[ -z "${NCX_REPO_RESOLVED}" ]]; then
    WARNINGS+=("NCX REST repo not found — expected a sibling directory with helm/charts/carbide-rest")
fi

# ---------------------------------------------------------------------------
# Output and prompts
# ---------------------------------------------------------------------------
_print_separator() { echo "---------------------------------------------------------------------"; }

if [[ ${#ERRORS[@]} -eq 0 && ${#WARNINGS[@]} -eq 0 ]]; then
    echo "Pre-flight OK  (NCX repo: ${NCX_REPO_RESOLVED:-not resolved})"
    [[ -n "${NCX_REPO_RESOLVED}" ]] && export NCX_REPO="${NCX_REPO_RESOLVED}"
    if ${_SOURCED}; then return 0; else exit 0; fi
fi

echo ""
_print_separator
echo "  PRE-FLIGHT CHECK RESULTS"
_print_separator

if [[ ${#ERRORS[@]} -gt 0 ]]; then
    echo ""
    echo "  ERRORS (setup will fail without these):"
    for _e in "${ERRORS[@]}"; do
        echo "    ✗  ${_e}"
    done
fi

if [[ ${#WARNINGS[@]} -gt 0 ]]; then
    echo ""
    echo "  WARNINGS (setup may fail or be incomplete):"
    for _w in "${WARNINGS[@]}"; do
        echo "    ⚠  ${_w}"
    done
fi

# Offer to clone NCX REST repo if missing
if [[ -z "${NCX_REPO_RESOLVED}" ]]; then
    echo ""
    echo "  NCX REST repo not found."
    echo ""
    echo "  setup.sh Phase 7 deploys the NCX REST stack (API, workflow engine, site-agent)"
    echo "  using Helm charts and kustomize bases from a separate repository:"
    echo "    ${NCX_CLONE_URL}"
    echo ""
    echo "  Options:"
    echo "    c) Clone it now into ${NCX_CLONE_PARENT}/ncx-infra-controller-rest"
    echo "    s) Skip — Phase 7 will be skipped or will fail"
    echo "    q) Quit setup entirely"
    echo ""
    echo "  (You can also clone it manually and re-run with:"
    echo "   export NCX_REPO=/path/to/ncx-infra-controller-rest)"
    if [[ "${AUTO_YES:-false}" == "true" ]]; then
        _clone_reply="s"
    else
        echo ""
        read -r -p "  ➤  Clone NCX REST repo now? [c=clone / s=skip / q=quit]: " _clone_reply
        echo ""
    fi
    case "${_clone_reply:-s}" in
        c|C)
            echo "  Cloning ${NCX_CLONE_URL} ..."
            git clone "${NCX_CLONE_URL}" "${NCX_CLONE_PARENT}/ncx-infra-controller-rest"
            NCX_REPO_RESOLVED="${NCX_CLONE_PARENT}/ncx-infra-controller-rest"
            export NCX_REPO="${NCX_REPO_RESOLVED}"
            echo "  Cloned OK — NCX_REPO=${NCX_REPO}"
            WARNINGS=("${WARNINGS[@]/NCX REST repo not found*/}")
            ;;
        q|Q)
            echo "  Aborted."
            if ${_SOURCED}; then return 1; else exit 1; fi
            ;;
        *)
            echo "  Skipping NCX REST repo — step [7/7] will fail."
            ;;
    esac
fi

echo ""
_print_separator

# Warnings only — default continue
if [[ ${#ERRORS[@]} -eq 0 ]]; then
    if [[ "${AUTO_YES:-false}" == "true" ]]; then
        echo "  Warnings noted — continuing (-y flag set)."
    else
        echo ""
        read -r -p "  ➤  Warnings above noted. Continue anyway? [Y/n]: " _reply
        echo ""
        if [[ ! "${_reply:-Y}" =~ ^[Yy]$ ]]; then
            echo "  Aborted."
            if ${_SOURCED}; then return 1; else exit 1; fi
        fi
    fi
    [[ -n "${NCX_REPO_RESOLVED}" ]] && export NCX_REPO="${NCX_REPO_RESOLVED}"
    if ${_SOURCED}; then return 0; else exit 0; fi
fi

# Hard errors — default abort
if [[ "${AUTO_YES:-false}" == "true" ]]; then
    echo "  Errors above noted — continuing (-y flag set). Things may fail."
    [[ -n "${NCX_REPO_RESOLVED}" ]] && export NCX_REPO="${NCX_REPO_RESOLVED}"
    if ${_SOURCED}; then return 0; else exit 0; fi
fi

echo ""
echo "  The issues above will likely cause setup to fail."
echo ""
read -r -p "  ➤  Continue anyway at your own risk? [y/N]: " _reply
echo ""
if [[ "${_reply:-N}" =~ ^[Yy]$ ]]; then
    echo "  Continuing — good luck."
    [[ -n "${NCX_REPO_RESOLVED}" ]] && export NCX_REPO="${NCX_REPO_RESOLVED}"
    if ${_SOURCED}; then return 0; else exit 0; fi
fi

echo "  Fix the issues above and re-run setup.sh."
if ${_SOURCED}; then return 1; else exit 1; fi
