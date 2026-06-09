# Site Controller Health

Use this playbook when the problem affects site-controller nodes, core NICo
services, cloud sync, or shared infrastructure rather than a single managed host.

Site-controller nodes run the NICo control plane. They are not managed hosts.

## Quick Health Checklist

```bash
kubectl get nodes -o wide
kubectl get pods -A
kubectl get svc -A | grep LoadBalancer
```

Check critical namespaces for the site:

```bash
kubectl get pods -n <nico-namespace>
kubectl get pods -n postgres
kubectl get pods -n vault
```

## Node and Kubernetes Layer

| Symptom | What to check |
|---|---|
| node `NotReady` | kubelet logs, cert renewal, node network, disk pressure. |
| node stuck after cert renewal | restart kubelet and API components; confirm certs on every control-plane node. |
| workload scheduling failures | taints, node pressure, image pull failures, storage class issues. |

## Core NICo Services

| Symptom | What to check |
|---|---|
| `nico-api` crash loop | config TOML, database connectivity, TLS, required site fields. |
| DB connection failures | Postgres health, pool exhaustion, deadlocks, Patroni member state. |
| DHCP or PXE endpoint down | `nico-dhcp`, `nico-pxe`, LoadBalancer IPs, MetalLB. |
| API TLS probe failure | certificate, LoadBalancer routing, DNS. |
| DNS down | DNS pods, upstream resolver, endpoint probes. |
| SSH console unreachable | SSH console pod and service routing. |

Postgres health needs more than `kubectl get pods`:

```bash
kubectl -n postgres exec pod/<postgres-pod> -c postgres -- patronictl list
```

## Control-Plane Networking

Check:

- MetalLB BGP peers
- IP pools
- LoadBalancer services
- FRR speaker status
- DNS and service routing

```bash
kubectl get svc -n <nico-namespace> | grep LoadBalancer
```

## Site Agent and Cloud Sync

Cloud-to-site sync failures can make the cloud UI and site state disagree.

Check site-agent logs:

```bash
kubectl logs -n <site-agent-namespace> -l app.kubernetes.io/name=<site-agent-label> | grep NicoClient
```

Common causes:

- site agent cannot reach `nico-api`
- mTLS cert projection problem
- DNS cold-cache or startup race
- cloud API connectivity issue
- site agent crash loop

## Upgrades and Configuration

For config or upgrade issues:

- lint changed TOML where possible
- confirm generated ConfigMaps contain expected values
- confirm ArgoCD or deployment sync completed
- confirm required secrets were projected

## Certificate and Secret Rotation

Credential and certificate issues often surface as unrelated BMC, API, or probe
failures.

Check:

- Vault pod health
- `nico-api` to Vault connectivity
- certificate renewal on every control-plane node
- projected secrets in affected pods
- `carbide_api_vault_requests_failed_total`

The metric prefix may remain `carbide_*` even when the service is now named
NICo.
