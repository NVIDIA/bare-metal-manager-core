# DevSpace Gotchas

Use this page when a local full-stack deployment fails before the changed
product behavior is exercised. These are harness diagnostics and recoveries;
they are not evidence of a product defect.

## Match the OAuth issuer hostname exactly

The local Keycloak realm issues tokens for
`http://localhost:18082/realms/nico-dev`. Acquire the token through
`localhost`, as shown in the README. Using `127.0.0.1` changes the token's
`iss` claim, and REST rejects it with `No processor found for token issuer`
even though both names reach the same port-forward.

After changing a Keycloak port-forward or hostname, mint a new token. Do not
reuse a token or `nicocli` config created for a different issuer.

## Serialize shared Core builds

Local DevSpace builds share the `nico-devspace-cargo-target` BuildKit cache and
the `nico-devspace-core-artifacts` image. Concurrent builds from different
checkouts can therefore mix generated Rust or protobuf outputs, and a later
runtime image can copy artifacts from the wrong revision.

Run only one Core artifact build at a time. For isolated verification, give the
Cargo cache a run-specific ID and record the artifact image and deployed image
IDs before exercising behavior. Do not delete or overwrite another run's cache
or image.

## Test Docker contexts without warm caches

Dockerfile-specific ignore files are allowlists. A warm Cargo target cache can
hide a missing source file when `include_str!`, `include_bytes!`, a build
script, or generated code consumed it during an earlier build.

When one of those inputs changes, run at least one build with a new cache ID.
If a clean build reports a missing file, add the required input to the owning
Dockerfile's ignore allowlist rather than copying it into the cache manually.

## Diagnose cluster DNS before changing product configuration

Inherited host search domains can make short Kubernetes service names time out
even when Service IP connectivity and TLS are healthy. Check unfiltered pod
logs, DNS resolution, TCP connectivity, and the same authenticated call from a
run-owned pod before classifying the failure.

For an isolated local run, prefer absolute Kubernetes service names ending in
`.` and the cluster resolver with `ndots:1`. Treat any pod DNS-policy or
ConfigMap patch as run-only harness recovery, and restore or discard it before
recording product evidence.

## Recreate port-forwards after rollouts

Temporary API and Keycloak port-forwards end when their source pod rolls or the
owning shell exits. A later `401`, connection refusal, or setup timeout can be a
stale forward rather than a service failure.

Before retrying the integration setup, confirm the documented local ports are
free, recreate the forwards to the current Services, and mint a fresh token.
