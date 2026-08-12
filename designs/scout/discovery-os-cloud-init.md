# Discovery OS Cloud-Init Snippets

## Software Design Document

## Revision History

| Version | Date | Modified By | Description |
| :---: | :---: | :---- | :---- |
| 0.1 | 2026-08-07 | Ron Thompson | Initial draft |

# **1. Introduction**

## **1.1 Purpose**

Today the primary way to add site-specific setup to the discovery OS (Scout) is to bake it into the image
at build time. That is done by the `carbide-extras` container, which CI unpacks directly into the mkosi
profile (`.github/workflows/build-boot-artifacts.yml`, "Inject carbide_extras content into build" —
already carrying `# TODO(ajf): This is NVIDIA specific stuff and really needs to be genericized`). This
couples NVIDIA-internal, non-open-source payloads to the open-source image build, and leaves everyone
else without a well-supported path to customize the discovery OS.

This proposes optional, per-site cloud-init snippets served to Scout at discovery boot. The concrete
near-term consumer is authentication setup — whichever mechanism a site uses, which will change over time
and will differ between sites. Machine-validation dependencies are a likely second consumer as they come
up, and end-user customization generally is the reason the mechanism is worth building broadly rather
than narrowly. Either way, it lets `carbide-extras` be removed from the build entirely.

## **1.2 Scope**

In scope: the x86_64 and aarch64 host Scout discovery boot. The feature is **optional** — with no site
config present, behavior is byte-for-byte what it is today.

Out of scope for v1: the DPU/BFB path (unchanged), tenant-assigned instance cloud-init (unchanged), and
storing snippets in carbide-api/the database.

# **2. Current State**

- **Scout has no cloud-init.** It is absent from both `pxe/mkosi.profiles/scout-oss-*` package lists.
- **Scout is configured entirely from the kernel command line.** `mac=`, `machine_id=`, `server_uri=`,
  `pxe_uri=` and `cli_cmd=` are emitted by `InstructionGenerator` in `crates/api-core/src/ipxe.rs`. It
  does not call the cloud-init routes at all.
- **Both halves of the mechanism have precedent.** `ubuntu-autoinstall`, `dgx-os`, and the qcow imager
  already append `ds=nocloud-net;s=${cloudinit-url}` to boot a machine against a cloud-init datasource,
  and the Scout image already trusts a PXE-served apt repo (`/etc/apt/sources.list.d/forge.list` →
  `http://carbide-pxe.forge/public/blobs/internal/apt/`).

# **3. Design**

A site drops cloud-config files into a directory that carbide-pxe serves. carbide-pxe lists them as a
cloud-init `#include` document, and Scout — which gains cloud-init and a datasource on its kernel command
line — applies them before `forge-scout` starts.

Everything below is work to be built unless marked as existing:

| Component | Change |
| :---- | :---- |
| Site deployment | **New** — optional per-site snippet files mounted into carbide-pxe; produced by whatever tooling owns that site (3.1) |
| carbide-pxe | **New** — `/api/v0/cloud-init/discovery/` prefix serving `user-data` and `meta-data`, the snippet-directory scan, and the rendered terminal document (3.2, 3.5) |
| Scout image | **Changed** — add the `cloud-init` package; drop `power_state_change` from the enabled final modules (3.3, 3.6) |
| carbide-api | **Changed** — append `ds=nocloud-net;s=…` to the Scout kernel command line (3.4) |
| `forge-scout.service` | **Changed** — order after cloud-init's completion unit; read the sentinel at startup (3.5) |

Reused unchanged: the static file handler under `/public`, resolution of the caller from client IP,
`instance_id` population on the machine-interface path, `[pxe_url]` substitution and its per-machine
overrides, the `PxeBootOutcome` / `OutcomeReason` metrics, and the PXE-served site apt repo.

## **3.1 Snippet source**

**New.** The contract is a mount path: any files present inside the carbide-pxe pod at
`/forge-boot-artifacts/blobs/internal/cloud-init.d/scout/` are picked up, and are served by the existing
static handler under `/public/blobs/internal/cloud-init.d/scout/`. Snippets are flat, site-wide, and
applied in sorted filename order (`10-auth.yaml`, `20-…`).

How the files arrive there is up to whatever tooling owns the site, and the feature depends on nothing
beyond their presence. Site configuration does not come from one place: `forged` drives the environments
it owns, a growing number of sites are materialized through dsx-sbom, and external customers generally
deploy with their own Helm charts and use neither. A ConfigMap is the natural implementation for the
sites we run and is what reference material should show, but a Helm-templated Secret or any other volume
satisfies the contract equally.

**A stock cloud-config must work unmodified.** There is no Carbide-specific dialect, no required
preamble, and no wrapper to learn — any valid cloud-config document in that directory is applied as-is.
This is a design constraint and the bar the documentation is held to: if the feature needs a sample to be
usable, the mechanism is too specialized. The only limits on what a snippet may do are in 3.6.

Snippets are flat and site-wide because per-machine and per-SKU behavior needs no mechanism from us. The
machine interface ID and MAC arrive on the kernel command line as `machine_id=` and `mac=`; the machine
ID is in the `meta-data` document (3.2); and hardware identity is readable locally through `dmidecode`
and `lshw`, both already in the image. A snippet that wants to branch on any of it does so directly.

## **3.2 carbide-pxe: the discovery endpoint**

**New.** carbide-pxe gains a route prefix used only by the discovery OS: `/api/v0/cloud-init/discovery/`.
carbide-api emits this URL only on the Scout kernel command line (3.4), so only discovery hosts reach it,
and the existing tenant cloud-init path is untouched.

`user-data` is rendered as a cloud-init `#include` list — the snippet directory scanned and sorted,
emitted as URLs under `CUSTOM_CLOUD_INIT_WEB_ROOT`. cloud-init fetches each in turn, so carbide-pxe never
parses or merges site YAML. A missing or empty directory yields a list containing only the terminal
document from 3.5; that is the "feature not configured" path.

`meta-data` is required by NoCloud and must always return a valid document, because a datasource that
fails to come up costs not just the snippets but the terminal document and therefore the sentinel. Its
`instance-id` carries the machine ID, which needs no new work: carbide-api already populates that field
on the machine-interface path when resolving the caller by client IP
(`crates/api-core/src/handlers/client_resolution.rs`), independently of and prior to Scout registering. A
snippet needing machine identity reads it there rather than scraping `/proc/cmdline`.

**Treat the machine ID as usually present rather than guaranteed.** It is served in `meta-data` whenever
carbide-api has it, which is the common case, but the field is optional and can be unset. A snippet that
uses it should tolerate its absence. The document itself is served and valid either way, with
`instance-id` backstopped by the interface ID so cloud-init always has one.

## **3.3 Scout image (mkosi)**

**Changed.** Add `cloud-init` to the `scout-oss-x86_64` and `scout-oss-aarch64` package lists. Because
the Scout rootfs is a read-only squashfs with a tmpfs overlay, **every discovery boot is a fresh
cloud-init instance**: there is no first-boot suppression to work around and no accumulated cloud-init
state to reset. Snippets apply on every discovery boot by construction.

## **3.4 Kernel command line (carbide-api)**

**Changed.** Append `ds=nocloud-net;s=[pxe_url]/api/v0/cloud-init/discovery/` to both host branches of
`get_pxe_instruction_for_arch`. This is the only carbide-api change the feature needs. The `[pxe_url]`
placeholder is already substituted per machine and already honors `pxe_url_override`, so external hosts
on the static-assignments segment work with no further change.

## **3.5 Completion sentinel and forge-scout ordering**

Today `forge-scout.service` orders only on `network-online.target`, so nothing keeps it from starting
before snippets have applied. Two changes address that.

**New — the terminal document.** carbide-pxe always appends a document of its own to the end of the
`#include` list, whose only job is to write a sentinel file (e.g. `/run/forge/cloud-init-complete`) once
everything ahead of it has run. Because carbide-pxe builds the list, a site snippet cannot remove or
reorder that entry.

**Changed — the ordering.** `forge-scout.service` gains `After=` cloud-init's completion unit, with no
`Requires=`. Ordering does not demand success, so a cloud-init that fails — or that exceeds its own
`TimeoutStartSec` and is killed — still releases forge-scout. The time bound therefore comes from
cloud-init's own unit timeout, and Scout needs no waiting logic of its own.

The sentinel is a **signal, not a gate**: Scout reads it once at startup, without blocking, to establish
whether site customization completed. Its absence means the boot is degraded rather than stalled, and is
logged and counted.

The sentinel step must survive cloud-config merge semantics across multiple documents — a site snippet
defining overlapping keys must merge with the terminal document rather than displace it. The cloud-init
shipped in Ubuntu 24.04 (noble) is documented to behave this way, but it is load-bearing enough to be
verified rather than assumed (8.1).

**The terminal document is also where the operator documentation lives.** It ships on every boot, cannot
be edited away by a site, and is what an operator lands on when they curl the endpoint or read cloud-init
logs while debugging. It carries, in comments, the effective time bound and what happens when a snippet
exceeds it — cloud-init is killed, Scout starts anyway, and the unfinished work is lost — together with
the no-reboot constraint from 3.6. Because carbide-pxe renders the document, that bound is interpolated
from the configured value rather than restated by hand, so it cannot drift from the behavior. This
requires the value to be readable where the document is rendered.

## **3.6 Reboot semantics**

Scout runs entirely from a RAMdisk, so **a reboot is not a reconfiguration — it is a full re-PXE.** The
overlay is discarded, the loader re-downloads the rootfs, and every snippet runs again from scratch. Much
of the conventional cloud-init idiom treats a reboot as a cheap way to settle changes; here it is not.
Two rules follow.

**Snippets must not reboot.** This is the sharpest edge in the design, because the cost is not one
re-PXE but an unbounded reboot loop across every machine that receives the snippet. The host re-PXEs, is
served Scout again, re-runs the same unchanged snippet, and reboots again. Nothing breaks the cycle on
its own: the rootfs is ephemeral so no local state accumulates, the sentinel lives in `/run`,
`check-scout-updates` needs 24 hours of uptime it will never reach, and the reboot fires before
`forge-scout` has started (3.5), so the machine never registers and never leaves the discovery state that
keeps serving it Scout. Because snippets are site-wide, every machine in discovery at that site loops at
once, each cycle re-downloading the rootfs from carbide-pxe.

**Anything requiring a reboot to take effect cannot be delivered this way.** Kernel parameters, kernel or
module changes needing a restart, and firmware activation belong in the image or in a lifecycle state
that already owns a reboot.

The loop is loud, and it self-heals: every cycle spikes request rates on carbide-pxe and carbide-api, and
stalled machines eventually breach their time-in-state SLA and alert, while correcting the snippet ends
the loop at the next boot with no per-machine intervention. What those signals do not say is *why* — that
a snippet is rebooting hosts — and machine-controller's reboot histograms do not help, because they count
only Carbide-initiated reboots. The cost is therefore paid in diagnosis time rather than in going
unnoticed, and is addressed by writing the symptom signature down: **a request-rate spike on carbide-pxe
and carbide-api together with discovery machines breaching time-in-state means a snippet is rebooting
hosts.** That makes the diagnosis a lookup.

The image build drops `power_state_change` from cloud-init's enabled final modules, which stops
cloud-init rebooting on its own. It cannot stop a snippet calling `reboot` from `runcmd`, and reboot
cannot be masked generally, since Carbide reboots hosts for lifecycle transitions and
`check-scout-updates` deliberately reboots to pick up a newer Scout image. The rule is therefore guarded
where it can be and stated everywhere it can be — in the terminal document served on every boot, and in
the operator documentation alongside the symptom signature. Since the guard cannot be enforcement,
documentation is the control that does the work, and it should be repeated past the point of feeling
excessive.

Reboots do happen legitimately — image updates and lifecycle transitions — and snippets re-run on a clean
rootfs each time. Local state is therefore always fresh and needs no first-run guarding. What needs care
is any effect reaching outside the ephemeral rootfs: **if you call an API from your cloud-init script, do
not expect it to be called only once in a machine's life.** The same holds for mutating BMC or firmware
state, writing to persistent disk, or consuming a license seat. Snippets are re-executed, and operations
like these must be idempotent.

# **4. Migrating off carbide-extras**

| Payload injected today | Replacement |
| :---- | :---- |
| `nvinit_setup/` (nvssh auth config) | `carbide-nvinit` deb from the site apt repo |
| `libnss-exec`, `libssl1.1`, `libuser` debs | site apt repo |
| `mnv_cli` (Lenovo M.2 RAID cleanup) | `carbide-tools` deb |
| `postinst-extras.sh` | snippet `runcmd` |
| machine-validation dependencies, as needed | site apt repo, installed by a snippet |

The site apt repo is the already-prototyped `carbide-apt-repo` sidecar. Once the above land, delete the
"Inject carbide_extras content into build" and "Verify required extras binaries are present" CI steps and
the `inject_extras` / `extras_container` workflow inputs. The `mnv_cli` check is currently a hard CI gate,
so its removal and the packaging of `carbide-tools` must land together.

# **5. Technical Considerations**

## **5.1 Security and trust model**

Snippets are fetched over plain HTTP (`carbide_pxe_url` is `http://`) and execute as root on the
discovery OS. This matches the trust model already in place for the `[trusted=yes]` apt source and the
loader's unauthenticated rootfs fetch, and it is inherent to the feature: an operator who can configure
the site can already choose what the discovery OS runs. PCR 16 measures the image we ship and continues
to mean exactly that; by design it does not attest to site customization layered on top.

## **5.2 Failure handling**

A broken snippet must not brick discovery. Fail open — log, emit a metric, and continue into
`forge-scout` — consistent with how `forge-scout-pre.sh` already tolerates `forge-scout-network.sh`
failing, and the reason for the ordering choice in 3.5.

## **5.3 Resource cost**

The overlay upper layer is tmpfs, so anything a snippet installs is resident in RAM for the life of the
boot and is re-fetched every boot. Prefer the site apt repo over large in-snippet payloads, and bound
total snippet size.

## **5.4 Observability**

Count served / not-configured / error outcomes on the new endpoint using the existing `PxeBootOutcome`
and `OutcomeReason` instrumentation, plus the sentinel outcome from 3.5. No new alerting is proposed: the
reboot loop of 3.6 is covered by documenting its symptom signature against the request-rate and
time-in-state alerts that already exist.

# **6. Alternatives Considered**

- **Extend the existing `/api/v0/cloud-init/` routes instead of adding a discovery prefix.** This would
  require deciding per request whether the caller is a host in discovery or an assigned instance, from
  data that does not cleanly distinguish them. A separate prefix reachable only from the Scout kernel
  command line removes the question. It also avoids inheriting the tenant `meta-data` handler's behavior
  of answering a missing-metadata case with an error template, which on this path would take the whole
  datasource down (3.2).
- **Serve one merged cloud-config instead of an `#include` list.** This would put carbide-pxe in the
  business of parsing and merging site YAML, and make it responsible for conflicts between snippets.
- **Gate `forge-scout` with `ConditionPathExists=` on the sentinel.** Conditions are evaluated once, when
  the queued start job runs; they do not wait. A failing one skips the unit "mostly silently" without
  moving it to `failed`, so `Restart=on-failure` would not recover it, and a sentinel that had not yet
  appeared would suppress `forge-scout` for the whole boot.
- **Detect the reboot loop in carbide-api and refuse to serve the customized path past a threshold.**
  Rejected as more mechanism than the failure warrants, given the loop already surfaces on existing
  alerts and self-heals as soon as the snippet is corrected (3.6).
- **Ship a starter snippet for operators to copy.** Rejected: 3.1 requires a stock cloud-config to work
  unmodified, so an author starts from any cloud-init document they already have, and a shipped sample
  would become a second source of truth that drifts from the terminal document.

# **7. Acceptance Criteria**

1. With no snippets present, Scout boots as it does today; the discovery endpoint serves only the
   terminal document and the sentinel appears promptly.
2. With N snippets configured, all N apply in filename order and are visible in cloud-init logs on the
   console, and Scout observes the sentinel before doing dependent work.
3. A deliberately broken snippet degrades the boot but still reaches `forge-scout`.
4. A host whose interface has no associated machine still gets a valid `meta-data` document, applies its
   snippets, and produces a sentinel.
5. A snippet that exceeds the time bound does not stall the boot: cloud-init is killed, Scout starts, and
   the missing sentinel is logged and counted as degraded customization.
6. The served terminal document carries the time bound and no-reboot constraint in comments, with the
   bound matching the value actually enforced; the no-reboot rule and the symptom signature from 3.6 also
   appear in the operator-facing documentation.
7. A site's authentication setup is delivered entirely by snippet, with no `carbide-extras` injection
   anywhere in the build; the extras CI steps and inputs are deleted and boot-artifacts builds green
   without an extras container.

# **8. Pre-Implementation Validation**

These are assumptions the design rests on, and none should be taken from documentation alone.

1. **Merge, not displacement.** On the cloud-init version actually shipped in noble, confirm that a site
   snippet defining keys that overlap the terminal document merges with it rather than replacing it, and
   that the sentinel step still runs. Pin the behavior with an explicit `merge_how` and re-confirm.
   Determine the exact packaged version as part of this, rather than assuming it from the release.
2. **Reboot behavior.** Confirm that dropping `power_state_change` prevents cloud-init from rebooting
   Scout on its own. Then deliberately reproduce the reboot loop from 3.6 on a test machine, to confirm
   both that it behaves as described and that correcting the snippet ends it cleanly.
3. **Completion unit and its timeout.** Confirm which unit in the shipped cloud-init layout is the right
   ordering target for "customization is done" (`cloud-final.service` and `cloud-init.target` are the
   candidates), and that exceeding its `TimeoutStartSec` releases `forge-scout` rather than blocking it.
4. **End-to-end proof.** The first implementation slice is a `10-hello-world.yaml` in the local-dev site
   configuration that writes a line to a log file — enough to exercise the whole path (mount → directory
   scan → `#include` → cloud-init → sentinel) without depending on any of the migration work in 4. It is
   a local-dev artifact and is not shipped in production site configuration.

   It also creates a testing hazard worth naming: once local-dev always has a snippet present, the
   *unconfigured* path stops being exercised in the normal dev loop, and that is precisely the path
   required to be byte-for-byte unchanged (criterion 1). That case needs testing deliberately.

# **9. Open Questions**

1. Sentinel path (`/run/forge/cloud-init-complete` is a placeholder), and what `TimeoutStartSec`
   cloud-init's completion unit should carry — the stock value may be generous for a discovery boot.
2. Should the daily `check-scout-updates` reboot consider snippet changes? It currently compares only the
   squashfs `Last-Modified`, so a snippet edit does not by itself recycle a long-lived discovery host.
3. Is a deprecation window needed for sites still building against `carbide-extras`?

