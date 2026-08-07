# Per-service container specifications.
#
# Every image carbide publishes starts from the same base: a distroless root
# with one binary in /bin. Most services need nothing more. The ones that do —
# a shell to exec, a directory that must exist before startup, a legacy path
# some PodSpec still references — declare those needs here, one entry per
# service, and flake.nix feeds them to mkContainer.
#
# This file holds data, not derivations, and takes no package set. The builders
# live in flake.nix so that they can share one crane `cargoArtifacts` across
# every binary; splitting them per-service would rebuild the dependency closure
# once per image. What that buys here is a file describing *what* each service
# needs, readable without knowing how any of it is assembled.
#
# FIELDS — all optional; an absent field means the service doesn't need it.
#
#   runtime           Packages placed on the image's PATH. A function of the
#                     package set rather than a plain list, because the same
#                     entry builds both the amd64 image (against `pkgs`) and
#                     the arm64 one (against `aarch64CrossPkgs`); a list would
#                     bake in whichever architecture evaluated first.
#   extraCommands     Shell run at image build time, from the image root.
#   optCarbideAliases /opt/carbide/<alias> -> /bin/<target> symlinks.
#   optCarbideDirs    Empty directories created under /opt/carbide/.
#   entrypoint        OCI Entrypoint. Set only on images that run standalone.
#                     Server-side images omit it so k8s PodSpecs stay in charge
#                     of what runs.
#
# Every service that produces a container has an entry, including the many
# that need nothing beyond their binary and so are written `{ }`. flake.nix
# rejects a service missing from this file and an entry matching no service,
# which makes the list below the inventory of what carbide ships — an empty
# entry is a deliberate statement that the plain distroless image is correct,
# not an oversight.
{
  # Mellanox Firmware Tools, as a function of the package set — services shell
  # out to flint, mlxfwreset, mlxconfig and mlxfwmanager for firmware work.
  mftFor,
  # Scripts and firmware staged for the nvswitch-manager image.
  nsmStaticFiles,
}:

{
  # ==========================================================================
  # Server-side services — built for both amd64 and arm64
  # ==========================================================================

  carbide-api = {
    # The API drives hardware directly: tpm2-tools for attestation, ipmitool
    # for out-of-band power control, iproute2/iputils for reachability checks.
    #
    # The second group covers what the API's dependency crates shell out to:
    # util-linux for lscpu (host-support), openssh for scp (ssh), and MFT for
    # mlxfwmanager (libmlx).
    #
    # TODO: carbide-kms-provider also invokes `vault`, which is not installed.
    # nixpkgs' vault is BUSL-1.1, and redistributing it inside a published
    # image is a licensing decision rather than a packaging one. Until that is
    # settled the Vault KMS backend fails with ENOENT at the point of use.
    runtime =
      p:
      [ (mftFor p) ]
      ++ (with p; [
        tpm2-tools
        ipmitool
        busybox
        iputils
        iproute2
        util-linux
        openssh
      ]);
    # Mount points. Init containers populate these before the API starts, and
    # the mounts fail if the directories are missing.
    optCarbideDirs = [
      "pxe/templates"
      "migrations"
      "static"
      "firmware"
    ];
  };

  carbide-dns.runtime = p: with p; [ busybox ];

  carbide-pxe.runtime = p: with p; [ busybox ];

  carbide-dhcp = {
    # The image ships Kea itself, since carbide-dhcp is a hook library loaded
    # into kea-dhcp4-server rather than a standalone program.
    runtime =
      p: with p; [
        kea
        busybox
      ];
    extraCommands = "mkdir -p var/run/kea";
  };

  nico-admin-cli = {
    # Kept until every PodSpec referencing the pre-rename binaries is updated.
    optCarbideAliases = [
      {
        alias = "forge-admin-cli";
        target = "nico-admin-cli";
      }
      {
        alias = "carbide-admin-cli";
        target = "nico-admin-cli";
      }
    ];
  };

  # These reach the outside world only over the network, and their PodSpecs
  # supply the command, so the binary alone is the whole image.
  carbide-bmc-proxy = { };
  carbide-dsx-exchange-consumer = { };
  carbide-health = { };
  carbide-log-parser = { };

  carbide-ssh-console = {
    # Drives BMCs out of band: ipmitool for the IPMI transport, ping to decide
    # whether an endpoint is reachable before dialling it.
    runtime =
      p: with p; [
        ipmitool
        iputils
        busybox
      ];
  };

  # Runs inside the scout initramfs as well as in a container. The initramfs
  # gets these tools from its own NixOS closure; the container has to name
  # them, and shipped none until this entry existed.
  #
  # systemd is here for systemctl and systemd-detect-virt, which scout calls
  # while probing the host. Both only do anything useful when the container
  # runs with the host's /run mounted through — inside an isolated container
  # they find no init to talk to.
  carbide-scout = {
    runtime =
      p:
      [ (mftFor p) ]
      ++ (with p; [
        busybox
        systemd
        tpm2-tools
        util-linux
        openssh
        nerdctl
      ]);
  };

  # ==========================================================================
  # DPU-side services — arm64 only
  # ==========================================================================

  forge-dpu-agent = {
    # bash backs the agent's upgrade and health scripts; cri-tools and lldpd
    # let it inspect the container runtime and link topology; openvswitch
    # provides ovs-vsctl for the DPU's bridge configuration.
    #
    # python3 is for MFT, not for the agent: mlxfwreset shells out to the
    # python_tools tree. MFT propagates it too, but the agent is the service
    # that actually calls mlxfwreset, so it is named here as well.
    runtime =
      p:
      [ (mftFor p) ]
      ++ (with p; [
        bash
        python3
        iproute2
        lldpd
        cri-tools
        openvswitch
        busybox
      ]);
    # crates/agent/src/ovs.rs invokes ovs-vsctl by absolute path, but buildEnv
    # links binaries into /bin — so /usr/bin/ovs-vsctl has to be created here
    # or every bridge operation fails with ENOENT.
    extraCommands = ''
      mkdir -p usr/bin
      ln -sf /bin/ovs-vsctl usr/bin/ovs-vsctl
    '';
    entrypoint = [ "/bin/forge-dpu-agent" ];
  };

  # A standalone DHCP server, unlike carbide-dhcp — it serves leases itself
  # rather than being loaded into kea, so the image ships no kea.
  forge-dhcp-server = {
    runtime = p: with p; [ busybox ];
    # The DPU's service definition invokes the binary through /var/support,
    # so the image provides that path as a symlink onto /bin.
    extraCommands = ''
      mkdir -p var/support/forge-dhcp/bin
      ln -sf /bin/forge-dhcp-server var/support/forge-dhcp/bin/forge-dhcp-server
    '';
    entrypoint = [ "/var/support/forge-dhcp/bin/forge-dhcp-server" ];
  };

  carbide-fmds = {
    runtime = p: with p; [ busybox ];
    entrypoint = [ "/bin/carbide-fmds" ];
  };

  # ==========================================================================
  # rest-api Go services
  # ==========================================================================

  rest-api-nsm.runtime = _: [ nsmStaticFiles ];

  # nsm is the exception in this set: it manages switch hardware and needs its
  # scripts and firmware on disk. The rest are Go services that talk to the
  # database and each other over the network and need nothing on the image.
  rest-api-api = { };
  rest-api-credsmgr = { };
  rest-api-flow = { };
  rest-api-mcp = { };
  rest-api-migrations = { };
  rest-api-nicocli = { };
  rest-api-psm = { };
  rest-api-site-agent = { };
  rest-api-sitemgr = { };
  rest-api-workflow = { };

  # ==========================================================================
  # Tooling images
  # ==========================================================================

  machine-a-tron = {
    # cacert for TLS to the BMCs it mocks; libssl and libudev arrive through
    # the binary's RPATH closure rather than being named here.
    runtime =
      p: with p; [
        cacert
        iproute2
        iputils
        busybox
      ];
    # Callers invoke it by its /opt path. Symlinked rather than copied so the
    # binary exists at exactly one location in the image.
    extraCommands = ''
      mkdir -p opt/machine-a-tron/bin
      ln -sf /bin/machine-a-tron opt/machine-a-tron/bin/machine-a-tron
      mkdir -p tmp/machine-a-tron-data
    '';
    entrypoint = [ "/opt/machine-a-tron/bin/machine-a-tron" ];
  };
}
