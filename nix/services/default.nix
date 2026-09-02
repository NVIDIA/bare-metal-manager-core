# Per-service container specifications.
#
# Every image is assembled directly from Nix store paths, without a base image.
# Most services need only their binary in /bin. The ones that need more —
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
#   cmd               OCI Cmd, used where the historical image has no
#                     Entrypoint of its own.
#   user              Numeric OCI user/group. The Nix-built root contains the
#                     matching minimal account files.
#   workingDir        OCI working directory when relative paths are part of the
#                     service contract.
#   ociTitle          Public OCI image title when it differs from the internal
#                     Nix service/package name.
#   additionalPackageNames
#                     Other first-party service binaries intentionally shipped
#                     in the same image. Names resolve within the matching
#                     architecture's package set.
#   includePrimarySources
#                     Include primary packages in OSS source/attribution
#                     generation. Set only when the workload itself is added
#                     third-party OSS, never for Carbide/NICo applications.
#
# Every service that produces a container has an entry, including the many
# that need nothing beyond their binary and so are written `{ }`. flake.nix
# rejects a service missing from this file and an entry matching no service,
# which makes the list below the inventory of what carbide ships — an empty
# entry is a deliberate statement that the Nix-built root needs only the
# primary binary, not an oversight.
{
  # Mellanox Firmware Tools, as a function of the package set — services shell
  # out to flint, mlxfwreset, mlxconfig and mlxfwmanager for firmware work.
  mftFor,
  # A collision-free package containing GNU timeout at /usr/bin/timeout.
  coreutilsTimeoutFor,
  # Scripts and firmware staged for the nvswitch-manager image.
  nsmStaticFiles,
  # PXE templates and Scout firmware update scripts served by carbide-pxe.
  pxeTemplateFiles,
  scoutFirmwareFiles,
  # ARM64 observability workloads and their repository-owned wrapper payload.
  otelcolContribAarch64,
}:

{
  # ==========================================================================
  # Server-side services — built for both amd64 and arm64
  # ==========================================================================

  carbide-api = {
    # The API drives hardware directly: tpm2-tools for attestation and ipmitool
    # for out-of-band power control. Its dependency crates also shell out to
    # openssh for scp. BusyBox supplies the chart's shell contract without
    # carrying unrelated network utilities. MFT belongs in Scout and DPU-agent
    # images: neither the API nor api-core has an MFT command execution path.
    runtime =
      p: with p; [
        tpm2-tools
        ipmitool
        busybox
        openssh
      ];
    # Mount points. Init containers populate these before the API starts, and
    # the mounts fail if the directories are missing.
    optCarbideDirs = [
      "pxe/templates"
      "migrations"
      "static"
      "firmware"
    ];
    # Machine-controller selects an update script from this fixed path.
    firstPartyContents = [ scoutFirmwareFiles ];
    extraCommands = ''
      mkdir -p usr/bin
      ln -sf /bin/ipmitool usr/bin/ipmitool
    '';
  };

  carbide-dns.runtime = p: with p; [ busybox ];

  carbide-pxe = {
    runtime = p: [ p.busybox ];
    firstPartyContents = [
      pxeTemplateFiles
      scoutFirmwareFiles
    ];
  };

  carbide-dhcp = {
    # The image ships Kea itself, since carbide-dhcp is a hook library loaded
    # into kea-dhcp4-server rather than a standalone program.
    runtime =
      p: with p; [
        kea
        busybox
      ];
    extraCommands =
      p:
      let
        multiarch = if p.go.GOARCH == "arm64" then "aarch64-linux-gnu" else "x86_64-linux-gnu";
      in
      ''
        mkdir -p var/run/kea var/lib/kea usr/lib/kea/hooks
        ln -sf /usr/lib/${multiarch}/kea/hooks/libdhcp.so usr/lib/kea/hooks/libdhcp.so
      '';
  };

  nico-admin-cli = {
    runtime =
      p: with p; [
        busybox
        openssh
      ];
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
    extraCommands = ''
      mkdir -p app
      ln -sf /bin/nico-admin-cli app/nico-admin-cli
      ln -sf /bin/nico-admin-cli app/carbide-admin-cli
    '';
    entrypoint = [ "/app/nico-admin-cli" ];
    workingDir = "/app";
  };

  # These reach the outside world only over the network. Their PodSpecs supply
  # the command; BusyBox exists only for the chart's `/bin/sh` contract.
  carbide-bmc-proxy.runtime = p: with p; [ busybox ];
  carbide-dsx-exchange-consumer.runtime = p: with p; [ busybox ];
  carbide-health.runtime = p: with p; [ busybox ];
  carbide-log-parser = { };

  carbide-ssh-console = {
    # Drives BMCs out of band through ipmitool. Reachability probing is done by
    # the Rust process itself with TCP and RMCP sockets, so iputils is not part
    # of the runtime contract.
    runtime =
      p: with p; [
        ipmitool
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
      [
        (mftFor p)
        (coreutilsTimeoutFor p)
      ]
      ++ (with p; [
        # MFT launchers invoke bare `bash`, while mlxfwreset requires the full
        # pciutils implementations of lspci and setpci. BusyBox's lspci does
        # not implement the flags used by the vendor reset workflow. mokutil's
        # Secure Boot result also controls which reset levels MFT considers
        # safe; treating a missing command as "disabled" bypasses that guard.
        bashNonInteractive
        busybox
        mokutil
        pciutils
        systemdMinimal
        tpm2-tools
        util-linux
        nerdctl
        lldpd
        dmidecode
        nvme-cli
        hdparm
        sg3_utils
      ]);
    # GPU enumeration uses GNU timeout's `--kill-after` spelling. Put /usr/bin
    # first so BusyBox's incompatible timeout applet cannot win command lookup.
    env = [ "PATH=/usr/bin:/bin" ];
    # The scrubber intentionally uses conventional distro paths. Nix packages
    # place these tools in /bin, so preserve the application's public runtime
    # contract with explicit links.
    extraCommands = ''
      mkdir -p usr/bin usr/sbin
      ln -sf /bin/nvme usr/sbin/nvme
      ln -sf /bin/hdparm usr/sbin/hdparm
      ln -sf /bin/sg_sanitize usr/bin/sg_sanitize
      # BusyBox implements the `oflag=direct` form used by the scrubber, so a
      # second GNU coreutils copy is unnecessary in this image.
      ln -sf /bin/dd usr/bin/dd
    '';
  };

  # ==========================================================================
  # DPU-side services — arm64 only
  # ==========================================================================

  forge-dpu-agent = {
    # bash backs the agent's upgrade and health scripts; cri-tools and lldpd
    # let it inspect the container runtime and link topology; openvswitch
    # provides ovs-vsctl for the DPU's bridge configuration.
    #
    runtime =
      p:
      [ (mftFor p) ]
      ++ (with p; [
        bashNonInteractive
        iproute2
        lldpd
        cri-tools
        openvswitch
        busybox
        util-linux
        tpm2-tools
      ]);
    # crates/agent/src/ovs.rs invokes ovs-vsctl by absolute path, but buildEnv
    # links binaries into /bin — so /usr/bin/ovs-vsctl has to be created here
    # or every bridge operation fails with ENOENT.
    extraCommands = ''
      mkdir -p usr/bin
      ln -sf /bin/ovs-vsctl usr/bin/ovs-vsctl
      ln -sf /bin/forge-dpu-agent usr/bin/forge-dpu-agent
    '';
    entrypoint = [ "/usr/bin/forge-dpu-agent" ];
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
    runtime =
      p: with p; [
        busybox
        iproute2
      ];
    # The chart's network-setup init container invokes /busybox/sh from this
    # image, matching the historical BusyBox layout.
    extraCommands = ''
      mkdir -p busybox
      ln -sf /bin/sh busybox/sh
      mkdir -p usr/bin
      ln -sf /bin/carbide-fmds usr/bin/carbide-fmds
    '';
    entrypoint = [ "/usr/bin/carbide-fmds" ];
  };

  # The collector composition is separately added OSS. Its generated source
  # participates in source/attribution generation, while the repository-owned
  # wrappers are classified as first-party container content.
  otelcol-contrib = {
    runtime =
      p: with p; [
        bashNonInteractive
        busybox
        coreutils
        systemdMinimal
      ];
    firstPartyContents = [ otelcolContribAarch64.wrapperScripts ];
    includePrimarySources = true;
    # `/usr/bin/env -S` in the wrapper shebang is a GNU extension that
    # BusyBox's env does not implement.
    extraCommands = p: ''
      mkdir -p usr/bin
      ln -sf ${p.coreutils}/bin/env usr/bin/env
    '';
    entrypoint = [ "/etc/otelcol-contrib/otelcol-wrapper" ];
  };

  # The release is a prebuilt, separately added GPLv3 workload. The package's
  # passthru points source generation at the matching tagged source archive.
  transceiver-exporter = {
    includePrimarySources = true;
    entrypoint = [ "/usr/bin/transceiver-exporter" ];
  };

  # This controller is a static Go workload. Kubernetes passes its flags as
  # args, so the image must retain an Entrypoint and the historical non-root
  # execution contract.
  mat-k8s-controller = {
    entrypoint = [ "/bin/mat-k8s-controller" ];
    user = "65534:65534";
  };

  # ==========================================================================
  # rest-api Go services
  # ==========================================================================

  rest-api-nsm = {
    ociTitle = "nico-nsm";
    runtime =
      p: with p; [
        bashNonInteractive
        busybox
        curl
        openssh
        sshpass
        iputils
      ];
    extraCommands = ''
      mkdir -p app usr/bin
      ln -sf /bin/nsm app/nsm
      ln -sf /bin/env usr/bin/env
    '';
    firstPartyContents = [ nsmStaticFiles ];
    entrypoint = [
      "/app/nsm"
      "serve"
    ];
    user = "65534:65534";
    workingDir = "/opt/nvswitch-manager";
  };

  # nsm is the exception in this set: it manages switch hardware and needs its
  # scripts and firmware on disk. The rest are Go services that talk to the
  # database and each other over the network and need nothing on the image.
  rest-api-api = {
    ociTitle = "nico-rest-api";
    # The production API image intentionally carries nicocli for debugging.
    additionalPackageNames = [ "rest-api-nicocli" ];
    runtime = p: with p; [ busybox ];
    extraCommands = ''
      mkdir -p app var/secrets/temporal/certs
      ln -sf /bin/api app/api
      ln -sf /bin/nicocli app/nicocli
    '';
    entrypoint = [ "/app/api" ];
    user = "65534:65534";
    workingDir = "/app";
  };
  rest-api-credsmgr = {
    ociTitle = "nico-rest-cert-manager";
    extraCommands = ''
      mkdir -p app
      ln -sf /bin/credsmgr app/credsmgr
    '';
    entrypoint = [ "/app/credsmgr" ];
    user = "65534:65534";
    workingDir = "/app";
  };
  rest-api-flow = {
    ociTitle = "nico-flow";
    # tzdata's default `outputsToInstall` selects only its executables and
    # manuals. Flow needs the otherwise omitted `out` output that owns the
    # IANA zoneinfo tree used by time.LoadLocation.
    runtime = p: [ p.tzdata.out ];
    extraCommands = ''
      mkdir -p app usr/share
      ln -sf /bin/flow app/flow
      ln -sf /share/zoneinfo usr/share/zoneinfo
    '';
    entrypoint = [
      "/app/flow"
      "serve"
    ];
    user = "65534:65534";
  };
  rest-api-mcp = {
    ociTitle = "nico-mcp";
    extraCommands = ''
      mkdir -p app
      ln -sf /bin/nico-mcp app/nico-mcp
    '';
    entrypoint = [ "/app/nico-mcp" ];
    user = "65534:65534";
    workingDir = "/app";
  };
  rest-api-migrations = {
    ociTitle = "nico-rest-db";
    extraCommands = ''
      mkdir -p app
      ln -sf /bin/migrations app/migrations
    '';
    cmd = [
      "/app/migrations"
      "db"
      "init_migrate"
    ];
    user = "65534:65534";
    workingDir = "/app";
  };
  rest-api-nicocli = {
    runtime = p: with p; [ busybox ];
    extraCommands = ''
      mkdir -p app
      ln -sf /bin/nicocli app/nicocli
    '';
    entrypoint = [ "/app/nicocli" ];
    user = "65534:65534";
  };
  rest-api-psm = {
    ociTitle = "nico-psm";
    extraCommands = ''
      mkdir -p app
      ln -sf /bin/psm app/psm
    '';
    entrypoint = [
      "/app/psm"
      "serve"
    ];
    user = "65534:65534";
  };
  rest-api-site-agent = {
    ociTitle = "nico-rest-site-agent";
    extraCommands = ''
      mkdir -p app
      ln -sf /bin/site-agent app/site-agent
    '';
    entrypoint = [ "/app/site-agent" ];
    user = "65534:65534";
    workingDir = "/app";
  };
  rest-api-sitemgr = {
    ociTitle = "nico-rest-site-manager";
    extraCommands = ''
      mkdir -p app
      ln -sf /bin/sitemgr app/sitemgr
    '';
    entrypoint = [ "/app/sitemgr" ];
    user = "65534:65534";
    workingDir = "/app";
  };
  rest-api-workflow = {
    ociTitle = "nico-rest-workflow";
    extraCommands = ''
      mkdir -p app var/secrets/temporal/certs
      ln -sf /bin/workflow app/workflow
    '';
    entrypoint = [ "/app/workflow" ];
    user = "65534:65534";
    workingDir = "/app";
  };

  # ==========================================================================
  # Data-only machine-validation images
  # ==========================================================================

  machine-validation-runner = {
    runtime = p: with p; [ busybox ];
    extraCommands = ''
      mkdir -p usr/bin
      ln -sf /bin/env usr/bin/env
    '';
  };

  machine-validation-config = {
    runtime = p: with p; [ busybox ];
    cmd = [
      "/bin/sh"
      "-c"
      "trap : TERM INT; sleep 9999999999d & wait"
    ];
  };

  # ==========================================================================
  # Tooling images
  # ==========================================================================

  machine-a-tron = {
    # The container builder adds the CA bundle globally. libssl and libudev
    # arrive through the binary's RPATH closure rather than being named here.
    runtime =
      p: with p; [
        iproute2
        busybox
        ipmitool
        # Optional IPMI simulation validates and starts `ipmi_sim`; the
        # shipped example configuration exposes that supported mode.
        openipmi
      ];
    # Callers invoke it by its /opt path. Symlinked rather than copied so the
    # binary exists at exactly one location in the image.
    extraCommands = ''
      mkdir -p opt/machine-a-tron/bin
      ln -sf /bin/machine-a-tron opt/machine-a-tron/bin/machine-a-tron
      mkdir -p usr/bin
      ln -sf /bin/env usr/bin/env
      mkdir -p tmp/machine-a-tron-data
    '';
    entrypoint = [ "/opt/machine-a-tron/bin/machine-a-tron" ];
    workingDir = "/opt/machine-a-tron";
  };
}
