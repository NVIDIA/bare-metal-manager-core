{
  pkgs,
  # aarch64 package set, used for the arm64 binaries. Architecture has to come
  # from the package set rather than from an environment variable — see
  # mkGoBinary below for why.
  crossPkgs,
  # Default image tag — typically the git revision of the workspace.
  version,
  # The build host's system string, used to select the native GOARCH for
  # container images. "aarch64-linux" → "arm64", everything else → "amd64".
  system,
  # Path to the rest-api/ subtree (passed from flake.nix so the path resolves
  # relative to the repo root, not this file).
  src,
  # go.mod vendor hash. TOFU on first build:
  #   1. Set to pkgs.lib.fakeHash.
  #   2. Run `nix build .#rest-api-api` — the build fails with a "hash
  #      mismatch" error printing the expected sha256.
  #   3. Copy that sha256 here and rebuild.
  # All rest-api binaries share this hash: they all live under the same
  # go.mod, so vendoring is identical for each.
  vendorHash,
}:

# Build one Go binary from the rest-api workspace.
#
# The rest-api/ tree is a single Go module (rest-api/go.mod) with a `replace`
# directive pointing at the in-tree rest-api/sdk/standard submodule. Default
# vendoring resolves that from the source tree, so `vendorHash` covers the
# `go mod vendor` output; proxyVendor is not enabled.
#
# Each production binary lives at <service>/cmd/<binary>/main.go; we build with
# CGO_ENABLED=0 and `-linkmode internal` — see the note by `ldflags` below for
# why the Makefile's `-extldflags '-static'` is not carried over. Static Go
# binaries make raw syscalls — no glibc, no ELF interpreter to patchelf — so
# they run on any Linux of the matching arch.
# Cross-compiling to aarch64 means building against an aarch64 package set;
# see the note on GOARCH below for why setting it directly does nothing.
let
  mkGoBinary =
    {
      pname,
      subPackage, # path relative to rest-api/, e.g. "api/cmd/api"
      binaryName ? null, # filename inside $out/bin; defaults to baseNameOf subPackage
      # The package set to build with. This is what selects the target
      # architecture: buildGoModule derives GOOS/GOARCH from its own `go`,
      # which follows the package set's platform.
      #
      # Setting env.GOARCH here does nothing at all. nixpkgs'
      # pkgs/build-support/go/module.nix ends with
      #
      #     env = args.env or { } // { inherit (go) GOOS GOARCH; };
      #
      # so anything the caller passes is overwritten unconditionally. That is
      # worth stating explicitly because the failure is silent: the build
      # succeeds, the attribute is still named -aarch64, and the binary inside
      # is amd64.
      buildPkgs ? pkgs,
    }:
    let
      defaultName = baseNameOf subPackage;
      outName = if binaryName == null then defaultName else binaryName;
    in
    buildPkgs.buildGoModule {
      inherit pname version src vendorHash;
      subPackages = [ subPackage ];

      # Static + no libc dep, matching what rest-api/Makefile produces for
      # production. CGO off is also what keeps cross-compiling free: no C
      # toolchain is involved, so the cross package set costs nothing beyond a
      # different go.
      env.CGO_ENABLED = "0";

      # `-linkmode internal` rather than the Makefile's `-extldflags '-static'`.
      # With CGO disabled the external linker never runs, so -extldflags is
      # inert — it described the intent without enforcing it, and on a cross
      # build it actively broke things: it pulled in the external linker, which
      # then failed on `cannot find -lc` because there is no static aarch64
      # libc. Asking for internal linking says the same thing in a way that
      # holds on both architectures.
      #
      # Without it, cross builds come out *dynamically* linked against a
      # /nix/store glibc, because nixpkgs' Go cross setup exports GO_LDSO and
      # Go then emits a PT_INTERP. That still runs inside an image built from
      # the closure, so it fails quietly rather than loudly.
      ldflags = [ "-linkmode internal" ];

      # buildGoModule names the output after the last path component of
      # subPackage (e.g. "api/cmd/api" → bin/api). Rename when the Makefile
      # uses a `-o <name>` that differs (e.g. cli/cmd/cli → nicocli).
      postInstall = pkgs.lib.optionalString (outName != defaultName) ''
        mv $out/bin/${defaultName} $out/bin/${outName}
      '';

      meta.mainProgram = outName;
    };

  # Per-arch binary specs. Mirrors rest-api/Makefile and docker/production/.
  buildSpec = [
    { pname = "rest-api-api";        subPackage = "api/cmd/api"; }
    { pname = "rest-api-workflow";   subPackage = "workflow/cmd/workflow"; }
    { pname = "rest-api-sitemgr";    subPackage = "site-manager/cmd/sitemgr"; }
    { pname = "rest-api-site-agent"; subPackage = "site-agent/cmd/site-agent"; }
    { pname = "rest-api-migrations"; subPackage = "db/cmd/migrations"; }
    { pname = "rest-api-credsmgr";   subPackage = "cert-manager/cmd/credsmgr"; }
    { pname = "rest-api-flow";       subPackage = "flow"; }
    { pname = "rest-api-psm";        subPackage = "powershelf-manager"; binaryName = "psm"; }
    {
      # Source is cli/cmd/cli/ but the Makefile names the binary `nicocli`.
      # buildGoModule would name it `cli` by default; renamed via binaryName.
      pname = "rest-api-nicocli";
      subPackage = "cli/cmd/cli";
      binaryName = "nicocli";
    }
    {
      # Dockerfile copies binary to /app/nsm; buildGoModule would produce
      # nvswitch-manager from the directory name.
      pname = "rest-api-nsm";
      subPackage = "nvswitch-manager";
      binaryName = "nsm";
    }
    {
      pname = "rest-api-mcp";
      subPackage = "mcp/cmd/nico-mcp";
      binaryName = "nico-mcp";
    }
  ];

  # Build the full set of rest-api binaries for one GOARCH. The goarch string
  # is kept as the caller-facing name because that is what the container specs
  # in flake.nix speak, but it only selects a package set.
  pkgsForGoarch = goarch: if goarch == "arm64" then crossPkgs else pkgs;

  binariesFor =
    goarch:
    pkgs.lib.listToAttrs (
      map (spec: {
        name = spec.pname;
        value = mkGoBinary (spec // { buildPkgs = pkgsForGoarch goarch; });
      }) buildSpec
    );

  # GOARCH matching the build host — used for container images so the image
  # arch matches the host that built it (no cross needed for the native case).
  nativeGoarch = if system == "aarch64-linux" then "arm64" else "amd64";

in
{
  inherit binariesFor;

  # Native-arch binaries (for container images built on this host).
  binariesNative = binariesFor nativeGoarch;

  # Explicit amd64 and arm64 sets (for packages output, which exposes both
  # arches from a single x86_64-linux host). The arm64 set gets -aarch64
  # suffixed names so amd64 and aarch64 don't collide in the same attrset.
  binariesAmd64 = binariesFor "amd64";
  binariesArm64 = pkgs.lib.mapAttrs' (
    name: drv: pkgs.lib.nameValuePair "${name}-aarch64" drv
  ) (binariesFor "arm64");
}
