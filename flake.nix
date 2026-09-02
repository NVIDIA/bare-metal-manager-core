/*
  BUILDING TARGETS
  ================

  List every available build target:

    nix flake show

  Build a specific target (output lands in ./result):

    nix build .#<name>

  VERSION comes from git describe when you pass `.git-describe` (gitignored)
  as the `git-describe` input. `scripts/nix-with-git-describe.sh` writes that
  file and adds the override. Bare `nix build .#<name>` uses the revCount
  fallback in nix/version.nix.

  Common examples:

    nix build .#carbide-api                    # native x86_64 binary
    nix build .#carbide-api-container          # x86_64 OCI container image
    nix build .#carbide-api-container-arm64    # arm64 OCI container image
    nix build .#carbide-dhcp                   # Kea hook library (libdhcp.so)
    nix build .#carbide-dhcp-container         # x86_64 DHCP container
    nix build .#ipxe-efi-x86                   # iPXE EFI bootloader
    nix build .#release-check-aarch64-page-size # explicit release ELF gate

  The boot-artifacts carrier image is built by cargo-make, not Nix:

    cargo make --cwd pxe nix-ipxe-x86_64       # stage Nix iPXE into static/
    cargo make --cwd pxe build-boot-artifacts-x86-host

  List every target:

    nix flake show

  Containers carry their copy helpers in passthru rather than as `nix run`
  targets:

    nix build .#carbide-api-container
    $(nix eval --raw .#carbide-api-container.passthru.copyToRegistry)/bin/copy-to-registry

  Enter the dev shell (Rust toolchain + all build tools):

    nix develop

  WHERE TO MAKE CHANGES

    nix/services/default.nix   what goes into a service's container image —
                               runtime tools, entrypoint, directory fixups
    nix/container/             the container builder
    nix/rust/                  how binaries are compiled
    nix/boot/                  iPXE bootloaders
    nix/third-party/           vendor packages nixpkgs does not carry

  Nix language quick reference
  Full docs: https://nix.dev/tutorials/nix-language
             https://nix.dev/manual/nix/2.26/language/
  nixpkgs lib search: https://noogle.dev

  KEY PROPERTIES
  ==============

  1. Everything is an expression — there are no statements. `if`, `let`, and
     `with` all produce values. In imperative languages `if` executes code; in
     Nix it evaluates to whichever branch was taken:

     buildInputs = if pkgs.stdenv.isLinux then [ pkgs.libudev ] else [];

     `let` evaluates to whatever follows `in`:

     let
       x = 5;
       label = if x > 3 then "big" else "small";
     in
     label  # -> "big"

  2. Immutable — bindings cannot be changed after they are set. `//` does not
     mutate an attrset; it produces a new one with the right-hand side winning
     on duplicate keys:

     { a = 1; b = 2; } // { b = 99; }  # -> { a = 1; b = 99; }

  3. Lazy — expressions are only evaluated when their value is needed.
     Evaluating a flake (e.g. `nix flake show`) does not build anything; a
     derivation is only realised when you explicitly request it (`nix build`).
     This is why a flake with hundreds of packages doesn't try to build them
     all up front.

  4. Functional — functions are first-class values. `rustToolchainFor` below is
     a plain binding that happens to hold a function.

  TYPES
  =====
  string, integer, boolean, null, list, attrset, path, function, derivation.
  There is no type system; type errors surface at evaluation time.

  FUNCTIONS
  =========
  Functions are defined with a colon — `argument: body`:

    x: x + 1          # anonymous function
    (x: x + 1) 5      # -> 6

  Bind a name in a `let`:

    let addOne = x: x + 1;
    in addOne 5        # -> 6

  Multiple arguments use currying — each `:` adds one parameter:

    let add = x: y: x + y;
    in add 3 4         # -> 7

  Attrset destructuring (the dominant pattern in nixpkgs and flakes):

    let
      say = { name, statement }: "${name}. ${statement}!";
    in
    say { name = "Joseph Miller"; statement = "it reaches out"; }

  `{ pkgs, system, version, ... }: ...` is a function that destructures named
  fields from an attrset. `...` means "accept extra fields I haven't named".

  COMMON SYNTAX
  =============

  inherit — shorthand for copying a binding by name:
    inherit pkgs;            # same as: pkgs = pkgs;
    inherit (foo) a b;       # same as: a = foo.a; b = foo.b;

  with — bring all attributes of a set into scope for one expression:
    with pkgs; [ curl openssl tpm2-tools ]
    # equivalent to: [ pkgs.curl pkgs.openssl pkgs.tpm2-tools ]

  import — evaluate a .nix file, optionally calling it as a function:
    import ./nix/rust/crate-binary.nix { inherit craneLib commonArgs; }
    # Reads the file, which returns a function, then calls it with the attrset.

  Paths vs strings — path literals (no quotes) are copied into the Nix store
  and resolve relative to the file they appear in:
    src = ./rest-api;      # path — added to the store, works as a source
    src = "./rest-api";    # string — NOT a path; will fail as a derivation src

  String interpolation uses ${ }:
    "--prefix=${pkgs.openssl}/lib"

  FLAKE STRUCTURE
  ===============
  A flake is an attrset with `description`, `inputs`, and `outputs`. The
  `outputs` attribute is a function that receives the resolved inputs and
  returns the flake's public attrset (packages, devShells, apps, etc.).
  The body of `outputs` is one large `let ... in` block — all the derivations
  and helper functions in this file live in that `let`.
*/

{
  description = "Infra Manager (Carbide) — Nix build infrastructure";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

    # crane: two-phase Rust build caching (deps separate from source).
    crane.url = "github:ipetkov/crane";

    # flake-utils: helpers for multi-system outputs (x86_64, aarch64).
    flake-utils.url = "github:numtide/flake-utils";

    # rust-overlay: provides exact Rust toolchain versions.
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    # nix2container: OCI-native image metadata with direct copy helpers.
    nix2container = {
      url = "github:nlewo/nix2container";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    # `git describe --tags --first-parent --always`. Default is an empty
    # placeholder; gitignored `.git-describe` is not in the flake source, so
    # pass it as this input:
    #   git describe --tags --first-parent --always > .git-describe
    #   nix build .#carbide-api --override-input git-describe path:$PWD/.git-describe
    # `scripts/nix-with-git-describe.sh` does both. Without the override,
    # VERSION falls back to reconstructing describe from self.revCount and the
    # anchor in nix/version.nix.
    git-describe = {
      url = "path:./nix/empty-git-describe";
      flake = false;
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      crane,
      flake-utils,
      rust-overlay,
      nix2container,
      git-describe,
    }:
    let
      versionAnchor = import ./nix/version.nix;
      sourceRevision =
        self.rev
          or (if self ? dirtyRev then builtins.replaceStrings [ "-dirty" ] [ "" ] self.dirtyRev else null);
      sourceDirty = self ? dirtyRev;
      describeText = versionAnchor.trimDescribe (builtins.readFile git-describe);
      versionData =
        if describeText == "" then
          versionAnchor.forSource {
            inherit sourceRevision sourceDirty;
            sourceRevCount = self.revCount or null;
          }
        else
          versionAnchor.fromDescribe describeText {
            inherit sourceRevision sourceDirty;
          };
      inherit (versionData) revision version;
    in
    # eachSystem iterates over an explicit list of systems, evaluating the
    # function for each, and merges the results into the flake outputs attrset.
    # https://github.com/numtide/flake-utils
    flake-utils.lib.eachSystem
      [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ]
      (
        system:
        let
          # Instantiate nixpkgs for this system. `import nixpkgs { system; }` is
          # how you get a package set bound to a specific platform — every
          # derivation in `pkgs` will be built for and run on `system`.
          pkgs = import nixpkgs {
            inherit system;
            config.allowUnfree = true;
            # overlays are a list of functions that patch or extend a package set.
            overlays = [
              rust-overlay.overlays.default
            ];
          };

          isLinux = pkgs.stdenv.isLinux;
          isX86Linux = system == "x86_64-linux";
          isAarch64Linux = system == "aarch64-linux";
          nativeOciArch =
            if isX86Linux then
              "amd64"
            else if isAarch64Linux then
              "arm64"
            else
              null;

          # Crane wants a function over the package set `p` rather than a pre-built
          # derivation so it can splice the toolchain through build/host/target
          # package sets correctly when cross-compiling.
          # https://github.com/oxalica/rust-overlay
          # Read the channel from rust-toolchain.toml rather than hardcoding it.
          # cargo-make, the Dockerfiles, and rustup all honour that file, so
          # duplicating the version here lets the flake silently drift onto a
          # different rustc than the one that produces the shipping binaries —
          # which it had (flake 1.95.0 vs rust-toolchain.toml 1.96.0).
          rustChannel = (builtins.fromTOML (builtins.readFile ./rust-toolchain.toml)).toolchain.channel;

          # Nightly is needed only for rustfmt: rustfmt.toml sets
          # unstable_features plus imports_granularity / group_imports /
          # format_code_in_doc_comments / normalize_doc_attributes, none of which
          # stable rustfmt accepts. Keep in sync with RUST_NIGHTLY in Makefile.toml.
          rustNightlyDate = "2026-06-16";

          # Components mirror what setup-nightly-rust installs via rustup:
          # rustfmt for the format checks, and rust-src/rustc-dev/llvm-tools for
          # carbide-lints, which is a rustc driver and links against rustc
          # internals. Supplying this from Nix means the lint tasks work under
          # `nix develop` without rustup — the Nix cargo rejects `+toolchain`.
          rustNightlyToolchain = pkgs.rust-bin.nightly.${rustNightlyDate}.default.override {
            extensions = [
              "rustfmt"
              "rust-src"
              "rustc-dev"
              "llvm-tools-preview"
            ];
          };

          rustToolchainFor =
            p:
            p.rust-bin.stable.${rustChannel}.default.override {
              extensions = [
                "rust-src"
                "rust-analyzer"
              ];
              targets = [
                "aarch64-unknown-linux-gnu"
              ];
            };

          # Initialize crane with the custom Rust toolchain above. All craneLib.*
          # calls in this file use this instance.
          # https://crane.dev/API.html#cranemklib
          craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchainFor;

          # nix2container library — provides buildImage and the OCI layer-diffing
          # machinery used by mkContainer.
          # https://github.com/nlewo/nix2container
          nix2containerLib = nix2container.packages.${system}.nix2container;

          # Skopeo-based copy helpers: copyToDockerDaemon, copyToRegistry, copyTo.
          # Uses a patched skopeo with the nix: transport so images can be copied
          # straight from the Nix store without a docker load round-trip.
          containerCopyHelpers = import ./nix/container/nix2container-skopeo.nix {
            inherit pkgs;
            skopeoNix2container = nix2container.packages.${system}.skopeo-nix2container;
          };

          # ====================================================================
          # System dependencies
          # ====================================================================
          nativeBuildInputs =
            (with pkgs; [
              cmake
              clang
              pkg-config
              protobuf
            ])
            ++ pkgs.lib.optionals isLinux (
              with pkgs;
              [
                # lld and autoPatchelfHook are Linux-only: macOS uses ld64 and
                # does not have ELF RPATH patching.
                lld
                # autoPatchelfHook embeds Nix-store paths in RPATH so the binary
                # finds its .so deps without LD_LIBRARY_PATH. Production
                # deployment ships the binaries inside containers via
                # mkContainer, which bundles the full /nix/store closure;
                # /nix/store paths exist inside the image so RPATH resolves
                # cleanly.
                autoPatchelfHook
              ]
            );

          # Union of every C library any crate in the workspace might link.
          #
          # The deps phase (cargoArtifacts) needs this complete set: cargo
          # compiles every external crate including -sys crates whose build.rs
          # calls pkg-config for "their" library. Missing any one library
          # fails the deps phase even if no individual binary needs it.
          #
          # Version assertion: libudev-zero is a drop-in libudev replacement
          # linked into every Rust binary. A version bump warrants a sanity
          # check before accepting. Update the string below after verifying.
          allBuildInputs = pkgs.lib.optionals isLinux (
            assert
              pkgs.libudev-zero.version == "1.0.3"
              || builtins.throw ''
                libudev-zero version changed to ${pkgs.libudev-zero.version}.
                Verify ABI compatibility, then update the assertion in flake.nix.
              '';
            [
              pkgs.libudev-zero
              pkgs.tpm2-tss.dev
              # Rust binaries implicitly depend on libgcc_s.so.1.
              # Putting it in buildInputs makes autoPatchelfHook find it and write
              # the correct /nix/store RPATH entry.
              pkgs.stdenv.cc.cc.lib
            ]
          );

          # ====================================================================
          # Source filtering
          # ====================================================================

          # Declare sources additively using filesets. We start with crane's
          # defaults (Cargo.{toml,lock}, .rs files, rust-toolchain.toml) and add
          # extra non-Rust files referenced at build or test time. Being explicit
          # about what's included means changes outside these paths (helm charts,
          # READMEs, etc.) don't invalidate the Nix build cache.
          # The deps cache (cargoArtifacts) uses the narrower `depsSrc` below,
          # so .rs-only changes don't force an external-crate rebuild.

          # https://noogle.dev/f/lib/fileset/toSource/
          # Two workspace members are kept out of every source below. Both hold
          # their only cargo targets in `tests/`, and crane builds dependencies
          # from a copy of the tree with first-party sources stripped — which
          # would leave each of them a Cargo.toml declaring no target at all, and
          # cargo rejects the whole workspace over that. `members` is a
          # `crates/*` glob, so omitting the directories is enough: cargo never
          # looks for what it cannot see. Neither crate is a dependency of
          # anything, and neither is buildable here anyway — both need a live
          # postgres.
          #
          # This has to be subtracted from `depsSrc` as well as `src`. They are
          # built from the tree independently, so excluding it from one alone
          # leaves the other still carrying the targetless manifest.
          excludedCrates = pkgs.lib.fileset.unions [
            ./crates/api-integration-tests
            ./crates/postgres-smoke-test
          ];

          src = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset =
              pkgs.lib.fileset.difference
                # https://noogle.dev/f/lib/fileset/unions/
                (pkgs.lib.fileset.unions [
                  # Deliberately not craneLib.fileset.commonCargoSources: that is
                  # cargoTomlAndLock ∪ rust ∪ toml, and its `toml` component matches
                  # *every* .toml in the tree. At the repo root that pulls in
                  # Makefile.toml, clippy.toml, deny.toml, Cross.toml and .taplo.toml
                  # — none of which cargo reads during a build, but all of which would
                  # then invalidate every binary and container on a cargo-make edit.
                  # https://crane.dev/API.html#cranelibfilesetcargotomlandlock
                  (craneLib.fileset.cargoTomlAndLock ./.)
                  # https://crane.dev/API.html#cranelibfilesetrust
                  (craneLib.fileset.rust ./.)
                  ./crates
                  # Non-Rust files outside crates/ referenced at build/test time.
                  ./.cargo
                  # PXE boot templates referenced by crates via
                  # include_str!("").
                  ./pxe/templates
                  ./pxe/ipxe/local
                  # bmc-mock embeds the ipmi_sim fixtures with include_bytes!, and it
                  # is a regular dependency of machine-a-tron rather than a dev-only
                  # one, so these are needed for a release build and not just tests.
                  ./dev/ipmi
                ])
                excludedCrates;
          };

          # Derive immutable build metadata before the source is copied into the
          # Nix sandbox, where .git is intentionally unavailable. VERSION is an
          # application contract: upgrade policy parses Git-describe syntax, and
          # the derived Helm version must be valid SemVer.
          helmVersion =
            let
              withoutV = pkgs.lib.removePrefix "v" version;
              parts = pkgs.lib.reverseList (pkgs.lib.splitString "-" withoutV);
              isDescribe =
                builtins.length parts >= 3
                && builtins.match "g[0-9a-f]+" (builtins.elemAt parts 0) != null
                && builtins.match "[0-9]+" (builtins.elemAt parts 1) != null;
            in
            if isDescribe then
              let
                suffix = "${builtins.elemAt parts 1}.${builtins.elemAt parts 0}";
                prefixParts = pkgs.lib.reverseList (pkgs.lib.drop 2 parts);
              in
              "${builtins.concatStringsSep "-" prefixParts}-${suffix}"
            else
              withoutV;
          buildDate =
            let
              timestamp = self.lastModifiedDate or "19700101000000";
            in
            assert builtins.stringLength timestamp == 14;
            "${builtins.substring 0 4 timestamp}-${builtins.substring 4 2 timestamp}-${
              builtins.substring 6 2 timestamp
            }T${builtins.substring 8 2 timestamp}:${builtins.substring 10 2 timestamp}:${
              builtins.substring 12 2 timestamp
            }Z";

          # `carbide-version` intentionally blanks VERSION and the revision
          # when `.git` is absent, even if callers provide those values. Nix
          # source trees never contain `.git`, so final package builds receive
          # a narrowly scoped Git facade. It answers only the probes made by
          # that build helper and delegates every other command to real Git.
          # This preserves the application source and the existing build path.
          versionGitShim = pkgs.writeShellApplication {
            name = "git";
            text = ''
              if [[ "$#" -eq 1 && "$1" == "rev-parse" ]]; then
                exit 0
              fi
              if [[ "$#" -eq 1 && "$1" == "status" ]]; then
                exit 0
              fi
              if [[ "$#" -eq 3 && "$1" == "log" && "$2" == "-1" && "$3" == "--format=%cI" ]]; then
                printf '%s\n' ${pkgs.lib.escapeShellArg buildDate}
                exit 0
              fi
              exec ${pkgs.git}/bin/git "$@"
            '';
          };

          buildMetadata = {
            VERSION = version;
            CI_COMMIT_SHORT_SHA = revision;
            CARBIDE_BUILD_DATE = buildDate;
            CARBIDE_BUILD_HELM_VERSION = helmVersion;
            FORGE_VERSION_AVOID_REBUILD = "1";
            CARBIDE_VERSION_AVOID_REBUILD = "1";
            USER = "nix-builder";
            HOSTNAME = "nix-build";
            preBuild = ''
              export PATH=${versionGitShim}/bin:"$PATH"
            '';
          };

          # ====================================================================
          # Common arguments shared by all crane derivations.
          # ====================================================================
          commonArgs = {
            inherit
              src
              nativeBuildInputs
              ;

            # Keep commit identity out of the dependency-only derivation. The
            # first-party package wrappers below inject it only where build
            # scripts can embed it in a shipped artifact.
            version = "workspace-dependencies";

            # Note: no buildInputs here. The deps phase and mkCrateBinary inject
            # `allBuildInputs` explicitly; individual binaries can append extra
            # inputs via extraArgs without affecting the shared dep-phase cache.
            pname = "carbide-workspace";
            strictDeps = true;
            doCheck = false;

            # Workspace-wide env vars.
            # The Nix sandbox has no network and no database. SQLX_OFFLINE tells
            # sqlx to use the pre-generated .sqlx/ query metadata checked into the
            # repo rather than connecting to a live Postgres instance at compile time.
            # Run `cargo sqlx prepare` against a real DB to regenerate .sqlx/ after
            # query changes, then commit the result.
            SQLX_OFFLINE = "true";
            PROTOC = "${pkgs.protobuf}/bin/protoc";
            PROTOC_INCLUDE = "${pkgs.protobuf}/include";
            # clang is already in nativeBuildInputs as the C compiler for -sys crates;
            # using it as the linker driver lets Cargo find lld (also in
            # nativeBuildInputs) without any additional path wiring.
            CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER = "clang";
          }
          // pkgs.lib.optionalAttrs isAarch64Linux {
            # Native ARM64 builds need the same PT_LOAD alignment as cross
            # builds. This keeps binaries loadable on both 4 KiB and 64 KiB
            # kernels regardless of the architecture of the build runner.
            CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS = "-C link-arg=-Wl,-z,max-page-size=0x10000";
          };

          # ====================================================================
          # Phase 1: Build only workspace dependencies.
          #
          # This derivation compiles every external crate dependency but none
          # of the carbide source. Input hash depends only on Cargo.lock and
          # Cargo.toml files, so source-only changes get a cache hit here.
          # ====================================================================

          # cleanCargoSource is toSource over commonCargoSources; spelled out
          # here so the excluded crates can be subtracted from it.
          # https://crane.dev/API.html?highlight=cleanCargoSource#cranelibcleancargosource
          depsSrc = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.difference (craneLib.fileset.commonCargoSources ./.) excludedCrates;
          };

          # buildDepsOnly → mkCargoDerivation → stdenv.mkDerivation. Functions
          # that wrap mkDerivation accept `...` and forward unknown arguments
          # straight through, which is why passing `buildInputs` here works even
          # though buildDepsOnly doesn't explicitly declare that parameter.
          # https://crane.dev/API.html#cranelibbuilddepsonly
          # https://nixos.org/manual/nixpkgs/stable/#var-stdenv-buildInputs
          cargoArtifacts = craneLib.buildDepsOnly (
            commonArgs
            // {
              src = depsSrc;

              # Deps phase compiles every external -sys crate; needs the full
              # library union so each one's build.rs finds its C library via
              # pkg-config.
              buildInputs = allBuildInputs;
            }
          );

          # Builds one native workspace binary, reusing the pre-compiled external
          # crate cache from cargoArtifacts. See nix/rust/crate-binary.nix.
          mkCrateBinaryWithoutMetadata = import ./nix/rust/crate-binary.nix {
            inherit
              craneLib
              commonArgs
              cargoArtifacts
              allBuildInputs
              ;
            targetOciArch = nativeOciArch;
          };
          mkCrateBinary =
            args:
            mkCrateBinaryWithoutMetadata (
              args
              // {
                # Keep per-commit values out of the shared dependency derivation;
                # only first-party binary builds consume embedded metadata.
                extraArgs = (args.extraArgs or { }) // buildMetadata;
                version = version;
              }
            );

          mkCrateHookLib = import ./nix/rust/crate-hook-lib.nix {
            inherit
              craneLib
              commonArgs
              cargoArtifacts
              allBuildInputs
              ;
            targetOciArch = nativeOciArch;
          };
          mkCrateHookLibWithMetadata =
            args:
            mkCrateHookLib (
              args
              // {
                extraArgs = (args.extraArgs or { }) // buildMetadata;
                version = version;
              }
            );

          # ====================================================================
          # Cross-compile pipeline for aarch64 binaries.
          #
          # Used for binaries that ship to aarch64 systems (carbide-scout,
          # carbide-agent, forge-dhcp-server, etc.). The helper intentionally
          # does not reuse native cargoArtifacts because x86_64 deps cannot be
          # reused for an aarch64 link; crane derives target-specific deps from
          # each cross package's args.
          # ====================================================================
          # pkgsCross.aarch64-multiplatform is a nixpkgs package set where every
          # derivation is built for aarch64-linux using a cross-compiler running
          # on the host. The stdenv override selects gcc 13 — matching Ubuntu
          # 24.04 and the iPXE EFI binary, which ipxe-x86.nix also builds with
          # gcc 13 — for the derivations we build *through* crossPkgs.stdenv.
          #
          # This is a top-level `//` rather than `.extend`, so it does not rebuild
          # the package set's fixed point: packages taken from this set (kea,
          # busybox, openvswitch) still compile with the nixpkgs default gcc.
          # That is deliberate. Both stdenvs resolve to the same glibc, so there
          # is nothing to reconcile, and rebuilding the whole cross closure on a
          # two-generation-old compiler would cost far more than it buys.
          aarch64CrossPkgs = pkgs.pkgsCross.aarch64-multiplatform // {
            stdenv = pkgs.pkgsCross.aarch64-multiplatform.gcc13Stdenv;
          };

          # Use a package set whose Go toolchain has the requested target. Nixpkgs
          # overwrites a caller-provided GOARCH with `go.GOARCH`, so merely setting
          # an environment variable would produce a correctly named package with
          # the wrong ELF architecture.
          goTargetPkgs = pkgs.lib.optionalAttrs isLinux {
            amd64 = if isX86Linux then pkgs else pkgs.pkgsCross.gnu64;
            arm64 = if isAarch64Linux then pkgs else aarch64CrossPkgs;
          };

          mkCrossHookLib = import ./nix/rust/cross-crate-hook-lib-aarch64.nix {
            inherit
              pkgs
              crane
              rustToolchainFor
              src
              version
              ;
            crossPkgs = aarch64CrossPkgs;
          };

          mkCrossCrateBinaryWithoutMetadata = import ./nix/rust/cross-crate-binary-aarch64.nix {
            inherit
              pkgs
              crane
              rustToolchainFor
              src
              version
              ;
            crossPkgs = aarch64CrossPkgs;
          };
          mkCrossCrateBinary =
            args:
            mkCrossCrateBinaryWithoutMetadata (
              args
              // {
                extraArgs = (args.extraArgs or { }) // buildMetadata;
              }
            );

          mkKeaLibShim =
            p:
            pkgs.runCommand "kea-lib-shim-${p.kea.version}" { } ''
              mkdir -p $out/lib
              ln -sf ${p.kea}/lib/libkea-*.so* $out/lib/
              ln -sf ${p.kea}/lib/libkea-dhcp.so $out/lib/libkea-dhcp++.so
            '';

          #
          # Version assertion: libdhcp.so links against libkea-*.so with
          # ABI-versioned SONAMEs. A Kea major version bump changes those SONAMEs,
          # breaking hook loading at runtime with an opaque dlopen error. Update
          # the string below after verifying hook ABI compatibility.
          dhcpCrateExtraArgs =
            dhcpPkgs:
            assert
              dhcpPkgs.kea.version == "3.0.3"
              || builtins.throw ''
                kea version changed to ${dhcpPkgs.kea.version}.
                libdhcp.so links against libkea-*.so — verify hook ABI compatibility
                before accepting. Then update the assertion in flake.nix.
              '';
            {
              buildInputs = with dhcpPkgs; [
                stdenv.cc.cc.lib
                kea
                boost.dev
              ];
              KEA_INCLUDE_PATH = "${dhcpPkgs.kea}/include/kea";
              KEA_LIB_PATH = "${mkKeaLibShim dhcpPkgs}/lib";
            };

          # Shared metadata applied to every carbide workspace binary.
          # make-container.nix reads meta.license and meta.homepage to build each
          # image's attributions.txt; SBOM tooling reads the same two fields.
          carbideMeta = {
            license = pkgs.lib.licenses.asl20;
            homepage = "https://github.com/NVIDIA/infra-controller";
            # A maintainer entry, not a bare address: nixpkgs' meta schema wants
            # attrsets here, and a string is rejected outright once checkMeta is
            # on. There is no upstream lib.maintainers handle for this team to
            # reference, so the entry is spelled out.
            maintainers = [
              {
                name = "Carbide";
                email = "carbide-dev@exchange.nvidia.com";
              }
            ];
          };

          # ====================================================================
          # Per-architecture binary sets
          #
          # The cargo PACKAGE names are carbide-* but each crate's [[bin]] target
          # may rename the BINARY to forge-* — so we build by package name and
          # downstream consumers see the forge-* binary in $out/bin/.
          # ====================================================================

          nativeLinuxMultiarch = if isAarch64Linux then "aarch64-linux-gnu" else "x86_64-linux-gnu";

          nativeRustBinaries = {
            carbide-api = mkCrateBinary {
              pname = "carbide-api";
              meta = carbideMeta;
            };
            carbide-dns = mkCrateBinary {
              pname = "carbide-dns";
              meta = carbideMeta;
            };
            carbide-pxe = mkCrateBinary {
              pname = "carbide-pxe";
              meta = carbideMeta;
            };
            carbide-dhcp = mkCrateHookLibWithMetadata {
              pname = "carbide-dhcp";
              libFileName = "libdhcp.so";
              installPath = "usr/lib/${nativeLinuxMultiarch}/kea/hooks/libdhcp.so";
              meta = carbideMeta;
              extraArgs = dhcpCrateExtraArgs pkgs;
            };
            carbide-dsx-exchange-consumer = mkCrateBinary {
              pname = "carbide-dsx-exchange-consumer";
              meta = carbideMeta;
            };
            nico-admin-cli = mkCrateBinary {
              pname = "nico-admin-cli";
              meta = carbideMeta;
            };
            carbide-health = mkCrateBinary {
              pname = "carbide-health";
              meta = carbideMeta;
            };
            carbide-ssh-console = mkCrateBinary {
              pname = "carbide-ssh-console";
              meta = carbideMeta;
            };
            # carbide-scout produces a binary named "forge-scout" (per the crate's
            # [[bin]] target); downstream packaging wraps it as needed.
            carbide-scout = mkCrateBinary {
              pname = "carbide-scout";
              meta = carbideMeta;
            };
            carbide-log-parser = mkCrateBinary {
              pname = "carbide-log-parser";
              meta = carbideMeta;
            };
            carbide-bmc-proxy = mkCrateBinary {
              pname = "carbide-bmc-proxy";
              meta = carbideMeta;
            };
          }
          // pkgs.lib.optionalAttrs isX86Linux {
            # Hardware simulation tool. x86_64 only — the Dockerfile it replaces
            # hardcoded --target x86_64-unknown-linux-gnu and a linux/amd64 runtime
            # stage, so there is deliberately no aarch64ServerBinaries entry.
            machine-a-tron = mkCrateBinary {
              pname = "carbide-machine-a-tron";
              meta = carbideMeta;
            };
          };

          # The deployed Core chart still uses one multi-binary image. These
          # DPU packages are built natively only for that compatibility image;
          # the standalone DPU images continue to use the arm64 package set.
          nativeCompatibilityOnlyBinaries = {
            forge-dpu-agent = mkCrateBinary {
              pname = "carbide-agent";
              meta = carbideMeta;
            };
            forge-dhcp-server = mkCrateBinary {
              pname = "carbide-dhcp-server";
              meta = carbideMeta;
            };
          };

          # DPU-side binaries. Build host can be either x86_64 or aarch64 —
          # pkgsCross.aarch64-multiplatform resolves to a real cross gcc on x86
          # hosts and to the native aarch64 gcc on aarch64 hosts.
          aarch64Binaries = {
            carbide-dpf = mkCrossCrateBinary {
              pname = "carbide-dpf";
              cargoExtraArgs = "--features driver --bin carbide-dpf-api-harness";
              meta = carbideMeta;
            };
            forge-dpu-agent = mkCrossCrateBinary {
              pname = "carbide-agent";
              meta = carbideMeta;
            };
            forge-dhcp-server = mkCrossCrateBinary {
              pname = "carbide-dhcp-server";
              meta = carbideMeta;
            };
            forge-dpu-otel-agent = mkCrossCrateBinary {
              pname = "carbide-dpu-otel-agent";
              meta = carbideMeta;
            };
            carbide-fmds = mkCrossCrateBinary {
              pname = "carbide-fmds";
              meta = carbideMeta;
            };
          };

          # Server-side binaries cross-compiled for aarch64. Used alongside
          # aarch64Binaries to build arm64 service containers from an x86_64 host.
          aarch64ServerBinaries =
            let
              mk =
                pname:
                mkCrossCrateBinary {
                  inherit pname;
                  meta = carbideMeta;
                };
            in
            (
              {
                carbide-api = mk "carbide-api";
                carbide-dns = mk "carbide-dns";
                carbide-pxe = mk "carbide-pxe";
                carbide-dsx-exchange-consumer = mk "carbide-dsx-exchange-consumer";
                nico-admin-cli = mk "nico-admin-cli";
                carbide-health = mk "carbide-health";
                carbide-ssh-console = mk "carbide-ssh-console";
                carbide-scout = mk "carbide-scout";
                carbide-log-parser = mk "carbide-log-parser";
                carbide-bmc-proxy = mk "carbide-bmc-proxy";
              }
              // pkgs.lib.optionalAttrs isAarch64Linux {
                # Kea's build does not support this cross configuration. A native
                # aarch64 builder can still produce the hook and its container.
                carbide-dhcp = nativeRustBinaries.carbide-dhcp;
              }
            );

          # Packages placed on every dev shell's PATH, and on the images that
          # declare them in nix/services/default.nix.
          runtimeTools = with pkgs; [
            curl
            ipmitool
            iproute2
            iputils # ping, traceroute, arping
            kea # kea-dhcp4-server + kea-ctrl-agent
            openipmi
            postgresql_15 # psql, pg_dump, etc.
            tpm2-tools
          ];

          carbide-scout-aarch64 = aarch64ServerBinaries.carbide-scout;

          # ====================================================================
          # Container builder — see nix/container/make-container.nix for the
          # two-phase build, OSRB artifacts, and parameter documentation.
          # ====================================================================
          mkOssSources = import ./nix/container/oss-sources.nix { inherit pkgs; };

          mkContainer = import ./nix/container/make-container.nix {
            inherit
              pkgs
              nix2containerLib
              containerCopyHelpers
              version
              revision
              mkOssSources
              ;
            created = buildDate;
          };

          # ====================================================================
          # iPXE EFI bootloaders
          #
          # Nix builds only the EFI binaries. Staging them into
          # pxe/static/blobs/internal/ and packaging the boot-artifacts carrier
          # image are cargo-make's job — see the nix-ipxe-* tasks in
          # pxe/Makefile.toml and dev/docker/Dockerfile.release-artifacts-*.
          #
          # Shared inputs for both arches: the upstream commit pin and the
          # carbide config headers. Each arch picks its own patch set and
          # DEBUG flags based on what it actually needs.
          #
          # ipxeRev must match the pxe/ipxe/upstream submodule, whose commit is
          # the gitlink in the tree rather than anything in .gitmodules:
          #
          #     git rev-parse HEAD:pxe/ipxe/upstream
          #
          # Nix cannot read a gitlink, so the two are kept in step by hand. When
          # upstream iPXE is bumped, update ipxeRev and ipxeHash together — the
          # first build with a new rev fails with a hash mismatch, so paste the
          # reported hash into ipxeHash and rebuild.
          # ====================================================================
          ipxeRev = "bbd7821bd42da5456ee068a471ef73d525ea26a1";
          ipxeHash = "sha256-5jzKYvIPkOP1Z7t7OsvmAaY0BI7g793jTh8MfrPpfP8=";
          ipxeConfigHeaders = [
            ./pxe/ipxe/local/branding.h
            ./pxe/ipxe/local/general.h
            ./pxe/ipxe/local/settings.h
          ];
          # Per-arch, matching pxe/Makefile.toml: `ipxe-x86_64` depends on
          # ipxe-patch-measured-boot and ipxe-patch-watchdog-timeout, while
          # `ipxe-aarch64` depends only on ipxe-patch-mlnx. Applying the union to
          # both would produce binaries that differ from what ships.
          ipxePatchesX86 = [
            ./pxe/ipxe/local/0001-efi-Add-TPM-measurement-API-via-TCG-v1-and-TCG-v2-EF.patch
            ./pxe/ipxe/local/0003-efi-prevent-load-image-watchdog-timeout.patch
          ];
          ipxePatchesAarch64 = [
            ./pxe/ipxe/local/0001-fix-update-to-allow-iPXE-to-boot-on-BlueField-NICs.patch
          ];

          ipxe-efi-x86 = import ./nix/boot/ipxe-x86.nix {
            inherit
              pkgs
              ipxeRev
              ipxeHash
              ipxeConfigHeaders
              ;
            ipxePatches = ipxePatchesX86;
            bannerVersion = "carbide-${version}";
            # Without EMBED= the EFI image runs only iPXE's built-in per-NIC
            # autoboot and falls through to "Nothing to boot" — no boot script
            # means no carbide DHCP next-server/filename handoff.
            embedScript = ./pxe/ipxe/local/embed.ipxe;
          };

          # Cross-compiled from x86_64 build hosts using
          # pkgsCross.aarch64-multiplatform.gcc13Stdenv.
          ipxe-efi-aarch64 = import ./nix/boot/ipxe-aarch64.nix {
            inherit
              pkgs
              ipxeRev
              ipxeHash
              ipxeConfigHeaders
              ;
            ipxePatches = ipxePatchesAarch64;
            bannerVersion = "carbide-${version}";
            embedScript = ./pxe/ipxe/local/embed.ipxe;
          };

          # Mellanox Firmware Tools. A function of the package set rather than a
          # fixed derivation, so the same spec entry serves both architectures —
          # mft.nix selects tarball, deb and ld.so from stdenv.hostPlatform.
          # ====================================================================
          # Go binaries
          #
          # Vendoring is identical for every binary — they share one go.mod — so
          # a single vendorHash covers the set. On a bump, set it to
          # pkgs.lib.fakeHash, build, and paste the reported value back.
          # ====================================================================
          restApiVendorHash = "sha256-oAnT1oSZl/OBhtwWgjP6N+K88W1VzPhE+sOdYNyRqpg=";

          restApi =
            if isLinux then
              import ./nix/go/rest-api.nix {
                inherit
                  pkgs
                  goTargetPkgs
                  version
                  buildDate
                  revision
                  ;
                meta = carbideMeta;
                src = ./rest-api;
                vendorHash = restApiVendorHash;
              }
            else
              null;
          restApiBinariesByArch =
            if isLinux then
              restApi.binariesByArch
            else
              {
                amd64 = { };
                arm64 = { };
              };
          restApiBinariesAmd64 = if isLinux then restApi.binariesAmd64 else { };
          restApiBinariesArm64 = if isLinux then restApi.binariesArm64 else { };

          # mat-k8s-controller is a standalone Go module, so its dependency
          # closure has a separate fixed-output vendoring hash.
          matK8sControllerVendorHash = "sha256-LGR4InHgda3Vo6o+m36MmYzmpcbNHS5/Fmgnzp5576c=";
          matK8sController =
            if isLinux then
              import ./nix/go/mat-k8s-controller.nix {
                inherit
                  pkgs
                  goTargetPkgs
                  version
                  ;
                meta = carbideMeta;
                src = ./dev/k8s/machine-a-tron-controller;
                vendorHash = matK8sControllerVendorHash;
              }
            else
              null;
          matK8sControllerBinariesByArch =
            if isLinux then
              matK8sController.binariesByArch
            else
              {
                amd64 = { };
                arm64 = { };
              };
          matK8sControllerBinariesAmd64 = if isLinux then matK8sController.binariesAmd64 else { };
          matK8sControllerBinariesArm64 = if isLinux then matK8sController.binariesArm64 else { };

          # Scripts and firmware bundled into the nsm container at the paths the
          # Dockerfile establishes (WORKDIR /opt/nvswitch-manager before COPY).
          nsmStaticFiles = pkgs.runCommand "rest-api-nsm-static" { } ''
            mkdir -p $out/opt/nvswitch-manager
            cp -r ${./rest-api/nvswitch-manager/scripts}  $out/opt/nvswitch-manager/scripts
            cp -r ${./rest-api/nvswitch-manager/firmware} $out/opt/nvswitch-manager/firmware
          '';

          pxeTemplateFiles = pkgs.runCommand "carbide-pxe-templates" { } ''
            mkdir -p "$out/opt/carbide/pxe"
            cp -r ${./pxe/templates} "$out/opt/carbide/pxe/templates"
          '';

          scoutFirmwareFiles = pkgs.runCommand "carbide-scout-firmware-scripts" { } ''
            mkdir -p "$out/opt/carbide/scout-firmware-scripts"
            cp -r ${./pxe/scout-firmware-scripts}/. "$out/opt/carbide/scout-firmware-scripts/"
          '';

          compatibilityStaticFiles = pkgs.runCommand "nvmetal-carbide-static" { } ''
            mkdir -p "$out/opt/carbide/migrations" "$out/opt/carbide/static"
            cp -r ${./crates/api-db/migrations}/. "$out/opt/carbide/migrations/"
            cp ${./crates/api/casbin-policy.csv} "$out/opt/carbide/casbin-policy.csv"
          '';

          machineValidationFiles = import ./nix/container/machine-validation.nix {
            inherit pkgs;
            configDir = ./crates/machine-validation/config;
            imagesDir = ./crates/machine-validation/images;
            scriptsDir = ./crates/machine-validation/scripts;
            skopeoNix2container = nix2container.packages.${system}.skopeo-nix2container;
          };

          mftFor = p: p.callPackage ./nix/third-party/mft.nix { };

          # Scout needs GNU timeout's long `--kill-after` option, but otherwise
          # relies on BusyBox for core utilities. Package only that executable
          # under /usr/bin so the two implementations do not collide in the
          # buildEnv; carrying coreutils metadata keeps OSS source generation
          # aligned with the executable actually added to the image.
          coreutilsTimeoutFor =
            p:
            p.runCommand "coreutils-timeout-${p.coreutils.version}"
              {
                pname = "coreutils-timeout";
                inherit (p.coreutils) version src meta;
              }
              ''
                mkdir -p "$out/usr/bin"
                ln -s ${p.coreutils}/bin/timeout "$out/usr/bin/timeout"
              '';

          # NVIDIA Data Center GPU Manager, from NVIDIA's Debian packages rather
          # than nixpkgs' `dcgm`. Consumed by the scout GPU image; exposed here
          # so it is buildable on its own.
          dcgm = pkgs.callPackage ./nix/third-party/dcgm-deb.nix { };

          # Prebuilt wobcom transceiver-exporter for aarch64 DPUs, scraped by the
          # nico-otelcol collector. Its container ships with the collector.
          transceiver-exporter-aarch64 = import ./nix/third-party/transceiver-exporter-aarch64.nix {
            inherit pkgs;
            crossPkgs = aarch64CrossPkgs;
          };

          otelcolContribAarch64 = import ./nix/third-party/otelcol-contrib-aarch64.nix {
            inherit pkgs;
            crossPkgs = aarch64CrossPkgs;
          };

          serviceSpecs = import ./nix/services {
            inherit
              mftFor
              coreutilsTimeoutFor
              nsmStaticFiles
              otelcolContribAarch64
              pxeTemplateFiles
              scoutFirmwareFiles
              ;
          };

          # ====================================================================
          # Per-service containers — one image per binary per architecture.
          #
          # amd64 images use nativeRustBinaries and native pkgs runtime tools.
          # arm64 images use the cross-compiled binaries and aarch64CrossPkgs
          # runtime tools.
          #
          # Each image bakes in, for OSRB compliance:
          #   /usr/share/oss-sources/               OSS source tarballs
          #   /usr/share/carbide/attributions.txt   license notices
          #
          # Exposed at:
          #   nix build .#carbide-api-container          # amd64
          #   nix build .#carbide-api-container-arm64    # arm64
          # ====================================================================
          containers =
            let
              mkServiceContainer =
                services: name: pkg: p:
                let
                  # Services with nothing to declare need only their primary
                  # binary in the Nix-built root.
                  spec = serviceSpecs.${name} or { };
                  additionalPackages = map (
                    packageName:
                    assert pkgs.lib.assertMsg (builtins.hasAttr packageName services) ''
                      ${name}: additional package ${packageName} is unavailable for ${p.go.GOARCH}.
                    '';
                    services.${packageName}
                  ) (spec.additionalPackageNames or [ ]);
                in
                mkContainer {
                  inherit name;
                  packages = [ pkg ] ++ additionalPackages;
                  # Derived from the package set this image is built with, not
                  # from the flake's native pkgs. The unsuffixed attributes are
                  # native — amd64 on an x86 host, arm64 on an aarch64 one — so a
                  # hardcoded string would mislabel one of the two.
                  arch = p.go.GOARCH;
                  # `runtime` is a function of the package set so one spec serves
                  # both architectures; see nix/services/default.nix.
                  runtime = if spec ? runtime then spec.runtime p else [ ];
                  firstPartyContents = spec.firstPartyContents or [ ];
                  extraCommands =
                    if spec ? extraCommands then
                      if builtins.isFunction spec.extraCommands then spec.extraCommands p else spec.extraCommands
                    else
                      "";
                  optCarbideAliases = spec.optCarbideAliases or [ ];
                  optCarbideDirs = spec.optCarbideDirs or [ ];
                  entrypoint = spec.entrypoint or null;
                  cmd = spec.cmd or null;
                  user = spec.user or null;
                  workingDir = spec.workingDir or null;
                  env = spec.env or [ ];
                  ociTitle = spec.ociTitle or name;
                  includePrimarySources = spec.includePrimarySources or false;
                  meta = carbideMeta;
                };

              mkContentContainer =
                name: contents: p:
                let
                  spec = serviceSpecs.${name};
                in
                mkContainer {
                  inherit name;
                  packages = [ ];
                  firstPartyContents = [ contents ];
                  arch = p.go.GOARCH;
                  runtime = if spec ? runtime then spec.runtime p else [ ];
                  extraCommands = spec.extraCommands or "";
                  entrypoint = spec.entrypoint or null;
                  cmd = spec.cmd or null;
                  user = spec.user or null;
                  workingDir = spec.workingDir or null;
                  env = spec.env or [ ];
                  meta = carbideMeta;
                };

              # list.json is consumed on provisioned machines, not by the
              # carrier container itself. Build its amd64 runner payload once
              # as a Docker archive, then embed that same payload in both OCI
              # architectures of the config carrier.
              machineValidationRunnerContainer =
                mkContentContainer "machine-validation-runner" machineValidationFiles.runnerFiles
                  goTargetPkgs.amd64;
              machineValidationRunnerArchive = machineValidationFiles.mkRunnerArchive machineValidationRunnerContainer;
              machineValidationConfigFiles = machineValidationFiles.mkConfigFiles {
                machine-validation-runner = machineValidationRunnerArchive;
              };

              # Preserve the image contract used by the current Core Helm
              # charts while per-service repositories are rolled out. This is
              # still a base-image-free Nix root; it simply carries the exact
              # first-party binary set those charts address under /opt/carbide.
              compatibilityBinaries =
                builtins.removeAttrs nativeRustBinaries [
                  "carbide-scout"
                  "machine-a-tron"
                ]
                // nativeCompatibilityOnlyBinaries;
              compatibilityServiceNames = builtins.attrNames compatibilityBinaries;
              compatibilityRuntime = pkgs.lib.unique (
                pkgs.lib.concatMap (
                  serviceName:
                  let
                    spec = serviceSpecs.${serviceName};
                  in
                  if spec ? runtime then spec.runtime pkgs else [ ]
                ) compatibilityServiceNames
              );
              compatibilityContainer = mkContainer {
                name = "nvmetal-carbide";
                packages = builtins.attrValues compatibilityBinaries;
                runtime = compatibilityRuntime;
                firstPartyContents = [
                  compatibilityStaticFiles
                  pxeTemplateFiles
                  scoutFirmwareFiles
                ];
                arch = nativeOciArch;
                extraCommands =
                  let
                    multiarch = if nativeOciArch == "arm64" then "aarch64-linux-gnu" else "x86_64-linux-gnu";
                  in
                  ''
                    mkdir -p usr/lib/kea/hooks var/lib/kea var/run/kea
                    ln -sf /usr/lib/${multiarch}/kea/hooks/libdhcp.so usr/lib/kea/hooks/libdhcp.so
                    mkdir -p usr/bin var/support/forge-dhcp/bin
                    ln -sf /bin/ipmitool usr/bin/ipmitool
                    ln -sf /bin/ovs-vsctl usr/bin/ovs-vsctl
                    ln -sf /bin/forge-dpu-agent usr/bin/forge-dpu-agent
                    ln -sf /bin/forge-dhcp-server var/support/forge-dhcp/bin/forge-dhcp-server
                  '';
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
                env = [ "CASBIN_POLICY_FILE=/opt/carbide/casbin-policy.csv" ];
                meta = carbideMeta;
              };

              # Rust server binaries exist only for the architecture of the
              # current build host. Pure-Go services are cheap to cross-compile,
              # so both OCI architectures are always available on Linux.
              amd64Services =
                pkgs.lib.optionalAttrs isX86Linux nativeRustBinaries
                // restApiBinariesByArch.amd64
                // matK8sControllerBinariesByArch.amd64;
              amd64Containers = pkgs.lib.mapAttrs' (
                name: pkg:
                pkgs.lib.nameValuePair "${name}-container" (
                  mkServiceContainer amd64Services name pkg goTargetPkgs.amd64
                )
              ) amd64Services;
              amd64ContentContainers = pkgs.lib.optionalAttrs isX86Linux {
                machine-validation-runner-container = machineValidationRunnerContainer;
                machine-validation-config-container =
                  mkContentContainer "machine-validation-config" machineValidationConfigFiles
                    pkgs;
              };

              # arm64 — cross-compiled server binaries + cross runtime packages.
              # carbide-dpf is deliberately absent: it is a test harness binary,
              # not a service, and ships no image. forge-dpu-otel-agent is also
              # absent intentionally: bluefield/Makefile.toml packages it into
              # the forge-dpu .deb, whose systemd unit runs it on the DPU host.
              aarch64Services =
                aarch64ServerBinaries
                // {
                  inherit (aarch64Binaries) forge-dpu-agent carbide-fmds forge-dhcp-server;
                  otelcol-contrib = otelcolContribAarch64;
                  transceiver-exporter = transceiver-exporter-aarch64;
                }
                // restApiBinariesByArch.arm64
                // matK8sControllerBinariesByArch.arm64;
              arm64Containers = pkgs.lib.mapAttrs' (
                name: pkg:
                pkgs.lib.nameValuePair "${name}-container-arm64" (
                  mkServiceContainer aarch64Services name pkg aarch64CrossPkgs
                )
              ) aarch64Services;
              arm64ContentContainers = {
                machine-validation-config-container-arm64 =
                  mkContentContainer "machine-validation-config" machineValidationConfigFiles
                    aarch64CrossPkgs;
              };

              # Specs are looked up by service name, so the two sides have to
              # agree exactly. A spec whose name matches no service is never
              # consulted, and a service with no spec silently takes every
              # default — both produce an image that is wrong in a way nothing
              # reports until it fails at runtime.
              builtServiceNames = builtins.attrNames (amd64Services // aarch64Services) ++ [
                "machine-validation-runner"
                "machine-validation-config"
              ];
              declaredServiceNames = builtins.attrNames serviceSpecs;
              platformOmittedServiceNames = pkgs.lib.optionals (!isX86Linux) [ "machine-a-tron" ];

              # subtractLists takes `subtractLists e1 e2` and removes e1 from e2.
              undeclared = pkgs.lib.subtractLists declaredServiceNames builtServiceNames;
              unmatched = pkgs.lib.subtractLists (
                builtServiceNames ++ platformOmittedServiceNames
              ) declaredServiceNames;
            in
            assert pkgs.lib.assertMsg (undeclared == [ ]) ''
              These services build a container but have no entry in nix/services/default.nix:
                ${builtins.concatStringsSep ", " undeclared}
              Add one. Use `{ }` if the binary alone is the whole image.
            '';
            assert pkgs.lib.assertMsg (unmatched == [ ]) ''
              nix/services/default.nix declares services that no container builds:
                ${builtins.concatStringsSep ", " unmatched}
              Check for a typo, or remove the entry if the service is gone.
            '';
            {
              inherit machineValidationRunnerArchive;
              all =
                amd64Containers
                // arm64Containers
                // amd64ContentContainers
                // arm64ContentContainers
                // {
                  nvmetal-carbide-container = compatibilityContainer;
                };
              amd64Containers =
                amd64Containers
                // amd64ContentContainers
                // pkgs.lib.optionalAttrs isX86Linux { nvmetal-carbide-container = compatibilityContainer; };
              arm64Containers =
                arm64Containers
                // arm64ContentContainers
                // pkgs.lib.optionalAttrs isAarch64Linux { nvmetal-carbide-container = compatibilityContainer; };
              nativeContainers =
                (
                  if isX86Linux then
                    amd64Containers // amd64ContentContainers
                  else
                    arm64Containers // arm64ContentContainers
                )
                // {
                  nvmetal-carbide-container = compatibilityContainer;
                };
            };

          # Release checks intentionally live under packages rather than the
          # default `checks` output. Each one realizes a large part of the
          # amd64/arm64 artifact graph; making `nix flake check` build all of
          # them together exhausted developer workstations. Explicit targets
          # let callers select appropriate hardware and concurrency per gate.
          releaseChecks =
            pkgs.lib.optionalAttrs isX86Linux {
              container-layouts = import ./nix/checks/containers.nix {
                inherit pkgs;
                containers = containers.all;
              };
            }
            // pkgs.lib.optionalAttrs isAarch64Linux {
              native-container-elf = import ./nix/checks/native-container-elf.nix {
                inherit pkgs;
                container = containers.all.nvmetal-carbide-container;
              };
            }
            // pkgs.lib.optionalAttrs isLinux {
              machine-validation-payloads = import ./nix/checks/machine-validation.nix {
                inherit pkgs;
                configContainers =
                  pkgs.lib.optional isX86Linux containers.all.machine-validation-config-container
                  ++ [ containers.all.machine-validation-config-container-arm64 ];
              };
            }
            // pkgs.lib.optionalAttrs isLinux (
              import ./nix/checks/elf.nix {
                inherit pkgs;
                amd64Packages =
                  restApiBinariesByArch.amd64
                  // matK8sControllerBinariesByArch.amd64
                  // pkgs.lib.optionalAttrs isX86Linux (nativeRustBinaries // nativeCompatibilityOnlyBinaries);
                arm64Packages =
                  aarch64ServerBinaries
                  // aarch64Binaries
                  // {
                    mft = mftFor aarch64CrossPkgs;
                    otelcol-contrib = otelcolContribAarch64;
                    transceiver-exporter = transceiver-exporter-aarch64;
                  }
                  // restApiBinariesByArch.arm64
                  // matK8sControllerBinariesByArch.arm64
                  // pkgs.lib.optionalAttrs isAarch64Linux (nativeRustBinaries // nativeCompatibilityOnlyBinaries);
              }
            );
          releaseCheckPackages = pkgs.lib.mapAttrs' (
            name: check: pkgs.lib.nameValuePair "release-check-${name}" check
          ) releaseChecks;
        in
        {
          # ==================================================================
          # Packages — `nix build .#<name>`
          # ==================================================================
          #
          # Native x86 server binaries, the DPU binaries cross-compiled to
          # aarch64, a container per service for both architectures, the iPXE
          # bootloaders, and the vendor packages from nix/third-party/. The
          # boot-artifacts carrier image is not here: cargo-make packages it
          # from pxe/static/blobs/internal/. No name overlap — every attribute
          # is unique. From an x86 dev machine `nix build .#forge-dpu-agent`
          # cross-compiles with no aarch64 hardware or emulation involved.
          packages =
            if isLinux then
              nativeRustBinaries
              // aarch64Binaries
              // restApiBinariesAmd64
              // restApiBinariesArm64
              // matK8sControllerBinariesAmd64
              // matK8sControllerBinariesArm64
              // containers.all
              // releaseCheckPackages
              // {
                inherit
                  carbide-scout-aarch64
                  ipxe-efi-aarch64
                  dcgm
                  transceiver-exporter-aarch64
                  ;
                otelcol-contrib-aarch64 = otelcolContribAarch64;
                machine-validation-runner-docker-archive = containers.machineValidationRunnerArchive;

                # Expose the deps-only derivation for direct cache warming.
                # `nix build .#deps` builds just the dependency phase — useful
                # for warming a binary cache after Cargo.lock changes.
                deps = cargoArtifacts;
              }
              // pkgs.lib.optionalAttrs ipxe-efi-x86.meta.available {
                inherit ipxe-efi-x86;
              }
            else
              { };

          apps =
            if isLinux then
              (import ./nix/apps/copy-to-docker.nix {
                inherit pkgs;
                containers = containers.nativeContainers;
              })
              // (import ./nix/apps/sbom.nix {
                inherit pkgs;
                containers = containers.all;
              })
            else
              { };

          # Keep the default flake check lightweight and evaluation-focused.
          # Build `release-check-*` packages explicitly for artifact gates.
          checks = {
            version-contract = import ./nix/checks/version.nix {
              inherit pkgs versionAnchor;
            };
          };

          formatter = pkgs.nixfmt;

          devShells.default = craneLib.devShell (
            {
              packages =
                (with pkgs; [
                  # `cargo make check-licenses` / `check-bans` shell out to this.
                  cargo-deny
                  cargo-make
                  cargo-nextest
                  sccache
                  sqlx-cli
                  taplo
                  # Keep the Go major/minor line aligned with rest-api/go.mod;
                  # nixpkgs supplies the latest patch release in that line.
                  go_1_26
                  gopls
                  delve
                ])
                # Runtime tools (kea, ipmitool, tpm2-tools, etc.) are Linux-only.
                ++ pkgs.lib.optionals isLinux runtimeTools;

              # Dev shell needs the full library set so contributors can build
              # any crate via `cargo build`, not just one specific binary.
              # tpm2-tss and other Linux-only libs are excluded on Darwin via
              # allBuildInputs already being gated.
              # Unlike a per-binary derivation, the dev shell has to build every
              # crate. carbide-dhcp's build.rs compiles C++ against Kea's headers,
              # and those #include <boost/...>, so both are needed here. Binary
              # derivations pick them up from dhcpCrateExtraArgs instead.
              buildInputs =
                allBuildInputs
                ++ pkgs.lib.optionals isLinux [
                  pkgs.kea
                  pkgs.boost.dev
                ];
              inherit nativeBuildInputs;

              # Nix's stdenv injects -D_FORTIFY_SOURCE by default, but that
              # requires -O1 or better. cargo's dev profile compiles the Kea C++
              # shim (crates/dhcp/build.rs -> cc-rs) at -O0, so every debug build
              # prints a wall of "#warning _FORTIFY_SOURCE requires compiling
              # with optimization" from glibc's features.h. It is noise, not a
              # miscompile — fortification is simply inert at -O0.
              #
              # Scoped to the dev shell on purpose: package builds go through
              # crane in release mode, where -O is on, fortification is real, and
              # this warning never fires. Disabling it globally would weaken the
              # binaries we actually ship.
              hardeningDisable = [ "fortify" ];

              # Route cargo compilations through sccache. First run populates
              # the cache; subsequent builds of the same source (across
              # branches, checkouts, rebuilds) get cache hits at the individual
              # object file level.
              RUSTC_WRAPPER = "sccache";

              # sccache finds its background server by port and its cache by
              # SCCACHE_DIR. At the defaults the dev shell's sccache will try to
              # use whichever server is already running — including one started
              # by a different sccache installed on the host. The versions then
              # disagree on the wire protocol and every compile dies with
              # "error reading compile response from server", which reads like a
              # compiler error but is not. Give the Nix sccache its own port and
              # cache directory so the two can coexist. Both are overridable.
              shellHook = ''
                export SCCACHE_DIR="''${SCCACHE_DIR:-$HOME/.cache/sccache-nix}"
                export SCCACHE_SERVER_PORT="''${SCCACHE_SERVER_PORT:-4227}"
              '';

              SQLX_OFFLINE = "true";
              PROTOC = "${pkgs.protobuf}/bin/protoc";
              PROTOC_INCLUDE = "${pkgs.protobuf}/include";

              # Nightly tooling for the lint tasks, supplied by Nix rather than
              # rustup. `cargo fmt` honours RUSTFMT, so the format tasks need no
              # `+toolchain` shim; CARGO_NIGHTLY is used to build carbide-lints.
              # The cargo-make tasks fall back to `cargo +${RUST_NIGHTLY}` when
              # these are unset, so rustup-based workflows keep working.
              RUSTFMT = "${rustNightlyToolchain}/bin/rustfmt";
              CARGO_NIGHTLY = "${rustNightlyToolchain}/bin/cargo";
            }
            // pkgs.lib.optionalAttrs isLinux {
              KEA_INCLUDE_PATH = "${pkgs.kea}/include/kea";
              # Same shim the package builds use — see mkKeaLibShim.
              KEA_LIB_PATH = "${mkKeaLibShim pkgs}/lib";

              # Ensure dev-shell aarch64 cross-builds use the same 64KB-page-
              # compatible max-page-size as `nix build`. ARM64 server hardware
              # (NVIDIA Grace, certain Ampere SKUs) runs 64KB-page kernels;
              # binaries linked with the default 4KB segment alignment can
              # load incorrectly there. Target-suffixed env var → no effect
              # on native x86 builds.
              CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS = "-C link-arg=-Wl,-z,max-page-size=0x10000";
            }
          );
        }
      );
}
