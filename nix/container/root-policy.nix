{ pkgs }:

let
  inherit (pkgs) lib;
in
rec {
  # /tmp is here because services declare working directories under it
  # (machine-a-tron).
  pathsToLink = [
    "/aarch64"
    "/app"
    "/apt"
    "/bin"
    "/busybox"
    "/sbin"
    "/etc"
    "/lib"
    "/lib64"
    # openssh re-execs /libexec/sshd-session and resolves ssh-keysign,
    # ssh-pkcs11-helper, and ssh-sk-helper there. Dropping it leaves a
    # non-functional sshd in /bin rather than no sshd at all.
    "/libexec"
    "/machine-validation"
    "/opt"
    "/root"
    "/run"
    "/share"
    "/tmp"
    "/usr"
    "/var"
    "/x86_64"
  ];

  # Allowlist of top-level names that may be dropped. Unused entries are
  # allowed: not every image includes busybox.
  discardedRootNames = {
    nix-support = "nixpkgs build metadata; never part of a runtime image";
    "default.script" = "busybox udev helper; these images run no udev";
    linuxrc = "busybox initramfs entry point; these images are not an initramfs";
    include = "C headers from kea and pciutils; nothing compiles in these images";
    example = "systemd-minimal sample tmpfiles.d/sysctl.d units; these images run no systemd";
  };

  allowedRootNames = map (lib.removePrefix "/") pathsToLink;

  assertShallow = lib.assertMsg (lib.all (
    p: builtins.match "/[^/]+" p != null
  ) pathsToLink) "root-policy: every pathsToLink entry must be a single top-level segment";

  assertDisjoint = lib.assertMsg (
    lib.intersectLists allowedRootNames (builtins.attrNames discardedRootNames) == [ ]
  ) "root-policy: discardedRootNames overlaps pathsToLink";

  mkRootInventoryGuard =
    {
      name,
      classifiedPaths,
    }:
    let
      discardedNames = builtins.attrNames discardedRootNames;
      classes = [
        "packages"
        "runtime"
        "firstPartyContents"
        "generated"
      ];
      walkClass =
        class:
        lib.concatMapStrings (
          input:
          let
            inputPath = builtins.toString input;
          in
          ''
            for entry in ${lib.escapeShellArg inputPath}/* ${lib.escapeShellArg inputPath}/.[!.]*; do
              [ -e "$entry" ] || continue
              entry_name=$(basename -- "$entry")
              case " ${lib.concatStringsSep " " allowedRootNames} " in
                *" $entry_name "*) continue ;;
              esac
              case " ${lib.concatStringsSep " " discardedNames} " in
                *" $entry_name "*) continue ;;
              esac
              case " $offenders " in
                *" $entry_name "*) continue ;;
              esac
              offenders="$offenders $entry_name"
              echo "${name}: /$entry_name, provided by ${class} ${inputPath}, would be dropped by pathsToLink." >&2
            done
          ''
        ) (classifiedPaths.${class} or [ ]);
    in
    # Report every offending name before failing. Exiting on the first one
    # turns a policy review into one rebuild per name.
    ''
      offenders=""
      ${lib.concatMapStrings walkClass classes}
      if [ -n "$offenders" ]; then
        echo "${name}: add each name above to pathsToLink in nix/container/root-policy.nix to ship it, or to discardedRootNames with a reason if dropping it is intended." >&2
        exit 1
      fi
    '';
}
