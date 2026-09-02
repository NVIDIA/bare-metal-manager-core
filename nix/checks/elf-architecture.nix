{ pkgs }:

# Keep the release validator inside the standalone Nix implementation. The
# generated program is used only by Nix derivations and does not add another
# repository script or alter the existing Make/cargo-make validation path.
pkgs.writeShellApplication {
  name = "check-elf-architecture";
  runtimeInputs = with pkgs; [
    binutils
    coreutils
    findutils
    gawk
  ];
  text = ''
    usage() {
      cat <<'EOF'
    Usage: check-elf-architecture <amd64|arm64> ROOT

    Scans regular ELF executables and shared objects below ROOT and verifies
    that each one targets the requested architecture. Non-ELF files and
    relocatable ELF objects are ignored.
    EOF
    }

    if (($# == 1)) && [[ "$1" == "-h" || "$1" == "--help" ]]; then
      usage
      exit 0
    fi

    if (($# != 2)); then
      usage >&2
      exit 2
    fi

    expected_arch=$1
    root=$2

    case "$expected_arch" in
      amd64)
        expected_machine="Advanced Micro Devices X86-64"
        ;;
      arm64)
        expected_machine="AArch64"
        ;;
      *)
        printf 'error: unsupported architecture: %s\n' "$expected_arch" >&2
        usage >&2
        exit 2
        ;;
    esac

    if [[ ! -e "$root" ]]; then
      printf 'error: path does not exist: %s\n' "$root" >&2
      exit 2
    fi

    export LC_ALL=C
    checked=0
    failed=0

    while IFS= read -r -d "" candidate; do
      # Corrupt ELF data must fail rather than being mistaken for an ordinary
      # non-ELF file and silently escaping the architecture gate.
      if elf_header=$(readelf --file-header --wide -- "$candidate" 2>/dev/null); then
        :
      else
        magic=""
        IFS= read -r -N 4 magic < "$candidate" || true
        if [[ "$magic" == $'\x7fELF' ]]; then
          printf 'FAIL unreadable ELF header file=%q\n' "$candidate"
          failed=1
        fi
        continue
      fi

      elf_type=$(awk -F: '
        /^[[:space:]]*Type[[:space:]]*:/ {
          value = $2
          sub(/^[[:space:]]+/, "", value)
          split(value, parts, /[[:space:]]+/)
          print parts[1]
          exit
        }
      ' <<<"$elf_header")

      if [[ "$elf_type" != "EXEC" && "$elf_type" != "DYN" ]]; then
        continue
      fi

      machine=$(awk -F: '
        /^[[:space:]]*Machine[[:space:]]*:/ {
          value = $2
          sub(/^[[:space:]]+/, "", value)
          sub(/[[:space:]]+$/, "", value)
          print value
          exit
        }
      ' <<<"$elf_header")

      case "$machine" in
        "Advanced Micro Devices X86-64" | "AMD x86-64" | "x86-64")
          actual_arch="amd64"
          ;;
        "AArch64")
          actual_arch="arm64"
          ;;
        *)
          actual_arch="unknown"
          ;;
      esac

      checked=$((checked + 1))
      if [[ "$actual_arch" == "$expected_arch" ]]; then
        printf 'OK   expected=%s actual=%s machine=%q file=%q\n' \
          "$expected_arch" "$actual_arch" "$machine" "$candidate"
      else
        printf 'FAIL expected=%s actual=%s machine=%q file=%q\n' \
          "$expected_arch" "$actual_arch" "$machine" "$candidate"
        failed=1
      fi
    done < <(find -- "$root" -type f -print0)

    printf 'Checked %d ELF executable/shared object(s) for %s (%s)\n' \
      "$checked" "$expected_arch" "$expected_machine"

    if ((checked == 0)); then
      printf 'FAIL no ELF executable/shared object(s) found under %s\n' "$root" >&2
      failed=1
    fi

    exit "$failed"
  '';
}
