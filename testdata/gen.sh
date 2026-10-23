#!/usr/bin/env bash
#
# gen.sh -- regenerate the compiled policy fixtures in testdata/policies/ from
#           the hand written policy.conf sources in testdata/src/.
#
# Usage:
#   bash testdata/gen.sh           regenerate the fixtures in place
#   bash testdata/gen.sh --check   compile into a temporary directory and compare
#                                  with the committed fixtures; exit non-zero if
#                                  anything differs (proves reproducibility)
#
# Environment:
#   CHECKPOLICY      checkpolicy binary
#                    (default: /home/qwe/src/selinux/checkpolicy/checkpolicy)
#   LIBSEPOL_DIR     directory containing libsepol.so.<n> for that checkpolicy
#                    build (default: /home/qwe/src/selinux/libsepol/src).
#                    Prepended to LD_LIBRARY_PATH when it exists, so that a
#                    locally built checkpolicy finds its libsepol without any
#                    manual setup.  Set LIBSEPOL_DIR= to skip.
#   CHECKPOLICY_FLAGS  extra checkpolicy flags (default: empty)
#
# checkpolicy is always invoked as:
#
#   $CHECKPOLICY -c <version> -M -U reject -o <fixture> <source>
#
# -M (MLS) because the sources declare sensitivities/categories/ranges,
# -U reject because every permission used in the sources is declared.
#
# The output is deterministic: re-running this script must reproduce the
# committed fixtures byte for byte.

set -euo pipefail

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
src_dir=$here/src
policy_dir=$here/policies

CHECKPOLICY=${CHECKPOLICY:-/home/qwe/src/selinux/checkpolicy/checkpolicy}
LIBSEPOL_DIR=${LIBSEPOL_DIR-/home/qwe/src/selinux/libsepol/src}
CHECKPOLICY_FLAGS=${CHECKPOLICY_FLAGS:-}

if [[ -n $LIBSEPOL_DIR && -d $LIBSEPOL_DIR ]]; then
    LD_LIBRARY_PATH="$LIBSEPOL_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    export LD_LIBRARY_PATH
fi

if [[ ! -x $CHECKPOLICY ]]; then
    echo "gen.sh: checkpolicy not found or not executable: $CHECKPOLICY" >&2
    echo "gen.sh: set CHECKPOLICY=<path to checkpolicy> and re-run" >&2
    exit 1
fi

# <source stem>:<policy versions to compile it for>
# extra_cond_xperm.conf uses extended permissions inside a conditional, which
# checkpolicy can only represent from policy version 34 on, hence version 35 only.
fixtures=(
    "sego_test:30,32,33,35"
    "sego_nlmsg:30,32,33,35"
    "extra_cond_xperm:35"
)

check=false
case ${1:-} in
    "") ;;
    --check) check=true ;;
    *)
        echo "usage: gen.sh [--check]" >&2
        exit 2
        ;;
esac

tmpdir=
if $check; then
    tmpdir=$(mktemp -d)
    trap 'rm -rf "$tmpdir"' EXIT
    outdir=$tmpdir
    status=0
else
    outdir=$policy_dir
    mkdir -p "$policy_dir"
fi

printf '%-18s %-4s %-9s %s\n' source version size sha256
for fixture in "${fixtures[@]}"; do
    stem=${fixture%%:*}
    versions=${fixture#*:}
    src=$src_dir/$stem.conf
    if [[ ! -f $src ]]; then
        echo "gen.sh: missing source $src" >&2
        exit 1
    fi
    IFS=, read -r -a vers <<< "$versions"
    for ver in "${vers[@]}"; do
        out=$outdir/$stem-v$ver.pol
        # shellcheck disable=SC2086
        "$CHECKPOLICY" $CHECKPOLICY_FLAGS -c "$ver" -M -U reject -o "$out" "$src"
        printf '%-18s %-4s %-9s %s\n' "$stem" "v$ver" "$(stat -c%s "$out")" \
               "$(sha256sum "$out" | cut -d' ' -f1)"
        if $check; then
            committed=$policy_dir/$stem-v$ver.pol
            if [[ ! -f $committed ]]; then
                echo "gen.sh: $committed is missing" >&2
                status=1
            elif ! cmp -s "$out" "$committed"; then
                echo "gen.sh: $committed differs from the regenerated policy" >&2
                status=1
            fi
        fi
    done
done

if $check; then
    if ((status == 0)); then
        echo "gen.sh: all $(find "$policy_dir" -name '*.pol' | wc -l) fixtures reproduce byte for byte"
    else
        echo "gen.sh: fixtures are NOT reproducible" >&2
    fi
    exit "$status"
fi
