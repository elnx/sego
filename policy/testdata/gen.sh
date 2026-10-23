#!/usr/bin/env bash
#
# gen.sh -- regenerate the compiled policy fixtures in policy/testdata/ from
#           the hand written policy.conf sources in policy/testdata/src/.
#
# Usage:
#   bash policy/testdata/gen.sh           regenerate the fixtures in place
#   bash policy/testdata/gen.sh --check   compile into a temporary directory and
#                                         compare with the committed fixtures;
#                                         exit non-zero if anything differs
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
# checkpolicy is invoked as:
#
#   $CHECKPOLICY -c <version> -M -U reject -o <fixture> <source>   (MLS sources)
#   $CHECKPOLICY -c <version> -U reject -o <fixture> <source>      (non_mls.conf)
#
# -M (MLS) because the sources declare sensitivities/categories/ranges,
# -U reject because every permission used in the sources is declared.
#
# The output is deterministic: re-running this script must reproduce the
# committed fixtures byte for byte.

set -euo pipefail

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
src_dir=$here/src
policy_dir=$here

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

# <source stem>:<mls flag>:<policy versions to compile it for>
# non_mls.conf is compiled without -M, so it carries mls=0.
fixtures=(
    "te_semantics:1:30,32,33,35"
    "xperm:1:30,32,33,35"
    "rbac:1:30,32,33,35"
    "mls_ranges:1:30,32,33,35"
    "non_mls:0:32"
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
status=0
if $check; then
    tmpdir=$(mktemp -d)
    trap 'rm -rf "$tmpdir"' EXIT
    outdir=$tmpdir
else
    outdir=$policy_dir
fi

printf '%-14s %-4s %-9s %s\n' source version size sha256
for fixture in "${fixtures[@]}"; do
    stem=${fixture%%:*}
    rest=${fixture#*:}
    mls=${rest%%:*}
    versions=${rest#*:}
    src=$src_dir/$stem.conf
    if [[ ! -f $src ]]; then
        echo "gen.sh: missing source $src" >&2
        exit 1
    fi
    mlsflag=
    if [[ $mls == 1 ]]; then
        mlsflag=-M
    fi
    IFS=, read -r -a vers <<< "$versions"
    for ver in "${vers[@]}"; do
        out=$outdir/$stem-v$ver.pol
        # shellcheck disable=SC2086
        "$CHECKPOLICY" $CHECKPOLICY_FLAGS $mlsflag -c "$ver" -U reject -o "$out" "$src"
        printf '%-14s %-4s %-9s %s\n' "$stem" "v$ver" "$(stat -c%s "$out")" \
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
    total=$(find "$policy_dir" -maxdepth 1 -name '*.pol' | wc -l)
    if ((status == 0)); then
        echo "gen.sh: all $total fixtures reproduce byte for byte"
    else
        echo "gen.sh: fixtures are NOT reproducible" >&2
    fi
    exit "$status"
fi
