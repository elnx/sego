#!/usr/bin/env bash
#
# gen_tools_expected.sh -- regenerate testdata/expected_tools/*.txt from
#                          testdata/tools.txt with the reference tools.
#
# Usage:
#   bash testdata/gen_tools_expected.sh            regenerate the goldens
#   bash testdata/gen_tools_expected.sh --check    regenerate into a temporary
#                                                  directory and compare with the
#                                                  committed goldens
#
# Reference oracles
#   ORACLE_PYTHON  Python interpreter of a setools 4.8 build
#                  (default: the throw-away build the corpus was recorded with)
#   ORACLE_DIR     directory holding the setools package and the tool scripts
#   SETOOLS_ENV    environment prefix for the oracle runs (the libselinux and
#                  libsepol the setools build links against)
#
# The sechecker report contains the run's start and end times, so the
# "Start time:"/"End time:" lines are removed from the recorded output; the
# integration test removes them from the actual output before comparing.
#
# Every case must produce the expected exit status. The expected files are
# committed so that the Go tests need nothing but the checkout.

set -uo pipefail

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$here/.." && pwd)
expected_dir=$here/expected_tools
matrix=$here/tools.txt

ORACLE_PYTHON=${ORACLE_PYTHON:-/tmp/setools48/venv312/bin/python}
ORACLE_DIR=${ORACLE_DIR:-/tmp/setools48}
SETOOLS_ENV=${SETOOLS_ENV:-LD_LIBRARY_PATH=/home/qwe/src/selinux/libselinux/src:/home/qwe/src/selinux/libsepol/src}

mode=${1:-}
case $mode in
    ""|--check) ;;
    *) echo "usage: gen_tools_expected.sh [--check]" >&2; exit 2 ;;
esac

if [[ ! -d $ORACLE_DIR/setools ]]; then
    echo "gen_tools_expected.sh: no setools build at $ORACLE_DIR" >&2
    echo "gen_tools_expected.sh: set ORACLE_DIR and ORACLE_PYTHON to a setools 4.8 build" >&2
    exit 1
fi

run_dir=$(mktemp -d)
trap 'rm -rf "$run_dir"' EXIT
if [[ $mode == --check ]]; then
    out_dir=$run_dir
else
    out_dir=$expected_dir
    mkdir -p "$out_dir"
fi

failures=0
fail() { echo "gen_tools_expected.sh: $*" >&2; failures=$((failures + 1)); }

cases=0
while IFS=$'\t' read -r tool name args exit_expected extra; do
    [[ -z ${name//[[:space:]]/} ]] && continue
    [[ $name == \#* ]] && continue
    if [[ -n ${extra:-} ]]; then
        fail "$name: more than four tab separated fields"
        continue
    fi
    if [[ -z $tool || -z $name || -z $args ]]; then
        fail "$name: missing field (tool/name/args)"
        continue
    fi
    exit_expected=${exit_expected:-0}
    if [[ ! -f $ORACLE_DIR/$tool ]]; then
        fail "$name: no reference tool $ORACLE_DIR/$tool"
        continue
    fi

    read -r -a argv <<< "$args"
    # shellcheck disable=SC2086
    (cd "$repo_root" && env $SETOOLS_ENV "$ORACLE_PYTHON" "$ORACLE_DIR/$tool" "${argv[@]}") \
        > "$run_dir/out" 2> "$run_dir/err"
    rc=$?

    cases=$((cases + 1))
    if [[ $rc != "$exit_expected" ]]; then
        fail "$name: exit $rc, expected $exit_expected: $(tr '\n' ' ' < "$run_dir/err")"
    fi

    if [[ $tool == sechecker ]]; then
        grep -v -E '^(Start|End) time: ' "$run_dir/out" > "$run_dir/filtered" || true
        mv "$run_dir/filtered" "$run_dir/out"
    fi

    if [[ $mode == --check ]]; then
        committed=$expected_dir/$name.txt
        if [[ ! -f $committed ]]; then
            fail "$name: $committed is missing"
        elif ! cmp -s "$run_dir/out" "$committed"; then
            fail "$name: $committed differs from the regenerated output"
        fi
    else
        cp "$run_dir/out" "$out_dir/$name.txt"
    fi
    echo "$name: exit=$rc bytes=$(stat -c%s "$run_dir/out")"
done < "$matrix"

if [[ $mode == --check ]]; then
    echo "gen_tools_expected.sh: $cases cases, $failures problem(s)"
else
    echo "gen_tools_expected.sh: wrote $cases golden files to $out_dir ($failures problem(s))"
fi
exit $((failures > 0))
