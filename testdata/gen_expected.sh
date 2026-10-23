#!/usr/bin/env bash
#
# gen_expected.sh -- regenerate testdata/expected/*.txt from testdata/queries.txt
#                    with the reference sesearch, and sanity check every case.
#
# Usage:
#   bash testdata/gen_expected.sh              regenerate the golden outputs
#   bash testdata/gen_expected.sh --check      regenerate into a temporary
#                                              directory and compare with the
#                                              committed goldens (reproducibility
#                                              check, nothing is written)
#   bash testdata/gen_expected.sh --compare    run both oracles on every case
#                                              both can handle and report any
#                                              difference (nothing is written)
#
# Reference oracles
#   SESEARCH       setools 4.2.2 sesearch (default /usr/bin/sesearch).  This is
#                  the oracle almost all goldens are recorded from.  It reads
#                  policy versions up to 32 only and cannot decode nlmsg
#                  extended permissions at all (libsepol 3.0).
#   SESEARCH_ENV   environment prefix for SESEARCH
#                  (default: "env -u PYTHONPATH -u PYTHONHOME", so that a
#                  PYTHONPATH pointing at some other setools build cannot leak
#                  into the 4.2.2 oracle and break it).
#   SESEARCH48     command line of a setools 4.8 build, used for the cases the
#                  4.2.2 CLI cannot express or cannot read (-Sp, -v33/-v35
#                  fixtures, sego_nlmsg fixtures, extra_cond_xperm fixtures).
#                  Default: the throw-away build used when this corpus was
#                  created (see expected/README.md, "Building the 4.8 oracle").
#   SESEARCH48_ENV environment prefix for SESEARCH48 (LD_LIBRARY_PATH and
#                  PYTHONPATH for that build).
#
# Which oracle a case uses is derived from the case itself:
#   * arguments contain --neverallow/--neverallowxperm -> 4.2.2 (4.8 dropped them)
#   * arguments contain -Sp                            -> 4.8
#   * the fixture is not sego_test-v30.pol/sego_test-v32.pol -> 4.8
#   * case name is in the complete-ioctl-driver list   -> 4.8 (the two oracles
#     print/compare those differently, see expected/README.md)
#   * otherwise                                        -> 4.2.2
# For the 4.2.2 runs the option names that 4.8 renamed are translated back
# (--role_transition -> --role_trans, --range_transition -> --range_trans,
# --type_transition -> -T); nothing else about the argument list is changed.
#
# Sanity checks (all failures are fatal):
#   * every case must have 3 or 4 tab separated fields and an existing fixture
#   * the exit status must equal the expected exit status (field 4, default 0)
#   * a case that exits 0 must produce output unless it is one of the documented
#     no-match cases (the list is in expected/README.md)
#   * a case that exits non-zero must be one of the documented error cases

set -uo pipefail

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$here/.." && pwd)
expected_dir=$here/expected
queries=$here/queries.txt

SESEARCH=${SESEARCH:-/usr/bin/sesearch}
SESEARCH_ENV=${SESEARCH_ENV:-env -u PYTHONPATH -u PYTHONHOME}
SESEARCH48=${SESEARCH48:-/home/qwe/.local/share/uv/python/cpython-3.12.12-linux-x86_64-gnu/bin/python3.12 /tmp/setools48/sesearch}
SESEARCH48_ENV=${SESEARCH48_ENV:-LD_LIBRARY_PATH=/home/qwe/src/selinux/libselinux/src:/home/qwe/src/selinux/libsepol/src PYTHONPATH=/tmp/setools48}

# Cases that legitimately match nothing: their expected file is empty (0 bytes).
# Keep in sync with expected/README.md.
no_match_cases="
allow_bool_nomatch
allow_nomatch_src
allow_src_expanded_attr
dontaudit_class_nomatch
neverallow_absent_te
neverallow_absent_xperm
nlmsg_xperm_nomatch
range_transition_src_attr_direct
type_trans_nomatch_tgt
type_trans_src_attr_direct
xperm_ioctl_two_runs_exact
xperm_nomatch
"

# Cases whose argv the reference rejects: non-zero exit, empty stdout.  The two
# legacy_neverallow* cases deliberately assert the 4.8 usage error (the flag no
# longer exists there), no_ruletype asserts the missing-rule-type error.
error_cases=" legacy_neverallow_te legacy_neverallowxperm_te no_ruletype "

# Cases whose golden comes from the 4.8 oracle although 4.2.2 can also run them:
# the two oracles disagree for complete ioctl driver ranges (0x0000-0x00ff), and
# the recorded corpus is kept consistent with the 4.8 CLI (see
# expected/README.md, "Divergences").
force_48_cases="
allow_and_allowxperm
allowxperm_all
te_mixed_ruletypes
te_xperm_ruletypes
xperm_ioctl_driver_range
xperm_ioctl_driver_range_exact
xperm_ioctl_driver_range_v30
"

contains_word() { # <word list> <word>
    local list=${1//$'\n'/ }
    case " $list " in
        *" $2 "*) return 0 ;;
        *) return 1 ;;
    esac
}

mode=${1:-}
case $mode in
    ""|--check|--compare) ;;
    *) echo "usage: gen_expected.sh [--check|--compare]" >&2; exit 2 ;;
esac

run_dir=$(mktemp -d)
trap 'rm -rf "$run_dir"' EXIT

abs_policy() {
    case $1 in
        /*) printf '%s\n' "$1" ;;
        *) printf '%s\n' "$repo_root/$1" ;;
    esac
}

translate_422() {
    local arg out=()
    for arg in "$@"; do
        case $arg in
            --role_transition) out+=(--role_trans) ;;
            --range_transition) out+=(--range_trans) ;;
            --type_transition) out+=(-T) ;;
            *) out+=("$arg") ;;
        esac
    done
    printf '%s\n' "${out[*]}"
}

oracle_for() { # <case name> <policy> <args>
    local name=$1 policy=$2 args=$3
    if contains_word "$force_48_cases" "$name"; then echo 48; return; fi
    case $policy in
        *sego_test-v30.pol|*sego_test-v32.pol) ;;
        *) echo 48; return ;;
    esac
    case " $args " in
        # --neverallow/--neverallowxperm were removed in 4.8: argv using them is
        # run against the 4.8 CLI so the recorded golden is the removal
        # (argparse usage error: exit 2, empty stdout).
        *" --neverallow "*|*" --neverallowxperm "*) echo 48; return ;;
        *" -Sp "*) echo 48; return ;;
    esac
    echo 422
}

run_case() { # <oracle> <policy-abs> <args> <outfile> <errfile>
    local oracle=$1 policy=$2 args=$3 out=$4 err=$5
    if [[ $oracle == 48 ]]; then
        # shellcheck disable=SC2086
        eval "$SESEARCH48_ENV $SESEARCH48 $args '$policy'" >"$out" 2>"$err"
    else
        local translated
        translated=$(translate_422 $args)
        # shellcheck disable=SC2086
        $SESEARCH_ENV $SESEARCH $translated "$policy" >"$out" 2>"$err"
    fi
}

failures=0
fail() { echo "gen_expected.sh: $*" >&2; failures=$((failures + 1)); }

if [[ $mode == --compare ]]; then
    printf '%-32s %-9s %s\n' case oracle verdict
fi

cases=0
while IFS=$'\t' read -r name policy args exit_expected extra; do
    [[ -z ${name//[[:space:]]/} ]] && continue
    [[ $name == \#* ]] && continue
    if [[ -n ${extra:-} ]]; then
        fail "$name: more than four tab separated fields"
        continue
    fi
    if [[ -z $name || -z $policy || -z $args ]]; then
        fail "$name: missing field (name/policy/args)"
        continue
    fi
    exit_expected=${exit_expected:-0}
    abs=$(abs_policy "$policy")
    if [[ ! -f $abs ]]; then
        fail "$name: missing policy $policy"
        continue
    fi
    oracle=$(oracle_for "$name" "$policy" "$args")

    if [[ $mode == --compare ]]; then
        other=48
        [[ $oracle == 48 ]] && other=422
        if [[ $policy == *sego_nlmsg* || $policy == *extra_cond_xperm* ]] ||
           [[ $args == *-Sp* ]] || [[ $args == *--neverallow* ]]; then
            printf '%-32s %-9s %s\n' "$name" "$oracle" \
                   "skipped (single-oracle case: only $oracle can express/read it, or the difference is the point)"
            continue
        fi
        run_case "$oracle" "$abs" "$args" "$run_dir/a.out" "$run_dir/a.err"; a_rc=$?
        run_case "$other" "$abs" "$args" "$run_dir/b.out" "$run_dir/b.err"; b_rc=$?
        verdict=identical
        if [[ $a_rc != "$b_rc" ]]; then
            verdict="DIFFERENT exit ($a_rc vs $b_rc)"
        elif ! cmp -s "$run_dir/a.out" "$run_dir/b.out"; then
            verdict="DIFFERENT stdout"
        fi
        printf '%-32s %-9s %s\n' "$name" "$oracle/$other" "$verdict"
        continue
    fi

    cases=$((cases + 1))
    run_case "$oracle" "$abs" "$args" "$run_dir/out" "$run_dir/err"
    rc=$?
    if [[ $rc != "$exit_expected" ]]; then
        fail "$name: exit $rc, expected $exit_expected"
    fi
    if [[ $rc == 0 ]] && [[ ! -s $run_dir/out ]] && ! contains_word "$no_match_cases" "$name"; then
        fail "$name: empty output but the case is not in the documented no-match list"
    fi
    if [[ $rc != 0 ]] && ! contains_word "$error_cases" "$name"; then
        fail "$name: non-zero exit for a case that expects results: $(tr '\n' ' ' <"$run_dir/err")"
    fi
    if [[ $rc == 0 ]] && [[ -s $run_dir/out ]] && contains_word "$no_match_cases" "$name"; then
        fail "$name: expected no matches but the oracle produced output"
    fi

    if [[ $mode == --check ]]; then
        committed=$expected_dir/$name.txt
        if [[ ! -f $committed ]]; then
            fail "$name: $committed is missing"
        elif ! cmp -s "$run_dir/out" "$committed"; then
            fail "$name: $committed differs from the regenerated output"
        fi
    else
        mkdir -p "$expected_dir"
        cp "$run_dir/out" "$expected_dir/$name.txt"
    fi
    printf '%-32s oracle=%-4s exit=%d bytes=%-6s %s\n' \
           "$name" "$oracle" "$rc" "$(stat -c%s "$run_dir/out")" \
           "$([[ -s $run_dir/err ]] && tr '\n' ' ' <"$run_dir/err" || true)"
done <"$queries"

if [[ $mode != --compare ]]; then
    nonempty=0
    empty=0
    for case in $(awk -F'\t' '!/^#/ && NF >= 3 {print $1}' "$queries"); do
        if [[ -s $expected_dir/$case.txt ]]; then
            nonempty=$((nonempty + 1))
        else
            empty=$((empty + 1))
        fi
    done
    if [[ $mode == --check ]]; then
        echo "gen_expected.sh: $cases cases, $nonempty with output, $empty empty: all reproduce byte for byte ($failures problem(s))"
    else
        echo "gen_expected.sh: wrote $cases golden files to $expected_dir ($nonempty with output, $empty empty, $failures problem(s))"
    fi
fi
exit $((failures > 0))
