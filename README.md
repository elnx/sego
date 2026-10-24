# sego

`sego` is a pure-Go reimplementation of the [setools](https://github.com/SELinuxProject/setools)
SELinux policy analysis tools. It reads *binary kernel policies* directly - no
libsepol, no cgo, no Python - and provides the policy object model, the rule
queries and the rule rendering the tools need.

The commands are the setools tools:

| command | what it does |
|---|---|
| `sesearch` | search the rules of a policy |
| `seinfo` | report the components and statistics of a policy |
| `sediff` | report the semantic differences of two policies |
| `sedta` | analyze domain transitions (transitions in, out of, and between domains) |
| `seinfoflow` | analyze information flows, weighted by a permission map |
| `sechecker` | run the checks of an INI configuration file against a policy |

Each reproduces setools 4.8's command line, output order, exit statuses and
diagnostics.

```
$ make build
$ ./bin/sesearch --allow -s app_t -t data_t testdata/policies/sego_test-v32.pol
allow app_t data_t:file { read write };
allow app_t data_t:process sigchld; [ ! c_beta && c_alpha ]:True
allow domain data_attr:file read;
```

## Supported policies

* **Binary kernel policies only** (the compiled `policy.<version>` files, what
  `/sys/fs/selinux/policy` and `/etc/selinux/<type>/policy/` hold). Source
  policies and loadable policy modules are rejected.
* **Policy versions 30 to 35** (`policy.VersionMin` .. `policy.VersionMax`):
  30 is the oldest version this module reads, 31 adds infiniband contexts,
  32 global permissive/glublub, 33 compressed filename transitions, 34 extended
  permissions in conditionals, 35 `neveraudit` types.
* **Targets**: SELinux (`SE Linux`) and Xen (`Xen`), as stored in the policy
  header.

Because the rules of a kernel policy are fully expanded and the assertion rules
are not part of it, type aliases, `neverallow`/`neverallowxperm` rules and
unexpanded type attributes do not exist here; see the divergences below.

## Building and testing

| target | what it does |
|---|---|
| `make` / `make build` | build every command into `bin/`, with the version compiled in |
| `GOOS=windows make` | cross build; the outputs are `bin/<tool>.exe` |
| `make dist` | build every platform in `DIST_PLATFORMS` into `bin/<os>_<arch>/` |
| `make test` | `go test ./...` - unit tests plus the query matrix when it is present |
| `make lint` | `gofmt -l .`, `go vet ./...` and `gopls check` when gopls is on `PATH` |
| `make fixtures` | regenerate `testdata/policies/*.pol` with `testdata/gen.sh` |
| `make clean` | remove `bin/` |
| `make help` | list the targets |

`GOOS` and `GOARCH` default to the host and can be given either way round, so
`GOOS=windows make` and `make GOOS=windows` are the same build; the Windows
suffix is added automatically:

```
$ GOOS=windows make            # -> bin/<tool>.exe
$ make GOOS=darwin GOARCH=arm64  # -> bin/<tool> (Mach-O arm64)
```

`make dist` cross compiles the release set (`linux/amd64`, `windows/amd64`,
`darwin/amd64`, `darwin/arm64` by default - override with
`DIST_PLATFORMS="linux/arm64 ..."`) into one directory per platform,
`bin/<os>_<arch>/`, holding every command as `<tool>[.exe]` plus a
`SHA256SUMS` for that directory. `DIST_ROOT` overrides the `bin` root, and the
host platform's own artifacts are run once to smoke test them. Because the
module is pure Go with no cgo, no cross toolchain is needed:

```
$ make dist
  building bin/linux_amd64/sesearch (GOOS=linux GOARCH=amd64)
  building bin/linux_amd64/seinfo (GOOS=linux GOARCH=amd64)
  ...
  building bin/windows_amd64/sesearch.exe (GOOS=windows GOARCH=amd64)
  ...
version 1.2.3, 4 platforms in bin/<os>_<arch>/:
  bin/linux_amd64/
     3623983  sesearch
     3807772  seinfo
    ...
  bin/windows_amd64/
     3727872  sesearch.exe
    ...
```

`--version` reports `dev` for a plain `go build`; release builds inject the
version, and `make build` does it from `VERSION` (default: `git describe
--tags --always --dirty`, or `dev` outside a git checkout):

```
go build -ldflags "-X main.version=1.2.3" -o bin/sesearch ./cmd/sesearch
```

`make test` needs no network access, no SELinux policy and no root: the module
has no dependencies outside the standard library, and the integration tests
skip themselves when their matrices are missing. It does need the `go`
toolchain on `PATH`, because it builds the commands once into a temporary
directory. The graphical output options (`-o` of `sedta` and `seinfoflow`) need
graphviz' `dot` at run time; the tests do not exercise them.

## Usage

```
sesearch [rule type ...] [expressions] [search options] [policy]
```

The rule type flags decide which family is searched, and the policy is located
with `sego.FindPolicyPath` (the running policy, then the installed
`policy.<version>` files) when it is not given.

TE rules - `--allow`, `--allowxperm`, `--auditallow`, `--auditallowxperm`,
`--dontaudit`, `--dontauditxperm`, `-T/--type_transition`, `--type_change`,
`--type_member`, and `-A` for allow plus allowxperm (the examples use the test
fixture `testdata/policies/sego_test-v32.pol`):

```
$ ./bin/sesearch --allow -s app_t -t data_t testdata/policies/sego_test-v32.pol
allow app_t data_t:file { read write };
allow app_t data_t:process sigchld; [ ! c_beta && c_alpha ]:True
allow domain data_attr:file read;

$ ./bin/sesearch -T -D default_t testdata/policies/sego_test-v32.pol
type_transition app_t data_t:file default_t sego_app_only;
...

$ ./bin/sesearch --allowxperm -x 0x5401,0x5404-0x5405 -c chr_file testdata/policies/sego_test-v32.pol
allowxperm app_t data_t:chr_file ioctl 0x5401;
allowxperm domain plain_t:chr_file ioctl 0x5404;

$ ./bin/sesearch --allow -c file,dir -p read,write -ep testdata/policies/sego_test-v32.pol
$ ./bin/sesearch --allow -p read -Sp -s domain -ds testdata/policies/sego_test-v32.pol
$ ./bin/sesearch --allow -b c_alpha,c_beta -eb testdata/policies/sego_test-v32.pol
$ ./bin/sesearch --allow -c '.*_file' -rc testdata/policies/sego_test-v32.pol
```

RBAC rules:

```
$ ./bin/sesearch --role_allow -s r_admin testdata/policies/sego_test-v32.pol
allow r_admin r_ops;
allow r_admin r_user;

$ ./bin/sesearch --role_transition -D r_ops -c process testdata/policies/sego_test-v32.pol
role_transition r_admin app_t:process r_ops;
role_transition r_user app_t:process r_ops;
```

MLS rules:

```
$ ./bin/sesearch --range_transition -D s1-s3 testdata/policies/sego_test-v32.pol
range_transition app_t data_t:dir s1 - s3;
```

Several families may be searched at once; the results are printed per family,
TE first, then RBAC, then MLS, each sorted by the rule's rendered statement:

```
$ ./bin/sesearch --allow --role_allow --range_transition testdata/policies/sego_test-v32.pol
allow app_t app_t:process sigchld;
...
range_transition server_t data_t:socket s1:c1.c2;
```

`-s`/`-t` match through type attributes unless `-ds`/`-dt` are given, `-rs`,
`-rt`, `-rc`, `-rd` and `-rb` switch the corresponding criterion to regular
expression matching, and `-eb`, `-ep`, `-ex` require exact matches instead of
overlap. `--help` lists the same options, metavariables and argument groups as
the reference tool, in the same order and layout; the descriptions are this
project's own (see [NOTICE.md](NOTICE.md)).

Errors follow the reference tool exactly:

* a usage error (no rule type, an unknown option, `-p`/`-x`/`-b` with an RBAC
  or MLS rule search) prints the usage line and the message on **stderr** and
  exits **2**;
* a runtime error (a policy that cannot be opened, an unknown type, class or
  Boolean, a malformed `-x` value or a bad expression) prints only the message
  on **stdout** and exits **1**.

```
$ ./bin/sesearch --allow -s nosuch testdata/policies/sego_test-v32.pol
nosuch is not a valid type attribute
$ echo $?
1
```

`-v/--verbose` logs what is being opened and searched to stderr; `--debug`
prints a stack trace instead of the plain message when something fails.

### Old Boolean names

When the policy is *located* rather than named on the command line, the names
given with `-b` are translated through the policy's `booleans.subs_dist`
(libselinux renames Booleans between policy versions). The file is
`/etc/selinux/<SELINUXTYPE>/booleans.subs_dist`, or
`/etc/selinux/targeted/booleans.subs_dist` when `SELINUXTYPE` is unset; old names
whose entry is missing, and a missing file, leave the name untouched. The path
can be overridden with `SEGO_BOOLEANS_SUBS_DIST`, which is what the unit tests
use to avoid depending on an installed policy.

## The other tools

`seinfo` reports the statistics and components of a policy. Without a component
selection it prints only the statistics block; the component queries are
`nargs='?'` options (bare: every component, with a value: a name filter) and
`-x/--expand` turns the names into policy statements:

```
$ ./bin/seinfo testdata/policies/sego_test-v32.pol
Statistics for policy file: testdata/policies/sego_test-v32.pol
Policy Version:             32 (MLS enabled)
...

$ ./bin/seinfo -a -x testdata/policies/sego_test-v32.pol
Type Attributes: 4
   attribute data_attr;
	data_t
	log_t
...
```

The Xen component queries (`--iomemcon`, `--ioportcon`, `--pcidevicecon`,
`--pirqcon`, `--devicetreecon`) cannot be combined with the SELinux ones, and
both groups are checked against the policy's target platform.

`sediff` reports the semantic differences of two policies. The section options
select the differences to print; when none is selected everything is compared.
`-A` selects the allow and allowxperm families; `--stats` prints only the
counts. The neverallow families do not exist in a kernel policy, so the
reference tool's (disabled) `--neverallow`/`--neverallowxperm` options are
absent here as well.

```
$ ./bin/sediff testdata/policies/sego_diff_a-v32.pol testdata/policies/sego_diff_b-v32.pol --class --default
Classes (0 Added, 0 Removed, 1 Modified)
   Modified Classes: 1
      * file (1 Removed permissions)
          - append

Defaults (0 Added, 0 Removed, 2 Modified)
   Modified Defaults: 2
      * default_range file +source -target +high -low;
      * default_user file +target -source;
```

`sedta` builds the domain transition graph from the `allow` and
`type_transition` rules: a transition `a -> b` needs `allow a b:process
transition`, a shared executable entrypoint type (`execute` for `a`,
`entrypoint` for `b`), and either `setexec` or a matching `type_transition`,
while a dynamic transition needs `dyntransition` and `setcurrent`. `-s` names
the source type, `-t` plus `-S`/`-A MAX_STEPS` selects the path analysis, and
`-r` reverses it. Without a path analysis, the direct transitions out of (or,
with `-r`, into) the source are printed:

```
$ ./bin/sedta -p testdata/policies/sego_dta-v32.pol -s a_t -t c_t -A 3 --full
Domain transition path 1:
Step 1: a_t -> plain_t
...
```

`seinfoflow` weights every `allow` rule by the permission map (the built-in map
is the standard SELinux permission map; `-m FILE` selects another one), builds
the flow graph from the read and write directions of the permissions, and
prints the flows in the same modes as `sedta`. `-w` (default 3) is the minimum
permission weight, `-b default` or `-b foo:true,bar:false` evaluates the
conditional rules instead of counting both branches:

```
$ ./bin/seinfoflow -p testdata/policies/sego_test-v32.pol -s app_t
Flow 1: app_t -> data_t
Flow 2: app_t -> log_t

2 information flow(s) found.
```

`sechecker` runs the checks of an INI configuration file. Each section is a
check: `check_type` names the module (`assert_te`, `assert_rbac`,
`empty_typeattr`, `ro_execs`, `ro_kmods`), `desc` and `disable` are optional,
and the remaining keys are the check's own options. The report lists every
check with its findings and ends with a result summary; the exit status is 0
when everything passes, 1 when a check fails, 2 for a configuration error and 3
for any other error:

```
$ ./bin/sechecker testdata/checker/checks.ini testdata/policies/sego_test-v32.pol
...
Result Summary:

te_allow                                FAILED (2 failures)
te_exempt                               FAILED (1 failures)
...
8 failure(s) found.
```

## Divergences from setools

The tools follow the CLIs in `/home/qwe/src/setools` (setools 4.8). Where the
installed `/usr/bin/sesearch` (setools 4.2.2) differs, `sesearch` follows 4.8:

1. **No `--neverallow` / `--neverallowxperm`.** They are commented out in the
   4.8 CLI because a binary kernel policy has no assertion rules; the flags are
   therefore rejected as unknown options. For the same reason no rule the tool
   prints can be a neverallow rule.
2. **4.8 option spellings.** `--type_transition` (4.2.2 also accepts `-T`),
   `--role_transition` and `--range_transition`; 4.2.2 spells the last two
   `--role_trans` and `--range_trans` and has no `--type_transition` alias.
   `-Sp` (permission subset matching) exists in 4.8 only - the 4.2.2 library
   implements the same semantics but its CLI has no switch for it.
3. **Permissions are validated.** `-p` is checked against the object classes
   selected with `-c`, or against every class in the policy when no class is
   selected, and an unknown permission is an error
   (`Permission(s) do not exist in the specified classes: ...`). 4.2.2 does no
   validation and silently matches nothing. The same applies to the other
   criteria: an unknown type, class, Boolean or range is a runtime error, and
   when several criteria are invalid the first one reported is the one the
   reference tool reports first (its criteria are resolved in reverse
   alphabetical order, so `-t` is resolved before `-s`).
4. **Malformed extended permissions exit 1**, with the value parser's message
   (`invalid literal for int() with base 16: 'zz'`); 4.2.2 parses `-x` in
   argparse and exits 2 instead.

Known differences that follow from the implementation, not from the reference:

* The error text for a policy that cannot be opened or parsed comes from this
  module's policy reader, not from libsepol. A missing file reports the
  operating system error (`open <path>: no such file or directory`); setools
  prints `[Errno 2] No such file or directory: '<path>'`. A policy that cannot
  be located at all reports `unable to locate an SELinux policy to load` from
  `sego.FindPolicyPath`, where setools raises
  `Unable to locate an SELinux policy to load.`.
* Regular expressions are Go's `regexp` (RE2), so the accepted syntax and the
  wording of a syntax error differ from Python's `re`. Back references and
  lookaround are not supported; the common constructs behave the same.
* `--debug` prints a Go stack trace where the reference prints a Python one.
* The `--help` and usage text keeps the reference tool's options,
  metavariables, argument groups and layout, because that is the interface
  scripts and muscle memory rely on, but the descriptions are written for this
  project instead of copied from the reference (see [NOTICE.md](NOTICE.md)), so
  the prose differs line by line while the flags do not.
* An MLS range criterion (`--range_transition -D`) against a policy compiled
  without MLS fails in both tools, but the reference raises an exception whose
  message is empty, so it prints a blank line; here it reports
  `MLS is not enabled in this policy`.
* The two usage errors this tool raises itself name the same conditions in this
  project's wording (`sesearch: error: No rule type was given; select at
  least one.` where the reference says `At least one rule type must be
  specified.`); the usage block, the option names and the exit status are
  unchanged.
* When several permissions are unknown, the reference lists them in the
  iteration order of a Python `set` (`Permission(s) do not exist any class:
  write, read`); here they are listed in the order the criteria were given
  (`read, write`).
* The terminal width for the usage and help text comes from `COLUMNS`, and
  defaults to 80 columns, which is also what Python's `argparse` assumes when
  its output is not a terminal.
* In setools 4.8 a type attribute with no members is *falsy*, so using one as a
  criterion matches every rule (`--allow -s legacy_attr`, where
  `expandattribute legacy_attr true` left `legacy_attr` without members, prints
  all allow rules). Here it matches nothing, which is what setools 4.2.2 does
  and what `testdata/expected/allow_src_expanded_attr.txt` records; see
  divergence 4b of the corpus README.

The other tools reproduce setools 4.8's output as well, with these known
differences:

* **Set iteration order.** Where setools iterates a Python `set` of permissions,
  aliases or names, its output order depends on the process's hash seed and is
  not reproducible across runs: a modified `allow` rule's permission list
  (`{ write read +lock }`), the order of several modified extended permission
  rules and the order of multiple "expected rule not found" findings. These
  lists are printed sorted here, so the output is stable; a setools run can
  print the same items in another order.
* **MLS alias order.** `seinfo -x` (and `sediff`'s modified category and
  sensitivity aliases) render the alias lists of sensitivities and categories
  in libsepol's hash table order in the reference. That order is not
  reproducible without libsepol, so the alias lists are sorted here.
* **Constraint sets.** A constraint that names more than one type renders its
  set in setools' frozenset iteration order (again hash-seed dependent); this
  tool renders the names in policy order.
* **Lookup diagnostics.** Differences in the wording of operating system errors
  (`open <path>: no such file or directory` here, `[Errno 2] No such file or
  directory: '<path>'` in setools) are the same as for `sesearch`.
* **Checker report times.** `sechecker` records the start and end time of the
  run with the same format as Python's `datetime.now(timezone.utc)`; the values
  naturally differ. The test corpus strips those two lines before comparing.
* **Graphical output.** `sedta -o` and `seinfoflow -o` draw the result graph
  with graphviz' `dot`, as the reference does through pygraphviz. The PNG
  layout and the error text when graphviz is missing differ.
* **Permission map.** `seinfoflow` reads the reference tool's permission map
  format, and its built-in map is the standard SELinux permission map data (see
  NOTICE.md). `-m` accepts an alternative map with the same parser and
  diagnostics. With `-v` the embedded map is reported as `perm_map`, while the
  reference reports the path of its packaged map file.
* **Verbose output.** `-v` logs the same policy, permission map, graph build
  and diff component lines to stderr as the reference; `sediff` emits them up
  front instead of interleaved with stdout, so only the merged stream order
  differs.
* **Extra checker context.** `sechecker` writes the same report as the
  reference and exits with the same statuses (0 pass, 1 failures, 2 config
  error, 3 other error). A check that raises gets the same `Unexpected error:
  ... Failing check.` line.

The full list of differences between the two reference versions, as they were
measured while recording the corpus, is in
[`testdata/expected/README.md`](testdata/expected/README.md).

## Architecture

```
policy/          SELinux binary policy reader (versions 30-35, selinux + xen)
                 policy.Open(path) -> *policy.Policy, the parsed tables; the
                 avtab reader restores libsepol's hash table iteration order
sego/            policy object model and the tools' API (this package, at the
                 repository root): symbols with setools identical statements,
                 rules with setools identical String() rendering, TERuleQuery,
                 RBACRuleQuery, MLSRuleQuery, XPermSet/ParseXPermSet,
                 SortRules, FindPolicyPath, statement and context rendering,
                 constraints, ocontexts, DiffPolicies, the ordered DiGraph with
                 networkx compatible traversals, DomainTransitionAnalysis,
                 PermissionMap and InfoFlowAnalysis
checker/         the sechecker checks: INI config reader, check registry and
                 the assert_te, assert_rbac, empty_typeattr, ro_execs and
                 ro_kmods modules
internal/argparse  argparse compatible parser, usage and help rendering
internal/graphout  graphviz (dot) invocation for the graphical results
cmd/sesearch/    the commands; each has args.go (option table, help prose)
cmd/seinfo/      and main.go (policy loading, output, errors)
cmd/sediff/
cmd/sedta/
cmd/seinfoflow/
cmd/sechecker/
integration_test.go        replays testdata/queries.txt for sesearch
tools_integration_test.go  replays testdata/tools.txt for the other tools
```

The package split keeps the argument handling (which has to look like Python's
`argparse`) away from the policy logic, so that every tool shares the same
`argparse` implementation and the same policy and analysis code.

## Test fixtures

`testdata/` is generated and committed so that the tests need nothing but the
checkout:

* `testdata/src/*.conf` - hand written `policy.conf` sources covering the TE,
  TE extended permission, RBAC and MLS rule families, conditionals, attributes
  and the object class/permission variants the queries can select on.
* `testdata/policies/*.pol` - the sources compiled with `checkpolicy` at policy
  versions 30, 32, 33 and 35 by `testdata/gen.sh` (reproducible byte for byte;
  `bash testdata/gen.sh --check` recompiles into a temporary directory and
  compares).
* `testdata/queries.txt` - the sesearch query matrix: tab separated case name,
  policy fixture, command line arguments and, when it is not zero, the
  expected exit status.
* `testdata/expected/<case>.txt` - the recorded stdout of the reference tool for
  each sesearch case (an existing but empty file means "no output"), recorded
  by `testdata/gen_expected.sh`.
* `testdata/tools.txt` - the same matrix for `seinfo`, `sediff`, `sedta`,
  `seinfoflow` and `sechecker`: tool, case name, arguments and exit status.
* `testdata/expected_tools/<case>.txt` - the recorded stdout for the tool
  matrix, recorded by `testdata/gen_tools_expected.sh` (the `sechecker` report's
  start and end time lines are omitted).
* `testdata/checker/*.ini` and `testdata/perm_map` - the checker
  configurations and the permission map the matrix uses.

The goldens are recordings of the reference implementations: `/usr/bin/sesearch`
(setools 4.2.2) for the cases it can run, and a throw-away build of the in-tree
setools 4.8 for `-Sp`, the v33/v35 fixtures, the `sego_nlmsg` fixtures and the
`extra_cond_xperm` fixture. `testdata/expected/README.md` documents the exact
recipe, which oracle produced which case, the provenance of every case, and the
known differences between the two reference versions.

Everything under `testdata/` is written for this project: the policy sources are
hand written, the compiled fixtures are generated from them by the checked-in
scripts, and the goldens record the *output* of the reference tools for queries
over our own sources. No setools file, source or binary is redistributed here;
[NOTICE.md](NOTICE.md) describes the provenance in detail.

## License

MIT, see [LICENSE](LICENSE). Copyright (c) 2026 elnx.

The module has no Go dependencies outside the standard library, and the source
tree contains no third-party code - [NOTICE.md](NOTICE.md) records which
implementations the behaviour was written against (libsepol for the policy
format, setools for the tool behaviour) and why reproducing their *interface*
does not make this a derivative work of them.
