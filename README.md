# sego

`sego` is a pure-Go reimplementation of the [setools](https://github.com/SELinuxProject/setools)
SELinux policy analysis tools. It reads *binary kernel policies* directly - no
libsepol, no cgo, no Python - and provides the policy object model, the rule
queries and the rule rendering the tools need.

`sesearch` (`cmd/sesearch`) is the first tool: a search over the rules of a
policy, reproducing setools 4.8's command line, output order, exit statuses and
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
| `make` / `make build` | build `bin/sesearch`, with the version compiled in |
| `GOOS=windows make` | cross build; the output is `bin/sesearch.exe` |
| `make dist` | build every platform in `DIST_PLATFORMS` into `bin/dist/` |
| `make test` | `go test ./...` - unit tests plus the query matrix when it is present |
| `make lint` | `gofmt -l .`, `go vet ./...` and `gopls check` when gopls is on `PATH` |
| `make fixtures` | regenerate `testdata/policies/*.pol` with `testdata/gen.sh` |
| `make clean` | remove `bin/` |
| `make help` | list the targets |

`GOOS` and `GOARCH` default to the host and can be given either way round, so
`GOOS=windows make` and `make GOOS=windows` are the same build; the Windows
suffix is added automatically:

```
$ GOOS=windows make            # -> bin/sesearch.exe
$ make GOOS=darwin GOARCH=arm64  # -> bin/sesearch (Mach-O arm64)
```

`make dist` cross compiles the release set (`linux/amd64`, `windows/amd64`,
`darwin/amd64`, `darwin/arm64` by default - override with
`DIST_PLATFORMS="linux/arm64 ..."`), names each artifact
`sesearch-<os>-<arch>[.exe]`, writes `bin/dist/SHA256SUMS` next to them and runs
the host's own artifact once to smoke test it. Because the module is pure Go
with no cgo, no cross toolchain is needed:

```
$ make dist
  building bin/dist/sesearch-linux-amd64 (GOOS=linux GOARCH=amd64)
  building bin/dist/sesearch-windows-amd64.exe (GOOS=windows GOARCH=amd64)
  building bin/dist/sesearch-darwin-amd64 (GOOS=darwin GOARCH=amd64)
  building bin/dist/sesearch-darwin-arm64 (GOOS=darwin GOARCH=arm64)
version 1.2.3, 4 platforms in bin/dist:
   3372296  sesearch-linux-amd64
   ...
```

`--version` reports `dev` for a plain `go build`; release builds inject the
version, and `make build` does it from `VERSION` (default: `git describe
--tags --always --dirty`, or `dev` outside a git checkout):

```
go build -ldflags "-X main.version=1.2.3" -o bin/sesearch ./cmd/sesearch
```

`make test` needs no network access, no SELinux policy and no root: the module
has no dependencies outside the standard library, and the integration test skips
itself when `testdata/queries.txt` is missing. It does need the `go` toolchain
on `PATH`, because it builds the command once into a temporary directory.

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

## Divergences from setools

`sesearch` follows the CLI in `/home/qwe/src/setools/sesearch` (setools 4.8).
Where the installed `/usr/bin/sesearch` (setools 4.2.2) differs, this tool
follows 4.8:

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

The full list of differences between the two reference versions, as they were
measured while recording the corpus, is in
[`testdata/expected/README.md`](testdata/expected/README.md).

## Architecture

```
policy/          SELinux binary policy reader (versions 30-35, selinux + xen)
                 policy.Open(path) -> *policy.Policy, the parsed tables
sego/            policy object model and the tools' API
                 sego.Open(path), symbols (types, attributes, roles, classes,
                 Booleans, sensitivities, categories), rules with setools
                 identical String() rendering, TERuleQuery, RBACRuleQuery,
                 MLSRuleQuery, XPermSet/ParseXPermSet, SortRules,
                 FindPolicyPath
cmd/sesearch/    the command
                 args.go   argparse compatible parser, usage and help rendering
                 main.go   policy loading, query construction, output, errors
                 subs.go   Boolean name substitution (booleans.subs_dist)
integration_test.go   replays testdata/queries.txt against the built command
```

The package split keeps the argument handling (which has to look like Python's
`argparse`) away from the policy logic, so that the remaining setools tools can
reuse `sego` unchanged.

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
* `testdata/queries.txt` - the query matrix: tab separated case name, policy
  fixture, command line arguments and, when it is not zero, the expected exit
  status.
* `testdata/expected/<case>.txt` - the recorded stdout of the reference tool for
  each case (an existing but empty file means "no output"), recorded by
  `testdata/gen_expected.sh`.

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
