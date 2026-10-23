# sego sesearch test corpus

Hand written policy sources, their compiled binaries and the recorded output of
the reference `sesearch` for a matrix of search invocations.  Everything in this
directory is generated (except the sources and the scripts); the files are
committed so that Go integration tests need nothing but the checkout.

```
testdata/
  src/sego_test.conf          main policy source (all TE/TE-xperm/RBAC/MLS coverage)
  src/sego_nlmsg.conf         nlmsg extended permissions (own policy, see below)
  src/extra_cond_xperm.conf   extended permissions inside a condition (version 35 only)
  gen.sh                      src/*.conf -> policies/*.pol   (reproducible)
  gen_expected.sh             queries.txt -> expected/*.txt  (reproducible)
  queries.txt                 the machine readable query matrix (103 cases)
  policies/*.pol              9 compiled fixtures (committed)
  expected/<case>.txt         103 golden stdout files (committed)
```

## Regenerating

### The compiled fixtures

```
bash testdata/gen.sh            # regenerate policies/*.pol in place
bash testdata/gen.sh --check    # compile to a temp dir and byte-compare, exit != 0 on any difference
```

`gen.sh` runs `$CHECKPOLICY -c <version> -M -U reject -o <fixture> <source>`
for every (source, version) pair below.  Defaults:

| variable           | default                                          |
|--------------------|--------------------------------------------------|
| `CHECKPOLICY`      | `/home/qwe/src/selinux/checkpolicy/checkpolicy`   |
| `LIBSEPOL_DIR`     | `/home/qwe/src/selinux/libsepol/src` (prepended to `LD_LIBRARY_PATH`) |
| `CHECKPOLICY_FLAGS`| empty                                             |

`bash testdata/gen.sh --check` is the reproducibility proof: it recompiles every
fixture into a fresh temporary directory and `cmp`s it against the committed
file, so it needs nothing but `src/`, `policies/` and `$CHECKPOLICY`.  Result at
the time of writing: *all 9 fixtures reproduce byte for byte* (re-run after
every source change, and once more from a different working directory).

### The golden outputs

```
bash testdata/gen_expected.sh            # regenerate expected/*.txt
bash testdata/gen_expected.sh --check    # regenerate to a temp dir and byte-compare
bash testdata/gen_expected.sh --compare  # run both oracles and report differences
```

Oracles (both are the *reference* implementation, `setools`):

| variable          | default                                        | used for |
|-------------------|------------------------------------------------|----------|
| `SESEARCH`        | `/usr/bin/sesearch` (setools **4.2.2**)         | 74 of 103 cases |
| `SESEARCH_ENV`    | `env -u PYTHONPATH -u PYTHONHOME`              | guards the 4.2.2 run against a leaked `PYTHONPATH` |
| `SESEARCH48`      | `/home/qwe/.local/share/uv/python/cpython-3.12.12-linux-x86_64-gnu/bin/python3.12 /tmp/setools48/sesearch` | 29 of 103 cases |
| `SESEARCH48_ENV`  | `LD_LIBRARY_PATH=/home/qwe/src/selinux/libselinux/src:/home/qwe/src/selinux/libsepol/src PYTHONPATH=/tmp/setools48` | ditto |

`SESEARCH48*` point at a throw-away build of the *in-tree* setools
(`/home/qwe/src/setools`, 4.8.0.dev) because the 4.2.2 CLI cannot express or
cannot read part of the matrix.  The build lives in `/tmp` and touches nothing
of the checkout; the recipe is in "Building the 4.8 oracle" below, and both
variables can be pointed at any other setools 4.8 build.

`gen_expected.sh` sanity checks every case and fails loudly on any of:

* a case that exits 0 with empty stdout which is **not** in the documented
  no-match list (12 cases, all listed below);
* a case in the no-match list that produces output;
* an exit status that differs from field 4 of `queries.txt` (3 error cases: the
  two `legacy_neverallow*` usage errors and `no_ruletype`);
* a malformed line (wrong number of fields, missing fixture).

Current result: **103 cases, 88 with output, 15 legitimately empty, 0 problems**,
and `gen_expected.sh --check` reports *all 103 cases reproduce byte for byte*.

### Building the 4.8 oracle (recipe used here)

```
# 1. copy the in-tree reference implementation to a scratch directory
mkdir -p /tmp/setools48 && cp -r /home/qwe/src/setools/setools \
      /home/qwe/src/setools/setup.py /home/qwe/src/setools/sesearch /tmp/setools48/

# 2. a Python >= 3.9 interpreter is required: the in-tree code uses PEP 585/604
#    syntax (list[str], X | Y) that Python 3.8 cannot evaluate at runtime.
/home/qwe/.local/share/uv/python/cpython-3.12.12-linux-x86_64-gnu/bin/python3.12 \
      -m venv /tmp/setools48/venv312
/tmp/setools48/venv312/bin/pip install "cython>=3.0" networkx

# 3. build the policyrep extension in place.  The upstream setup.py cannot be
#    used as is (pyproject.toml conflicts with modern setuptools, and the file
#    itself uses 'list[str]' annotations at module level), so /tmp/setools48/
#    build.py is a 20 line equivalent:
#      Extension('setools.policyrep', ['setools/policyrep.pyx'],
#                include_dirs=[<userspace>/libsepol/include,
#                              <userspace>/libselinux/include],
#                libraries=['selinux', 'sepol'],
#                library_dirs=[<userspace>/libsepol/src,
#                              <userspace>/libselinux/src, '.', '/usr/lib', …],
#                cython_include_dirs=['setools/policyrep'],
#                compiler_directives={...})   # then cythonize(..., include_path=…)
cd /tmp/setools48 && USERSPACE_SRC=/home/qwe/src/selinux \
      ./venv312/bin/python build.py build_ext --inplace

# 4. run it (this is exactly the default SESEARCH48/SESEARCH48_ENV pair)
LD_LIBRARY_PATH=/home/qwe/src/selinux/libsepol/src PYTHONPATH=/tmp/setools48 \
      /home/qwe/.local/share/uv/python/cpython-3.12.12-linux-x86_64-gnu/bin/python3.12 \
      /tmp/setools48/sesearch --allow /home/qwe/src/sego/testdata/policies/sego_test-v35.pol
```

## Reference provenance

| oracle | cases | why |
|--------|-------|-----|
| `/usr/bin/sesearch` 4.2.2 | 74 | the reference CLI named by the task; reads policy versions up to 32 |
| setools 4.8 (in-tree build) | 29 | `-Sp` (flag does not exist in 4.2.2), v33/v35 fixtures, `sego_nlmsg` fixtures, `extra_cond_xperm` fixtures, the 7 cases where 4.2.2 prints complete ioctl driver ranges differently, and the 2 `legacy_neverallow*` cases whose golden is the 4.8 usage error |

Cases recorded from 4.8 (`expected/README.md` is the only place this is
recorded; `queries.txt` carries no extra column):

```
allow_and_allowxperm allow_class_single_v33 allow_class_single_v35 allow_perm_subset
allow_perm_subset_class allow_perm_subset_multiple allowxperm_all
cond_xperm_all_v35 cond_xperm_bool_v35 cond_xperm_dontaudit_all_v35 cond_xperm_value_v35
legacy_neverallow_te legacy_neverallowxperm_te
nlmsg_allow_and_xperm nlmsg_allowxperm_all nlmsg_auditallowxperm nlmsg_dontauditxperm
nlmsg_xperm_nomatch nlmsg_xperm_range nlmsg_xperm_single nlmsg_xperm_two_values_exact
range_transition_v35 te_mixed_ruletypes te_xperm_ruletypes type_trans_v33 type_trans_v35
xperm_ioctl_driver_range xperm_ioctl_driver_range_exact xperm_ioctl_driver_range_v30
```

For 86 cases both oracles were run over the same argv/fixture and compared
(`gen_expected.sh --compare`): **73 are byte identical**, 8 differ in stdout
(the seven complete-ioctl-driver cases of divergence 4 plus the empty-attribute
case of divergence 4b) and 5 differ in exit status (the v33/v35 cases 4.2.2
cannot read, divergence 5).  The remaining 17 cases cannot be compared at all
(2 `--neverallow*` which are 4.8 usage-error assertions by design, 3 `-Sp`,
8 `sego_nlmsg`, 4 `extra_cond_xperm`).  This is why a corpus recorded mostly
from 4.2.2 is still valid for an implementation that mirrors the 4.8 CLI.

## Divergences between the two reference versions

1. **Option names.** 4.2.2 spells the RBAC/MLS rule type switches
   `--role_trans` / `--range_trans` and has no `--type_transition` alias;
   4.8 uses `--role_transition` / `--range_transition`.  `-T` exists in both and
   is what the matrix uses.  `queries.txt` always uses the 4.8 spelling;
   `gen_expected.sh` renames the two long options for the 4.2.2 runs (pure
   rename, nothing else about the argv changes).
2. **`-Sp` does not exist in the 4.2.2 CLI** (the 4.2.2 *library* implements the
   same `perms_subset` semantics, only the switch is missing), so the three
   `*_subset*` cases are recorded with 4.8.
3. **`--neverallow` / `--neverallowxperm` are 4.2.2 only** (commented out in the
   4.8 CLI).  The two `legacy_neverallow*` cases assert 4.8 CLI parity: the
   invocation must fail as a usage error, so their golden is **exit 2 with empty
   stdout** and it is recorded with the 4.8 oracle
   (`sesearch: error: unrecognized arguments: --neverallow`, usage text on
   stderr).  4.2.2 accepts the flags, prints nothing and exits 0.  The neverallow
   *semantics* are covered independently of that flag by `neverallow_absent_te`
   and `neverallow_absent_xperm`, which use ordinary 4.8-valid argv to look for
   exactly the rule (`allow plain_t config_t:file read`) and the extended
   permission (`allowxperm plain_t data_t:chr_file ioctl 0x1234`) that the two
   neverallow rules forbid; both match nothing with exit 0, proving the
   assertions never reached the binary policy.
4. **Complete ioctl driver ranges are printed differently.**  For a rule that
   covers a whole driver code (source `ioctl { 0x0000-0x00ff }`) 4.2.2 prints

   ```
   allowxperm client_t log_t:chr_file ioctl 0x0000;              <- 4.2.2
   allowxperm client_t log_t:chr_file ioctl 0x0000-0x00ff;       <- 4.8
   ```

   and `-x 0x0000-0x00ff -ex` matches the rule in 4.8 but *not* in 4.2.2.
   The recorded corpus follows 4.8 here (cases `allowxperm_all`,
   `allow_and_allowxperm`, `te_xperm_ruletypes`, `te_mixed_ruletypes`,
   `xperm_ioctl_driver_range`, `xperm_ioctl_driver_range_exact`,
   `xperm_ioctl_driver_range_v30`) so that the whole corpus is consistent.
   A Go implementation mirroring 4.2.2 would have to print `0x0000` in these
   seven cases instead.
4b. **An expanded attribute with no members is mishandled by 4.8.**
   `sego_test.conf` declares `expandattribute legacy_attr true;`, so
   `legacy_attr` stays in the binary policy as a type attribute with **zero
   members** (both versions agree on that:
   `p.lookup_typeattr("legacy_attr").expand() == []`).  `--allow -s
   legacy_attr` then behaves differently:

   ```
   /usr/bin/sesearch  4.2.2 :  0 matches        (the sane answer)
   setools 4.8         :  all 17 allow rules, with and without -ds
   ```

   (`TERuleQuery` in 4.8 matches every rule when the criteria is resolved to an
   empty type attribute.)  The corpus follows **4.2.2** for this case
   (`allow_src_expanded_attr` is one of the documented empty cases), because
   matching all rules for an attribute that has no members looks like a bug
   rather than behaviour worth reproducing.
5. **Policy version ceiling.** 4.2.2 (libsepol 3.0) reads at most policy
   version 32; every v33/v35 case exits 1 with

   ```
   Invalid policy: <path>. A binary policy must be specified. (use e.g. policy.32 or sepolicy) Source policies are not supported.
   ```

   (this is the caught exception message, which both CLIs print on **stdout**,
   followed by `sys.exit(1)`; see "Error handling" below).
6. **nlmsg extended permissions are unreadable by 4.2.2** (libsepol 3.0 has no
   `AVRULE_XPERMS_NLMSG`): *any* query against a policy containing an nlmsg
   xperm rule aborts with `Unknown extended permission: 3` on stdout and exit 1,
   even for `--allow`.  That is why nlmsg coverage lives in its own policy
   source.
7. **Argument validation.** 4.8 rejects `-p/-x/-b` combined with RBAC/MLS rule
   searches (`-p/--perms, -x/--xperms, and -b/--bool options are only supported
   with TE rule searches.`); 4.2.2 silently ignores them.  Related 4.8-only
   behaviour (`--neverallow`, `-Sp`) is listed above.  The argument-error cases
   in the matrix are `no_ruletype` (argv `-s app_t`, exit 2, both oracles agree)
   and the two `legacy_neverallow*` cases (exit 2 from 4.8, exit 0 from 4.2.2).

## Error handling as observed in the reference CLI

Both reference CLIs wrap the whole query in

```python
except Exception as err:
    if args.debug:
        raise
    else:
        print(err)
    sys.exit(1)
```

so runtime errors (unreadable policy, unknown extended permission, unknown
type/class name in a criteria, …) are printed on **stdout**, exit status 1, and
stdout carries no rule output at all.  Argument errors are different: argparse
writes usage to **stderr** and exits 2 (the `no_ruletype` case).  The goldens
only capture stdout, so for an error case the expected file is empty and the
non-zero status is recorded in field 4 of `queries.txt`.

## Fixtures

| source | versions | size (bytes) | sha256 |
|--------|----------|--------------|--------|
| `sego_test.conf` | 30 | 4203 | `c75a6b3238b77fc72fab7e12008012b6af006cde190b7ece1c252a37d30024d2` |
| `sego_test.conf` | 32 | 4211 | `e0bc8fc9381b5d00e5b165ce56916f41887e7375d2d2e3678864e9bcf32b58db` |
| `sego_test.conf` | 33 | 4256 | `87f2be9298e3f55616621782b848e09a875852e58769faaa72495c1c67937e71` |
| `sego_test.conf` | 35 | 4268 | `ce62c57b926ff68a6daeb1cbd9ae97ba469f0846b47a8ea8bcc23cf53514bd6e` |
| `sego_nlmsg.conf` | 30 | 1404 | `446e56322ccece59c97b2546f8af13b6d0976a7c8af321cd7e5d53916aaec5c4` |
| `sego_nlmsg.conf` | 32 | 1412 | `411f05faf8dc10a8340b049e302accc59ba55b3d373797823234cb36361945fa` |
| `sego_nlmsg.conf` | 33 | 1412 | `b17ff0ce96a600f4aeef6be0f7407170668692d97d0a8d4b4f0d580a01f2c782` |
| `sego_nlmsg.conf` | 35 | 1424 | `5539c61049b5d8d71af4852e986143aafe3825d29f10efc192069e32ed464ecb` |
| `extra_cond_xperm.conf` | 35 | 1296 | `342c8b980417f2cf288de1af7aae994c40fa555e67f5eced59c4789ccc16608e` |

### Version differences (verified, not assumed)

* **Filename transitions are re-encoded at version 33.**  `sego_test.conf` has
  three filename transitions, two of them sharing the name `sego_shared` but with
  different source types (`app_t`, `server_t`).  Up to version 32 libsepol writes
  one `filename_trans` entry per (name, source type) pair
  (`filename_write_one_compat`, `p->filename_trans_count` entries = 3), from
  version 33 (`POLICYDB_VERSION_COMP_FTRANS`) one entry per (name, object type
  class) with an ebitmap of source types (`hashtab nel` = 2).  Visible directly
  in the fixtures: `grep -o sego_shared` finds **2** occurrences in the v30/v32
  fixtures and **1** in the v33/v35 fixtures (`sego_app_only` appears once in
  every version).  All four versions still decode to the same three rules
  (`type_transition app_t data_t:file default_t sego_app_only;`,
  `… default_t sego_shared;`, `type_transition server_t data_t:file plain_t
  sego_shared;`), and the recorded goldens prove it end-to-end:
  `type_trans_all` (v32) == `type_trans_v30` == `type_trans_v33` ==
  `type_trans_v35` byte for byte, and the same holds for
  `allow_class_single`/`allow_class_single_v30/_v33/_v35`,
  `range_transition_all`/`_v30`/`_v35` and
  `xperm_ioctl_driver_range`/`xperm_ioctl_driver_range_v30`.  (The files get
  slightly *bigger* with the newer version numbers, because the version adds
  unrelated tables/headers; the size difference alone would be weak evidence,
  hence the string count and the golden comparison above.)
* **Conditional extended permissions need version 34 or later**
  (`POLICYDB_VERSION_COND_XPERMS`).  checkpolicy rejects `extra_cond_xperm.conf`
  at 30/32/33 with

  ```
  libsepol.validate_cond_av_list: Invalid cond av list
  libsepol.validate_cond_list: Invalid cond list
  libsepol.policydb_validate: Invalid policydb
  checkpolicy: validation of policydb failed
  ```

  and compiles it at 35.  `gen.sh` therefore only builds that source at 35.

## What the sources cover (and where)

`src/sego_test.conf` — compiled at 30/32/33/35:

| # | requirement | declarations / rules | cases |
|---|-------------|----------------------|-------|
| 1 | plain `allow`/`auditallow`/`dontaudit`, concrete + attributes (multi-member attribute, a type in two attributes, attribute as source *and* as target, `self`) | `app_t/server_t/client_t` in `domain`, `data_t/config_t` in `data_attr`, `log_t` in `data_attr`+`special_attr`; `allow domain data_attr:file read;` vs `allow plain_t special_attr:file write;`; `allow special_attr data_t:dir …`; `allow app_t self:process sigchld;`; `expandattribute legacy_attr true` | `allow_*`, `auditallow_all`, `dontaudit_all`, `allow_src_expanded_attr*` |
| 2 | `type_transition` / `type_change` / `type_member`, concrete default type and attribute source | 3 × `type_transition`, 2 × `type_change`, 2 × `type_member` (all default `default_t`, three of them attribute sourced) | `type_trans_all`, `type_change_all`, `type_member_all`, `type_trans_src_attr*` |
| 3 | filename transitions: two names, one name with two source types | `type_transition app_t data_t:file default_t "sego_app_only"`, `… "sego_shared"`, `type_transition server_t data_t:file plain_t "sego_shared"` | `type_trans_*`, `type_trans_v30/_v33/_v35` |
| 4 | `role allow` / `role_transition`: type target, role target, class-only variants | `allow r_admin r_user;` etc. (`--role_allow` needs role targets), `role_transition r_admin app_t r_ops;`, `role_transition r_ops special_attr:file r_user;`, `role_transition r_ops data_t:{file,dir,process} r_admin;` | `role_allow_*`, `role_transition_*` |
| 5 | `range_transition`: single level, `s1 - s3`, `s1:c0.c3` | 4 rules, one with an attribute source | `range_transition_*` |
| 6 | conditionals: 4 booleans, `&&`, `\|\|`, `!`, nested parens, several allows per block, a `dontaudit`, two Booleans in one expression, `else` | 4 `bool` declarations, 4 `if` statements (one with `else`) | `allow_bool_*`, `allow_src_attr_indirect`, `allow_and_allowxperm` |
| 7 | extended permissions | `allowxperm … ioctl 0x5401` (single), `ioctl { 0x0000-0x00ff }` (complete driver), `ioctl { 0x1000-0x1010 0x2000-0x2005 }` (two runs), `ioctl 0x5404` with an attribute source, `auditallowxperm`, `dontauditxperm` | `xperm_*` |
| 8 | classes with/without a `common`, permission unique to one class | `file/dir/chr_file` inherit `file_common`, `socket/netlink_socket` inherit `sock_common`, `process` has no common; `ioctl` only in `chr_file`, `search/open` only in `dir`, `fork` only in `process`, `nlmsg` only in `netlink_socket` | `allow_class_*`, `allow_perm_*` |
| 9 | `neverallow` / `neverallowxperm` present in the source, absent from the policy | 2 × `neverallow`, 1 × `neverallowxperm`, none of them satisfied by the allow rules (checkpolicy would refuse otherwise) | `neverallow_absent_te`, `neverallow_absent_xperm` (empty output, exit 0) and `legacy_neverallow_te`, `legacy_neverallowxperm_te` (4.8 usage error, exit 2) |

`src/sego_nlmsg.conf` — compiled at 30/32/33/35; required because the 4.2.2
oracle aborts on any policy containing nlmsg extended permissions (divergence 6):
`allowxperm`/`auditallowxperm`/`dontauditxperm`/`neverallowxperm` over
`netlink_socket:nlmsg` with a single value, a range, two disjoint values and an
attribute source.  Cases: `nlmsg_*`.

`src/extra_cond_xperm.conf` — version 35 only; `allowxperm`/`dontauditxperm`
inside `if (…) { } [else { }]` blocks (version 34+ construct).  Cases:
`cond_xperm_*`.

## Encoding details worth knowing when reading the fixtures

Observed through the reference tools while building this corpus:

* `role_transition SRC TYPE ROLE;` (the short form without a class) compiles to
  class **`process`**: `role_transition r_admin app_t r_ops;` comes back as
  `role_transition r_admin app_t:process r_ops;`.  The class-qualified form
  (`role_transition r_ops data_t:file r_admin;`) keeps its class.
* `type_transition`, `type_change`, `type_member` and `range_transition` rules
  whose **source is an attribute** are expanded into one rule per member type in
  the binary policy: `-s domain -ds` matches nothing while `-s domain` (indirect)
  matches the expanded rules (`range_transition_src_attr*`,
  `type_trans_src_attr*`).
* `allow`/`auditallow`/`dontaudit` rules and `allowxperm` rules keep their
  attribute source/target (not expanded), so `-s domain -ds` matches
  `allow domain data_attr:file read;` (`allow_src_attr_direct`) and
  `-t special_attr -dt` matches `allow plain_t special_attr:file write;`
  (`allow_tgt_attr_direct`).
* `expandattribute legacy_attr true;` rewrites the rule that named it to
  `allow legacy_t data_t:file lock;`.  The attribute itself is still present in
  the binary policy but has **no member types** (`typeattribute` entry with an
  empty ebitmap): `--allow -s legacy_attr` matches nothing with 4.2.2,
  `--allow -s legacy_t` matches the expanded rule.  (4.8 matches everything for
  the empty attribute, see divergence 4b.)
* Conditionals are stored in simplified form, so the printed expression is not
  the source text: `if (c_alpha && !c_beta)` is stored as `[ ! c_beta && c_alpha ]`
  and `if (!(c_beta || c_delta))` as `[ c_delta || c_beta ]:False`.
* `allowxperm` with two disjoint ranges stays two rules (`0x1000-0x1010`,
  `0x2000-0x2005`), therefore `-x 0x1000-0x1010,0x2000-0x2005 -ex` matches
  nothing while the same argv without `-ex` matches both
  (`xperm_ioctl_two_runs_exact` is empty, `xperm_ioctl_two_runs` is not).

## Cases that are empty on purpose (15)

"Empty" means the expected file exists and is 0 bytes.  Twelve of them exit 0
(the "matches nothing" cases), the other three are argv errors documented by
field 4 of `queries.txt`: `legacy_neverallow_te` and `legacy_neverallowxperm_te`
(exit 2, the two flags were removed in 4.8) and `no_ruletype` (exit 2, no rule
type selected).

| case | why it matches nothing |
|------|------------------------|
| `allow_src_expanded_attr` | `legacy_attr` was expanded by `expandattribute … true` and has no member types left |
| `type_trans_src_attr_direct` | attribute-sourced type transitions are expanded per type |
| `range_transition_src_attr_direct` | ditto for range transitions |
| `xperm_nomatch` | ioctl value 0xdead is not granted anywhere |
| `xperm_ioctl_two_runs_exact` | the two ranges are separate rules, no single rule matches exactly |
| `allow_bool_nomatch` | `-b c_delta -eb` requires the expression to be exactly `c_delta` |
| `allow_nomatch_src` | `default_t` is never a rule source |
| `dontaudit_class_nomatch` | no dontaudit rule on class `process` |
| `type_trans_nomatch_tgt` | no type transition targets `config_t` |
| `nlmsg_xperm_nomatch` | deliberately never granted (the same range is a `neverallowxperm`) |
| `neverallow_absent_te` | looks for `plain_t config_t:file read`, forbidden by `neverallow` and therefore absent |
| `neverallow_absent_xperm` | looks for `plain_t data_t:chr_file ioctl 0x1234`, forbidden by `neverallowxperm` and therefore absent |
| `legacy_neverallow_te`, `legacy_neverallowxperm_te` | argv error: the flag no longer exists in 4.8 (exit 2, stdout empty) |
| `no_ruletype` | argv error: no rule type was selected (exit 2, stdout empty) |

## Known coverage gaps

* **Extended permissions inside a conditional** are only representable from
  policy version 34 on, so they exist only in the v35 fixture
  (`extra_cond_xperm-v35.pol`); there is no v30/v32/v33 counterpart (see the
  checkpolicy failure text above).
* **`-rd` (regular expression on the rule default) is not implemented for MLS
  rule queries** in either setools version: `MLSRuleQuery` has no
  `default_regex` parameter, and the CLI silently ignores `-rd` for
  `--range_transition`.  No case uses it; only `-D` on range transitions.
* **`role_transition` has no role-typed target field** in the policy
  representation (source role, target *type*/type-attribute, default *role*).
  Role targets are exercised through `--role_allow` instead (including a role
  attribute target: `allow r_user r_attr;` compiles to `allow r_user r_ops;`).
* **Policy versions 31 and 34 are not built.**  The matrix uses 30 (oldest
  supported), 32 (newest the 4.2.2 oracle can read), 33 (first compressed
  filename-transition encoding) and 35 (newest, `neveraudit`).
* **`--neverallow` / `--neverallowxperm` still exist in 4.2.2 only.**  Nothing
  can be recorded *from 4.8* with those flags, so the two `legacy_*` cases assert
  what 4.8 does instead (usage error, exit 2) and the neverallow semantics are
  asserted through `neverallow_absent_te` / `neverallow_absent_xperm`.
* **stderr is not part of the golden data** (only stdout and the exit status,
  which is field 4 of `queries.txt`).  The three cases with interesting stderr
  are the argparse usage errors `no_ruletype`, `legacy_neverallow_te` and
  `legacy_neverallowxperm_te` (all exit 2, empty stdout); the oracle's stderr for
  each run is printed by `gen_expected.sh` and is summarised in the divergence
  section above.
