# policy/testdata

Compiled policy fixtures for the `sego` query tests (`query_test.go`,
`render_test.go`). Every fixture is compiled from our own sources in `src/`
by `gen.sh`; none of them is derived from another project's test data.

## Sources and fixtures

| source                | fixtures (`<stem>-v<NN>.pol`)   | MLS | used by |
|-----------------------|----------------------------------|-----|---------|
| `src/te_semantics.conf` | `te_semantics-v{30,32,33,35}.pol` | yes | `TestTERuleQuery*`, `TestConditionalRendering`, `TestMatchIndirect` |
| `src/xperm.conf`        | `xperm-v{30,32,33,35}.pol`        | yes | `TestTERuleQueryXperm*`, `TestAVRuleXpermRendering`, `TestFileNameTERuleRendering` |
| `src/rbac.conf`         | `rbac-v{30,32,33,35}.pol`         | yes | `TestRBACRuleQuery` |
| `src/mls_ranges.conf`   | `mls_ranges-v{30,32,33,35}.pol`   | yes | `TestMLSRuleQuery`, `TestMLSRuleQueryRangeFlags`, `TestLevelAndRangeRendering`, `TestParseRangeErrors` |
| `src/non_mls.conf`      | `non_mls-v32.pol`                 | no  | `TestNonMLSPolicy` |

The query tests load the `-v30` fixtures; the other versions exist so the
policy parser and the version handling code are exercised over more than one
policy format (`version_test.go`, `policy/parse_test.go`).

The hand written sources carry descriptive symbol names rather than positional
ones, so a name states what the symbol demonstrates (for example `src_direct`
is the attribute used by the direct source criterion, `c_alpha`/`c_beta` are
the two classes of the class list criterion, `grant_read` is one of the
permissions used by the permission set criteria).

## Regenerating

```
bash policy/testdata/gen.sh           # regenerate the fixtures in place
bash policy/testdata/gen.sh --check   # recompile into a temp dir and compare
```

`gen.sh` invokes checkpolicy as

```
checkpolicy -c <version> -M -U reject -o <fixture> <source>   # MLS sources
checkpolicy -c <version>    -U reject -o <fixture> <source>   # non_mls.conf
```

See `gen.sh` for the `CHECKPOLICY` / `LIBSEPOL_DIR` environment variables.
The output is deterministic; `--check` must report byte-identical fixtures.
