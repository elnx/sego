# Provenance and third-party references

`sego` is an independent Go implementation, released under the MIT license (see
`LICENSE`). It contains no third-party source code. This file records what the
implementation was written against, so that the claim is checkable.

## The policy format

The binary kernel policy format read by `policy/` is a data format defined by
the Linux kernel's SELinux subsystem and by
[libsepol](https://github.com/SELinuxProject/selinux) (LGPL-2.1-or-later). The
layout, field sizes, bit values and encodings were taken from the format
documentation and from reading libsepol's reader/writer (`libsepol/src/write.c`,
`policydb.c`, `avtab.c`, `conditional.c`, `ebitmap.c`) and the format header
(`sepol/policydb/*.h`). Format facts are not copyrightable, and no libsepol code
was copied: `policy/` is a Go implementation written for this project.

## Tool behaviour

Rule rendering, query semantics, diagnostics, exit statuses and the command
line interface were implemented to match
[setools](https://github.com/SELinuxProject/setools) (GPL-2.0-only), which is
the reference for what the tools do (`sesearch`, `seinfo`, `sediff`, `sedta`,
`seinfoflow` and `sechecker`). This means:

- The *behaviour* matches: which rules a query returns, the order and text of
  the rendered rule statements and the exit statuses. So do the *per-symbol*
  diagnostics, which are short factual phrases (`foo is not a valid type
  attribute`, `Permission(s) do not exist in any class: ...`); they are
  reproduced because scripts match on them, and a tool that reported something
  else for a missing type would not be a drop-in replacement.
- The *prose* is original: the option table, help texts and usage-error sentences
  in `cmd/sesearch/args.go`, the README, `NOTICE.md` and every code comment were
  written for this project. The flag names, metavariables, argument groups and
  layout follow the reference CLI because they are its interface; the wording
  does not. (The fragments argparse itself produces for a parse failure -
  `unrecognized arguments:`,
  `expected one argument`, `ambiguous option:` - come from Python's argparse and
  are kept because they are the conventional format.)
- No setools source file is redistributed here, and none of its Python or
  Cython code was translated.
- The command line tables, the report and section layouts, the stats block and
  the check modules of `sechecker` follow the reference tools' interfaces the
  same way: the flags, section titles and item formats match because scripts
  and muscle memory depend on them, while the help texts and comments are this
  project's own.

## The permission map data

`perm_map.txt` is the standard SELinux permission map: the table of object
class permissions with their information flow directions and weights. It is
the map shipped with setools/apol (GPL-2.0-only) and is included here as
*data* so that `seinfoflow`'s default analysis produces the same results as
the reference. Its provenance is recorded here for the same reason as the
format facts above: the weights and directions are data the tool's behaviour
is defined against, not code.

## Graphical output

`sedta -o` and `seinfoflow -o` write a PNG of the result graph by invoking
graphviz' `dot`, which is also what the reference tool requires (through
pygraphviz). Graphviz is not distributed with this project.

## Test data

Everything under `testdata/` and `policy/testdata/` is written for this project:
the policy sources (`*/src/*.conf`) are hand written, the compiled fixtures are
built from them by the checked-in generator scripts, and the golden files in
`testdata/expected/` are recordings of the reference tools' **output** for
queries over *our own* policy sources.

`testdata/expected/README.md` documents which reference build produced which
golden file and how it was obtained. Recording a program's output does not make
this project a redistribution of that program: no setools file, binary or source
is included in this repository or in its release artifacts, and the scripts that
produce the goldens download/build nothing - they use a locally installed
reference tool, or none at all (`testdata/gen.sh` and
`policy/testdata/gen.sh` are pure `checkpolicy` invocations).

The policy sources necessarily share the policy language's primitives with any
other policy (`class file`, `sid kernel`, `sensitivity s0;`, permission names
such as `read`/`write`/`ioctl`). That is the vocabulary of the language, not
copied content.

## Dependencies

The module has no Go dependencies outside the standard library, so the built
binaries contain no third-party Go code. Building the *fixtures* needs
`checkpolicy` from the SELinux userspace (GPL-2.0-only); that is a build-time
tool which is not distributed with this project.
