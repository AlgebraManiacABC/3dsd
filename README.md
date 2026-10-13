# 3dsd — 3DS Decompilation Pipeline

A build pipeline for matching decompilations of 3DS binaries (`code.bin` and
`.cro` modules). It compiles your decompiled sources with the original ARM
compiler, finds every function and data object they define, and measures them
against the original binary with [objdiff](https://github.com/encounter/objdiff)
to report progress. With `--roundtrip` it also splits the original into
per-symbol objects and relinks them, checking that the pipeline reproduces the
binary byte for byte.

ALL work done in Claude Code using Opus 4.6 and Fable 5 models.

## Requirements

- Python 3.10+ with `pip install pyyaml ninja`
- The ARM compiler (armcc) the game was built with — **not bundled**; point
  `cc.yaml` at your install (see below)
- GNU `ld` and `objcopy` for ARM in the project's `tools/` directory
  (binutils 2.36+ preferred: `ld --force-group-allocation` tidies up the
  objdiff base ELF, and is skipped when unsupported)
- `objdiff-cli`, on PATH or in the project's `tools/` directory, for the
  progress figures. Everything else runs without it. The objdiff GUI is
  optional, for per-function diffs.

## Project layout

```
myproject/
├── orig/           original binaries (code.bin, *.cro, exheader)
├── symbols/        one CSV per binary: code.bin.csv, ModuleX.cro.csv ...
├── src/
│   └── code.bin/   sources for that binary (any folder structure below)
├── include/        optional; added as -Iinclude to every source
├── deps/           referenced external source trees, one directory each
├── tools/          ld, objcopy (optionally objdiff-cli, armcc installs)
└── cc.yaml         compiler configuration
```

Everything else is generated and safe to delete (see `clean` below):

```
├── build/          compiled translation units, mirroring src/ (code.bin/Item/Item.c.o)
├── split/          per-symbol .o carved out of the original binary (--roundtrip)
├── link/           <bin>_linked and its .map (--roundtrip)
├── out/            objdiff_base/, objdiff_target/, report.json, recreated binaries
├── build.ninja     generated build graph
└── objdiff.json    generated objdiff project
```

A top-level `include/` directory, if present, is added as `-Iinclude` to every
source in the project, ahead of any dependency or toolchain headers. Reconstructed
types belong there and are reachable as `#include "types.h"` from any depth,
rather than each file counting directories back to them. Nothing breaks if you
already list it in `flags:` — it is not added twice — and a project without the
directory is unaffected.

Symbol CSVs have the header `Location,Name,Mode,Size,Segment`, e.g.
`00100000,Entry,$a,00000002,".text"` (`$a` = ARM, `$t` = Thumb, `$d` = data;
hex sizes).

Every byte the CSV leaves unnamed has to be guessed at, and the pipeline does
not guess: a gap becomes an unnamed `pad_` symbol, which in `.text` objdiff
counts as an unmatched function. The commonest gap is a function's literal
pool, which armcc places right after the function's last instruction, outside
its symbol. Each build lists the gaps, those right after a decompiled
function first. Label them in the CSV: a `$d` entry in `.text` is measured as
data, not code. Every `$d` label between a decompiled function and the next
code symbol belongs to that function's pool, gaps between them included, and
the pool is compared with the one armcc emitted (cut at armcc's own `$d`
mapping symbols), so a wrong constant or address shows in the data figures.
Any other `$d` label goes with the undecompiled data.

Rows named exactly `$a`, `$t` or `$d` are **mapping rows**, as ELF names its
mapping symbols: they name nothing, they mark what kind of bytes begin there.
A function row runs from its entry to its last instruction, exactly as
armcc's own symbol does, and mapping rows inside it mark its mid-function
literal pools and the code after them:

```
"00101000","foo","Global",$t,00000058,".text"   <- foo, entry to last instruction
"00101020","$d","Global",$d,00000008,".text"    <- a pool inside foo
"00101028","$t","Global",$t,00000030,".text"    <- foo's code resumes
"00101058","$d","Global",$d,00000008,".text"    <- foo's trailing pool, outside it
```

A mapping row runs until the next one or the end of the symbol it sits in;
its Size is only checked against that, and a disagreement is reported. A `$d`
row outside every symbol is unnamed data: right after a decompiled function
it is that function's trailing pool, as above. Mapping rows are exempt from
the unique-name check.

Pools are data wherever they sit. A decompiled function whose pools are
marked is cut in two on both sides: its code ranges, laid end to end, become
`.text:<function>`, compared instruction for instruction, and its pools --
the ones in its middle and the one after it -- become `.pool:<function>`,
compared word for word. The compiled side is cut at armcc's own mapping
symbols. A decompiled function whose compiled version holds a pool the CSV
does not mark is reported, and is compared whole -- pool words and all --
until the rows are added, so it cannot reach 100% before then.

Put the title's `exheader.bin` in `orig/` too. It records where `code.bin`'s
`.text`, `.rodata` and `.data` really begin and end, and when it is present
each symbol's segment is taken from its address rather than the `Segment`
column, with a warning listing any labels that disagree. That matters for
`--roundtrip`: the linker gathers all `.rodata` before all `.data`, so one
mislabelled object is moved out of address order and the verify fails.
Progress does not depend on the labels.

An optional `Namespace` column may follow `Name`
(`Location,Name,Namespace,Mode,Size,Segment`). Anything whose namespace is
`std` or starts with `std::` is treated as C++ standard library code linked in
from a `.a` rather than written by the original developers: its bytes are
written into the objdiff target but left without a symbol, so they drop out of
`total_code` and the function count and no longer weigh down the completion
percentage. The split and the relink are unaffected — the final binary is
still byte-perfect. Note that objdiff measures data by section size, so
discounting only moves the code figures; `std` entries in `.rodata` still show
up in the data total.

## Compiler & tools setup

The pipeline needs two things in addition to your sources and symbols:

1. **`tools/`** — GNU binutils for ARM (`ld` and `objcopy`). These are the
   standard `arm-none-eabi-` binutils from [devkitPro](https://devkitpro.org/)
   or any ARM GCC toolchain. Copy or symlink the executables into `tools/`:

   ```
   tools/
   ├── ld           (or ld.exe)
   └── objcopy      (or objcopy.exe)
   ```

2. **armcc** — the ARM Compiler that the game was originally built with. The
   pipeline does **not** bundle it. You need the exact version that matches the
   original binary (different builds produce different code). Each compiler
   install is a directory containing `bin/armcc` and `include/`.

   Point `cc.yaml` at your install(s) in one of two ways:

   - **Named in `compilers:`** (recommended) — map a version-tagged name to
     the install root. The name format `armcc_<version>_<build>` is verified
     at runtime against `armcc --vsn`:

     ```yaml
     compilers:
       armcc_4.1_1049: C:/armcc_4.1_b1049
       armcc_5.0_169:  /opt/armcc/5.0/b169
       armcc_4.1_894:  deps/armstd_4.1_894    # relative to the project
     ```

     A relative path is resolved against the project directory, not the
     directory the command is run from, so vendoring a toolchain under `deps/`
     keeps `cc.yaml` free of machine-specific absolute paths.

   - **Placed in `tools/`** — drop the install directory (or a symlink) in
     `tools/` and reference it by directory name:

     ```yaml
     default:
       cc: armcc_4.1_1049      # looks for tools/armcc_4.1_1049
     ```

   The compiler's own `include/` directory is appended to the flags
   automatically (`-I<install>/include`).

## cc.yaml

```yaml
compilers:
  armcc_4.1_1049: C:/armcc_4.1_b1049

default:
  cc: armcc_4.1_1049
  flags: []

presets:
  thumb: {cc: armcc_4.1_1049, flags: [--thumb]}

code.bin:
  ignored: [wip/*]
  presets:
    thumb: [FUN_00100794.c]
  "*.cpp":
    cc: armcc_4.1_1049
    flags: [--cpu=MPCore, -O3, --split_sections, -Iinclude]
```

`--split_sections` is optional. Symbols are discovered from each object's
symbol table, which names every function and data object whether they share
one `.text` or sit in `i.NAME` sections of their own, so progress is measured
the same either way. Use it or not to match how the game was built.

## Referencing external dependencies

3DS games share libraries — `nw4c`, `nnsdk`, zlib, libpng — and some of them
are decompilation projects in their own right. Rather than copying that code
into `src/`, point at it: put it under `deps/<name>` (a git submodule is the
natural way, and pins a revision for free) and describe it in `cc.yaml`.

Nothing is assumed about the dependency's own layout. It is treated as an
inert directory of files, and *everything* about how to build it is declared by
your project — which is what lets an arbitrary upstream repo be used
unmodified.

```yaml
dependencies:
  libpng:
    sources: ["."]        # directories under deps/libpng to compile
    include: ["."]        # -I roots under deps/libpng
    "*.c":
      cc: armcc_4.1_894
      flags: [--cpu=MPCore, -O3, --split_sections]

code.bin:
  dependencies: [libpng]  # binaries declare what they consume
```

A dependency entry accepts everything a binary entry does — `ignored:`,
`presets:`, wildcards and per-file `{cc, flags}` overrides — and falls back to
`default:` like anything else. The only difference is that its paths are
relative to the dependency root instead of `src/<binary>/`.

- `sources:` is required. Use `[]` for a headers-only reference; nothing is
  inferred from the dependency's layout.
- `include:` directories are added as `-I` to **every** source compiled for a
  binary that declares the dependency, so your own code can include its
  headers, and one dependency can include another's.
- Dependency files are compiled as ordinary translation units and measured
  per symbol, exactly like your own sources, and count toward the binary's
  progress. A dependency serving several binaries is compiled once per binary.
- Your own sources always win: if a file under `src/` and a dependency file
  define the same symbol, `src/` claims it and the overlap is reported.
- A dependency usually defines far more than any one game uses. Files that
  claim nothing are skipped silently and never reach the build graph; instead
  one summary line is printed per dependency:

  ```
  libpng @a3f91c2: 53 of 198 discovered symbols are in symbols/code.bin.csv
  ```

A headers-only entry is also the way to give a bare `tools/` compiler its
standard headers. armcc does not locate its own `include` directory — the
`-I` is what makes `<string.h>` resolve — and the pipeline can only add it
automatically when cc.yaml names an install root under `compilers:`, or when
`tools/<name>` is a directory. When the compiler is a lone executable in
`tools/`, point a dependency at its headers instead:

```yaml
dependencies:
  armcc-headers:
    sources: []
    include: ["."]      # deps/armcc-headers -> the compiler's include dir

code.bin:
  dependencies: [armcc-headers]
```

**This only works if the binary's symbol CSV uses the dependency's symbol
names.** That code is already inside `code.bin` at real addresses; if the CSV
calls those addresses `FUN_0034a1c0`, a perfectly decompiled library will claim
nothing. That summary line is how you find out.

Not everything under `deps/` belongs in your repository. A decompiled library
is normally a submodule, but a vendored toolchain — a compiler and its
standard headers — is licensed material that must not be committed. Ignore
those, keeping the directory itself:

```gitignore
deps/armstd_4.1_894/*
!deps/armstd_4.1_894/.gitkeep
```

Git cannot track an empty directory, so the `.gitkeep` is what keeps it in the
tree. A directory holding nothing but dotfiles counts as empty, so a fresh
clone gets the same "uninitialised submodule" message as a missing one rather
than compiling on and failing later with `cannot open source input file
"stdio.h"`.

The pipeline never runs git commands that write. If `deps/<name>` is missing or
empty — the usual uninitialised-submodule case — it says so and names the fix.

### cc.yaml reference

| Key | Scope | Description |
|-----|-------|-------------|
| `compilers:` | top-level | Map of compiler names to install roots; relative paths resolve against the project |
| `default:` | top-level | Fallback `{cc, flags}` for any file without a specific rule |
| `presets:` | top-level | Named `{cc, flags}` bundles reusable across binaries |
| `dependencies:` | top-level | Map of dependency name to its build config; it lives at `deps/<name>` |
| `<binary>:` | top-level | Per-binary overrides (key = binary filename, e.g. `code.bin`) |
| `dependencies:` | per-binary | List of dependency names this binary consumes |
| `ignored:` | per-binary | List of glob patterns for source files to skip |
| `presets:` | per-binary | Map of preset name to list of files/globs that use it |
| `<filename>:` | per-binary | Direct `{cc, flags}` for one source file (path under `src/<binary>/`, or a bare file name) |
| `"<glob>":` | per-binary | Wildcard `{cc, flags}` applied to matching source files |

Rules are resolved in order: direct filename match > preset match > wildcard
match > `default`. The first match wins.

## Usage

```bash
python -m 3dsd build .
```

This generates `build.ninja` and `objdiff.json`, compiles every source, links
the objdiff base ELF, and prints progress. It does not touch `split/`: the
objdiff target is cut from the original binary and the symbol CSV, so decomp
progress never needs the originals taken apart.

```bash
python -m 3dsd build . --roundtrip
```

adds the byte-perfect rebuild — split every symbol, link the pieces back
together, and verify the result hashes identically to `orig/`. A mismatch
fails the build. Every object that link consumes holds original bytes, so it
confirms the pipeline agrees with itself (the split, the linker script, the
CRO rebuild) rather than measuring the decomp; progress is the same either
way. It is off by default
because it costs a split and a link of every symbol in every binary — for
ACNL's `code.bin` that is 74,384 objects and a link measured in minutes, versus
seconds for the progress path. Run it when the split, the linker script or the
CRO rebuild changed, and in CI. Other commands:

| command | purpose |
|---|---|
| `python -m 3dsd progress .` | progress report without building |
| `python -m 3dsd check .`    | verify `out/` binaries match `orig/` (needs `--roundtrip` first) |
| `python -m 3dsd split .`    | (re)split originals into `split/` |
| `python -m 3dsd ninja .`    | regenerate `build.ninja` only (`--roundtrip` for the full graph) |
| `python -m 3dsd objdiff .`  | regenerate `objdiff.json` only |
| `python -m 3dsd clean .`    | remove generated output |

(`3dsd` starts with a digit, so there is no `import 3dsd` / pip script — always
invoke it as `python -m 3dsd`.)

### clean

`clean` takes any number of targets — `build`, `split`, `link`, `out`, `ninja`
(`build.ninja` + ninja's logs), `objdiff` (`objdiff.json`), or `all`. With no
target it removes everything **except `split/`**, which is expensive to
regenerate. Use `-n` / `--dry-run` to list what would go without deleting.

```bash
python -m 3dsd clean . --dry-run
```

Because `clean` removes `build.ninja`, run `python -m 3dsd ninja .` (or any
`python -m 3dsd build .`) before invoking bare `ninja` again.

## Writing sources

Source layout is free. Put one function in a file named after it, put a whole
translation unit's worth in one file, use C or C++ — the pipeline compiles each
file once, reads the symbol table of the object, and claims every function and
data object it finds that the symbol CSV also names.

- **One function per file**: name the file after the symbol
  (`FUN_00123456.c`, `_Z9ActNpCharP6NpChar.cpp`).
- **Many functions per file**: any filename works, including a name that
  happens to be one of the functions inside (`inflate.c` holding `inflate`,
  `inflateEnd` and `inflateReset`).
- **C++**: symbols are matched under their mangled names, which is what the
  symbol CSV holds, so nothing is needed beyond the right compiler flags.
  Template instantiations are found like any other function.
- **Data**: a global the CSV names is claimed and measured like a function,
  in whichever of `.rodata` or `.data` the compiler put it.
- Files are identified by their path under `src/<binary>/`, so `zlib/util.c`
  and `png/util.c` are distinct, as are `foo.c` and `foo.cpp`.
- If two files define the same symbol, the file *named* after it wins; failing
  that, the first in path order does, and the overlap is reported. Vtables,
  RTTI records and template instantiations that every translation unit emits
  are folded silently, as the linker would. Two files with the same **strong**
  definition will still break the objdiff base link — that is a genuine
  conflict in the sources, not something to paper over.
- Keep a function's CSV size to its instructions. armcc places the literal
  pool after them inside the function's own section, so the compiled symbol is
  often a few bytes longer; objdiff diffs over the target symbol's extent and
  still scores such a function 100%.
- **Calls and addresses**: the objdiff target is cut from a linked binary, so
  every call and address load in it is already resolved, while the base's are
  relocations. For each symbol the base defines, the target gets the
  relocations its compiled twin implies: `bl`/`blx`/`b` and literal-pool
  words are found by a masked search, the address each reaches is named from
  the symbol CSV, and the bytes are put back in unlinked form. Without this
  no function that calls anything could reach 100%. Name callees and globals
  in the CSV as the compiler does, or the relocations will not pair. String
  literals and statics, which armcc refers to through their section, are
  matched by content instead. See `3dsd/reloc.py`.

`3dsd ninja` compiles every source once to do this discovery (in parallel,
cached in `build/`); on an 1,800-file project that is around 20 seconds cold
and nothing at all once the objects are there.

See [docs/multi-function-sources.md](docs/multi-function-sources.md) for how
the objdiff base ELF is assembled and why it needs its own linker script.

## Progress output

One row per binary, plus a `Total` row when there is more than one:

```
  Binary   |       Code bytes |  Code % | Fuzzy Code % |      Data bytes |  Data % | Fuzzy Data % | Total bytes | Total %
  ---------+------------------+---------+--------------+-----------------+---------+--------------+-------------+--------
  code.bin | 13,952 / 290,816 | 4.7975% |     13.1438% | 9,646 / 204,800 | 4.7100% |      4.7100% |     495,616 | 4.7613%
```

Code and data are measured separately, each against its own size, because
objdiff reports them that way:

- **Code bytes / Code %** — bytes in functions that match exactly, out of
  objdiff's `total_code`.
- **Fuzzy Code %** — partial credit for functions still in progress, so it is
  always ≥ *Code %*.
- **Data bytes / Data %** — matched data out of `total_data`. objdiff credits
  a data section only once it matches completely, so every decompiled object
  is given a section of its own (`.rodata:gEnts`, `.data:gTable`) in both the
  base and the target: each one that matches exactly counts, whatever the
  others do. These are not the original translation units, only a finer
  grain for the same measurement.
- **Fuzzy Data %** — how far along the data is: the size-weighted mean of
  objdiff's per-section fuzzy percentages, which objdiff does not total itself.
- **Total bytes / Total %** — code and data together, the closest thing to
  whole-binary completion.

Only data you have actually decompiled is paired and diffed. Everything else
is routed to a section the base never has, because objdiff's data diff is
quadratic in section length: pairing all of New Leaf's 1.13 MB `.rodata`
would take over an hour.

A `-` means an exact zero — a binary nobody has started, or a CRO with no data
section of its own. A value that merely rounds to `0.0000%` keeps its digits,
because it is real progress.

Values that move during a decomp are coloured on a red → yellow → green scale
by how complete they are; fixed denominators are left uncoloured. Exact zeros
are dimmed to a darker red, so an untouched binary stands out from one that is
barely underway. Colour is emitted only when stdout is a terminal, and setting
`NO_COLOR` turns it off, so redirected or piped output stays plain.

Progress is computed by `objdiff-cli`, which is looked up on `PATH` and then in
the project's `tools/` directory; without it the rest of the build still runs.
Its full report — per unit, per section and per symbol — is saved,
pretty-printed, to `out/report.json`. Open the project in the objdiff GUI
(`objdiff.json` is generated for you) for instruction-level diffs of any
function.

## Development

The package has no test suite yet; changes are checked by building a real
project before and after and comparing the outputs. Linting is configured in
`pyproject.toml`:

```bash
pip install ruff pylint
```

```bash
ruff check 3dsd
```

```bash
pylint 3dsd
```

Both are expected to pass cleanly. Problems with a project's own inputs — a
missing directory, a bad `cc.yaml` entry, a compiler that reports the wrong
version — are raised as `PipelineError` and printed as a one-line error
rather than a traceback.

