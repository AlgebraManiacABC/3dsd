# 3dsd — 3DS Decompilation Pipeline

A build pipeline for matching decompilations of 3DS binaries (`code.bin` and
`.cro` modules). It splits the original binary into per-function objects,
compiles your decompiled sources with the original ARM compiler, compares the
results byte-for-byte (relocation-aware), and reports progress. The rebuilt
binary is **always byte-perfect** — unmatched or in-progress code falls back to
the original bytes automatically.

ALL work done in Claude Code using Opus 4.6 and Fable 5 models.

## Requirements

- Python 3.10+ with `pip install pyyaml ninja`
- The ARM compiler (armcc) the game was built with — **not bundled**; point
  `cc.yaml` at your install (see below)
- GNU `ld` and `objcopy` for ARM in the project's `tools/` directory
  (binutils 2.36+ preferred: `ld --force-group-allocation` tidies up the
  objdiff base ELF, and is skipped when unsupported)
- Optional: [objdiff](https://github.com/encounter/objdiff) for a per-function
  diff GUI; if `objdiff-cli` is on PATH or in the project's `tools/` directory,
  its report is included in progress output

## Project layout

```
myproject/
├── orig/           original binaries (code.bin, *.cro, exheader)
├── symbols/        one CSV per binary: code.bin.csv, ModuleX.cro.csv ...
├── src/
│   └── code.bin/   sources for that binary (any folder structure below)
├── deps/           referenced external source trees, one directory each
├── tools/          ld, objcopy (optionally objdiff-cli, armcc installs)
└── cc.yaml         compiler configuration
```

Everything else is generated and safe to delete (see `clean` below):

```
├── build/          compiled translation units, mirroring src/ (Item/Item.c.o)
├── split/          per-symbol .o carved out of the original binary
├── link/           compared objects, plus <bin>_linked and its .map
├── out/            recreated binaries, plus objdiff_base/ and objdiff_target/
├── build.ninja     generated build graph
└── objdiff.json    generated objdiff project
```

Symbol CSVs have the header `Location,Name,Mode,Size,Segment`, e.g.
`00100000,Entry,$a,00000002,".text"` (`$a` = ARM, `$t` = Thumb; hex sizes).

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

Use `--split_sections` in your flags for any file holding more than one
function — it is what lets the pipeline see the individual functions. Without
it armcc emits a single `.text`, and the file can only stand for the one symbol
it is named after.

## Referencing external dependencies

3DS games share libraries -- `nw4c`, `nnsdk`, zlib, libpng -- and some of them
are decompilation projects in their own right. Rather than copying that code
into `src/`, point at it: put it under `deps/<name>` (a git submodule is the
natural way, and pins a revision for free) and describe it in `cc.yaml`.

Nothing is assumed about the dependency's own layout. It is treated as an
inert directory of files, and *everything* about how to build it is declared by
your project -- which is what lets an arbitrary upstream repo be used
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

A dependency entry accepts everything a binary entry does -- `ignored:`,
`presets:`, wildcards and per-file `{cc, flags}` overrides -- and falls back to
`default:` like anything else. The only difference is that its paths are
relative to the dependency root instead of `src/<binary>/`.

- `sources:` is required. Use `[]` for a headers-only reference; nothing is
  inferred from the dependency's layout.
- `include:` directories are added as `-I` to **every** source compiled for a
  binary that declares the dependency, so your own code can include its
  headers, and one dependency can include another's.
- Dependency files are compiled as ordinary translation units and compared
  per-function, exactly like your own sources, and count toward the binary's
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
standard headers. armcc does not locate its own `include` directory -- the
`-I` is what makes `<string.h>` resolve -- and the pipeline can only add it
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
is normally a submodule, but a vendored toolchain -- a compiler and its
standard headers -- is licensed material that must not be committed. Ignore
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
empty -- the usual uninitialised-submodule case -- it says so and names the fix.

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

One command does everything: splits the originals (first run only), generates
`build.ninja` and `objdiff.json`, compiles, compares, links a byte-perfect
binary into `out/`, and prints progress. Other commands:

| command | purpose |
|---|---|
| `python -m 3dsd progress .` | progress report without building |
| `python -m 3dsd check .`    | verify `out/` binaries match `orig/` |
| `python -m 3dsd split .`    | (re)split originals into `split/` |
| `python -m 3dsd ninja .`    | regenerate `build.ninja` only |
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
file once, reads the `i.NAME` sections `--split_sections` produced, and
compares every function it finds against the original independently.

- **One function per file**: name the file after the symbol
  (`FUN_00123456.c`, `_Z9ActNpCharP6NpChar.cpp`). No `--split_sections` needed.
- **C++ templates**: instantiations land in `t.NAME` sections rather than
  `i.NAME`, and are discovered the same way -- a C++ file is usually mostly
  these.
- **Many functions per file**: any filename works, including a name that
  happens to be one of the functions inside (`inflate.c` holding `inflate`,
  `inflateEnd` and `inflateReset`). Needs `--split_sections`.
- **C++**: symbols are matched under their mangled names, which is what the
  symbol CSV holds, so nothing is needed beyond the right compiler flags.
- Files are identified by their path under `src/<binary>/`, so `zlib/util.c`
  and `png/util.c` are distinct, as are `foo.c` and `foo.cpp`.
- If two files define the same symbol, the file *named* after it wins; failing
  that, the first in path order does, and the overlap is reported. Two files
  defining the same **global** symbol will still break the objdiff base link —
  that is a genuine conflict in the sources, not something to paper over.
- A function's **literal pool** is compared with it. armcc keeps the pool at the
  end of the function's own section, while a symbol's size covers only its
  instructions -- so the compiled form is often a few bytes longer. Rather than
  asking you to overstate the size in Ghidra (the pool is data, not code), the
  comparison widens to cover the trailing padding and pool, but never past the
  next symbol. Widening only ever makes a comparison stricter, so it cannot
  invent a match, and the linked output is untouched.
- A function counts as *matching* only if its bytes equal the original exactly,
  with relocation sites verified against the symbol CSV where the target
  address is known (and masked out where it isn't — data globals, library
  calls, unnamed functions).

`3dsd ninja` compiles every source once to do this discovery (in parallel,
cached in `build/`); on an 1,800-file project that is around 20 seconds cold
and nothing at all once the objects are there.

See [docs/multi-function-sources.md](docs/multi-function-sources.md) for how
the objdiff base ELF is assembled and why it needs its own linker script.

## Progress output

One row per binary, plus a `Total` row when there is more than one:

```
  Binary        |          Code bytes |  Code % | Fuzzy % | Functions 100% | Func % | Data bytes |         Total bytes | Total %
  --------------+---------------------+---------+---------+----------------+--------+------------+---------------------+--------
  ModuleFtr.cro |      0 /    179,968 | 0.0000% | 0.0000% |     0 /    236 |  0.00% |          - |      0 /    179,968 | 0.0000%
  code.bin      | 30,358 /  7,574,364 | 0.4008% | 0.4754% | 1,569 / 53,330 |  2.94% |  1,350,820 | 30,358 /  8,925,184 | 0.3401%
  --------------+---------------------+---------+---------+----------------+--------+------------+---------------------+--------
  Total         | 30,358 / 12,047,532 | 0.2520% | 0.2989% | 1,569 / 55,921 |  2.81% |  1,350,820 | 30,358 / 13,398,352 | 0.2266%
```

The table is about 135 columns wide with long binary names. Numerators and
denominators are sized independently, so the `/` separators line up down each
column no matter how the magnitudes differ.

Values that move during a decomp — matched byte counts, matched function
counts, and every percentage — are coloured on a red → yellow → green scale by
how complete they are. Fixed denominators are left uncoloured. Exactly zero is
dimmed to a darker red, so a binary nobody has started is distinguishable from
one just underway; early in a decomp the gradient alone is far too shallow to
separate them. Colour is emitted only when stdout is a terminal, and is
disabled by setting `NO_COLOR`, so redirected or piped output stays plain.

**Code %** is measured against the binary's **code**, not its total size — the
denominator is objdiff's `total_code`, which excludes the bytes in the *Data
bytes* column. For the `code.bin` row that is 7,574,364 of 8,925,184, so the
same match reads as 0.4008% of code but 0.3401% of the file.

**Total bytes** spans code + data, and is the closest thing to whole-binary
completion. Its numerator counts matched data only when objdiff reports one,
so while data is untracked it equals the code numerator and the percentage is
a *floor*.

**Fuzzy %** adds partial credit for in-progress functions (masked byte ratio),
so it is always ≥ *Code %*. **Func %** counts only functions matching 100%,
and is a fraction of the function *count* — not of bytes, so it moves at a
different rate than *Code %*.

The *data* line reports only the size when objdiff returns no `matched_data`
figure, which is the normal case for whole-binary units: objdiff matches data
at the section level, and a unit spanning the entire binary gives it nothing
to compare. If objdiff does report matched data, the line shows the full
`matched / total (percent)` form instead. Code matching is unaffected — it is
symbol-based and works regardless.

Progress is computed by `objdiff-cli`, which is looked up on `PATH` and then in
the project's `tools/` directory; without it the rest of the build still runs.
Open the project in the objdiff GUI (`objdiff.json` is generated for you) for
instruction-level diffs of any function.
