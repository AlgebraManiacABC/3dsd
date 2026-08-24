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
- Optional: [objdiff](https://github.com/encounter/objdiff) for a per-function
  diff GUI; if `objdiff-cli` is on PATH its report is included in progress
  output

## Project layout

```
myproject/
├── orig/           original binaries (code.bin, *.cro, exheader)
├── symbols/        one CSV per binary: code.bin.csv, ModuleX.cro.csv ...
├── src/
│   └── code.bin/   sources for that binary (any folder structure below)
├── tools/          ld, objcopy
└── cc.yaml         compiler configuration
```

Symbol CSVs have the header `Location,Name,Mode,Size,Segment`, e.g.
`00100000,Entry,$a,00000002,".text"` (`$a` = ARM, `$t` = Thumb; hex sizes).

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
     ```

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

Use `--split_sections` in your flags — it is what enables multiple functions
per source file.

### cc.yaml reference

| Key | Scope | Description |
|-----|-------|-------------|
| `compilers:` | top-level | Map of compiler names to install paths |
| `default:` | top-level | Fallback `{cc, flags}` for any file without a specific rule |
| `presets:` | top-level | Named `{cc, flags}` bundles reusable across binaries |
| `<binary>:` | top-level | Per-binary overrides (key = binary filename, e.g. `code.bin`) |
| `ignored:` | per-binary | List of glob patterns for source files to skip |
| `presets:` | per-binary | Map of preset name to list of files/globs that use it |
| `<filename>:` | per-binary | Direct `{cc, flags}` for one source file |
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

(`3dsd` starts with a digit, so there is no `import 3dsd` / pip script — always
invoke it as `python -m 3dsd`.)

## Writing sources

- One function per file: name the file after the symbol
  (`FUN_00123456.c`, `_Z9ActNpCharP6NpChar.cpp`).
- **Multiple functions per file**: any filename works — the pipeline compiles
  the file once and discovers which symbols it defines from its
  `--split_sections` output, then compares each function independently.
- A function counts as *matching* only if its bytes equal the original exactly,
  with relocation sites verified against the symbol CSV where the target
  address is known (and masked out where it isn't — data globals, library
  calls, unnamed functions).

## Progress output

```
code.bin: 27,964 / 495,616 bytes (5.6423%)          ← exact-matched bytes (primary)
          functions: 83 / 1,571 (5.28%), 104 with source
          fuzzy: 34,609 bytes (6.9830%), 21 in progress (avg 56.4%)
```

Byte percentages are measured against the whole binary. *Fuzzy* adds partial
credit for in-progress functions (masked byte ratio). Open the project in the
objdiff GUI (`objdiff.json` is generated for you) for instruction-level diffs
of any function.
