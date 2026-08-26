# Multiple functions per source file

Notes from making the pipeline handle real translation units — a `.c` or `.cpp`
file holding many functions — instead of only one-function-per-file with the
file named after the symbol.

## What was actually broken

`--split_sections` was never the problem. armcc splits a multi-function file
exactly as advertised, and the pipeline's own comparison already handled the
result correctly. Compiling New Leaf's `src/code.bin/Item/Item.c` (14
functions) and comparing each `i.Item_*` section against its split object gives
**the same verdict, function by function, as compiling the 14 one-function
files separately**:

```
Item_Clear                       mono=False ind=False
Item_Copy                        mono=True  ind=True
Item_CopyAndReturn               mono=True  ind=True
Item_GetID                       mono=False ind=False
Item_GetModelName                mono=False ind=False
Item_GetPrice                    mono=True  ind=True
Item_GetRawID                    mono=True  ind=True
Item_GetTopBitOf2                mono=True  ind=True
Item_IsFromGracieGrace           mono=True  ind=True
Item_IsFromWishyOrSpotlight      mono=True  ind=True
Item_IsID                        mono=True  ind=True
Item_IsNullItem                  mono=True  ind=True
Item_IsValidID                   mono=False ind=False
Item_Param11Valid                mono=True  ind=True
```

(The four `False`s are the literal-pool issue described at the bottom — they
fail in both layouts, for a reason unrelated to file layout.)

What was broken was everything *around* the comparison. Five separate defects,
each of which only bites once a file holds more than one function.

### 1. Section discovery compiled in the wrong directory

`ProjectConfig.get_source_map` pre-compiles a source to read its `i.NAME`
sections. It ran `subprocess.run(cmd)` with no `cwd`, so it inherited whatever
directory the pipeline was invoked from. Ninja's `compile` rule runs from the
project working directory, so a flag like `-Iinclude` resolves there — but
discovery did not, and every multi-function file failed to compile with
`cannot open source input file "png.h"`. Files claimed by name never went
through discovery, so nothing else in the pipeline noticed.

Fixed: `compile_source` takes a `cwd`, and discovery passes the project
working directory.

### 2. A file named after one of its functions was never scanned

Discovery only ran on sources whose stem did *not* match a symbol. So
`inflate.c` — a real translation unit that happens to contain `inflate` —
claimed exactly one symbol and its other functions (`inflateEnd`,
`inflateReset`) were silently dropped. Naming a monolithic file after any
function inside it disabled discovery for the whole file.

Fixed: every source is compiled and scanned. To keep the old precedence, a file
whose name *is* a symbol still owns that symbol; only afterwards are the
remaining discovered sections handed out. Adding `Item.c` next to the existing
`Item_Clear.c` therefore cannot take `Item_Clear` away from it, and the overlap
is reported:

```
Warning: Item_Clear is defined by both Item/Item_Clear.c and Item/Item.c; keeping Item/Item_Clear.c.
```

Scanning everything costs one compile per source, parallelised and cached in
`build/`. On New Leaf (1,861 sources) a cold `3dsd ninja` takes ~18 s.

### 3. Sources were keyed by stem, so paths collided

`{s.stem: s for s in sources}` meant `zlib/util.c` and `png/util.c` were one
entry, and `foo.c` and `foo.cpp` in the same folder shared the object file
`build/<bin>/foo.o`. Per-file `cc.yaml` rules were keyed on the bare file name
with the same consequence.

Fixed: a source is identified by its path relative to `src/<binary>/`, and its
object mirrors that path — `src/code.bin/Item/Item.c` builds to
`build/code.bin/Item/Item.c.o`. `cc.yaml` glob expansion keys on the relative
path too; a bare file name still resolves, as a fallback, so existing configs
keep working.

### 4. The objdiff base ELF kept armcc's split sections

This is the one that actually produced the "doesn't match through objdiff"
symptom, and it is a hard failure rather than a subtle one.

`out/objdiff_base/<binary>` is a relocatable ELF made by `ld -r` over every
compiled object. objdiff pairs base and target **by section name**, and the
target ELF only ever has `.text` / `.rodata` / `.data` / `.bss`. With
`--split_sections`, `ld -r` preserves armcc's per-symbol sections, so the base
ended up with hundreds of sections called `i.png_sig_cmp`, `i.huft_build`, …
and **not one** of them paired with the target. objdiff read the file happily
and reported 0 matched functions out of 2,975.

New Leaf never hit this only because almost all of its sources compile without
`--split_sections`, leaving a single `.text` per object for `ld -r` to merge.

Fixed with `3dsd/base.ld`, a linker script used only for the base ELF, which
folds the split **code** sections into `.text`. Routing is by section flags
rather than by name, because armcc gives *data* objects `i.NAME` sections too —
`i.png_sig_cmp` is code (`AX`) while `i.png_libpng_ver` is data (`WA`), and
only the flags separate them:

```
.text 0 : { INPUT_SECTION_FLAGS (SHF_EXECINSTR) *(i.* .text*) }
```

`--force-group-allocation` additionally dissolves the COMDAT groups armcc puts
its `__ARM_common_*` helpers in; binutils older than 2.36 does not have the
option, so the link is retried without it.

**Data is deliberately left unpaired.** The first version of this script also
folded read-only data into `.rodata`, which the target ELF does have — and that
made `3dsd progress` on New Leaf go from **16 seconds to over 45 minutes**,
measured. objdiff's data diff cost grows far faster than linearly with section
size, and New Leaf's target `.rodata` is 1.13 MB, most of it synthetic `pad_*`
symbols. So read-only data keeps armcc's own `.constdata` name and writable
data gets an invented `.rwdata`; neither exists in the target, so objdiff skips
both, exactly as it did before this change. Data is still carried through the
link because `.text` relocations point into it and objdiff needs those symbols
to name what a load is reading. Making data actually count would be a real
improvement, but it needs the objdiff side to get faster first.

### 5. objdiff rejects armcc's R_ARM_NONE marker relocations

armcc emits `R_ARM_NONE` entries at offset 0 to pin down which printf variant a
function needs (`_printf_percent`, `_printf_s`, `_printf_str`). objdiff-cli
refuses relocation type 0 outright:

```
objdiff-cli failed: Unsupported ARM implicit relocation 0
```

and gives up on the entire unit — so a single decompiled function that calls
`printf` would zero out the whole binary's reported progress. This is not
specific to multi-function files; New Leaf simply has no matched function that
calls printf yet.

Fixed: after linking the base ELF, `strip_none_relocs` drops every type-0
entry. Kept entries are packed to the front of each `REL` section and the
section size is shrunk, so nothing in the file moves and no offset needs
rewriting.

Both steps now run inside `3dsd link-base`, which replaces the raw `ld -r`
command in the `link_base` ninja rule.

## Measured result

The Ikachan test project is, in its shipped form, ~24 real translation units
each copied out 3–12 times under different one-function file names — 104 files
that are really 27. That layout makes `ld -r` fail outright with hundreds of
`multiple definition` errors, so no base ELF is produced at all and objdiff
reports nothing.

Consolidating those 104 files back into their 27 real translation units, with
the fixes above:

| | 104 one-function files | 27 real translation units |
|---|---|---|
| compile rules | 104 | 27 |
| symbols claimed | 104 | 104 |
| objdiff base ELF | **fails to link** | links |
| objdiff progress | *no report* | 1.52 % code, 30 / 2,975 functions |
| pipeline exact matches | 83 | **84** |
| `3dsd check` | pass | pass |

The consolidated layout matches one function *more* — `inflateEnd`, which the
one-function-per-file layout could never claim (defect 2). Nothing regressed.

On New Leaf, regenerating `build.ninja` produces the identical 1,859 compare
and compile rules as before the change, and a full rebuild reports numbers that
are identical to the digit — 30,358 matched code bytes, 1,569 matched
functions, 0.47536927 % fuzzy — with **not one function's** `fuzzy_match_percent`
changed anywhere in the binary.

### Item.c as the only source for its 14 functions

Deleting the 14 `src/code.bin/Item/Item_*.c` files and leaving only `Item.c`
still produces 1,859 compare rules — `Item.c` alone claims every symbol the 14
files used to. Thirteen of the fourteen report exactly as before.

The fourteenth, `Item_GetModelName`, does change — and for a reason that is
worth knowing:

```
; from Item_GetModelName.c (Item_GetID declared extern)
push  {r4, lr}
bl    Item_GetID
...

; from Item.c (Item_GetID visible in the same translation unit)
ldrh  r0, [r0]
bic   r0, r0, #0x8000       <- Item_GetID inlined, no call at all
sub   r2, r0, #0x2000
```

At `-O3` armcc inlines a call whose callee is in the same translation unit. The
original binary makes a real `bl`, so the monolithic build produces genuinely
different — non-matching — code. This is compiler semantics, not a pipeline
defect, and it is fixable in the source: marking the callee
`__declspec(noinline)` brings the call back and the function to within a
register of matching.

```
push  {lr}
bl    Item_GetID
cmn   r0, #1
...
```

(only the prologue differs from the original's `push {r4, lr}`).

This cuts both ways and is the whole reason real decompilations need real
translation units: same-TU visibility changes inlining, literal-pool sharing
and section ordering. Sometimes that is what finally makes a function match;
here it is what breaks one.

One loose end: objdiff reports the mismatched `Item_GetModelName` as having no
base symbol at all rather than as a low fuzzy percentage, even though the
symbol is present in the base ELF. Base symbols that are *larger* than their
target counterpart do normally pair (Ikachan has such a case at 100 %), so the
reason objdiff drops this particular one is unresolved. It makes no practical
difference — unpaired and 40 % both mean "not done".

## Known limitations, not addressed here

**Literal pools fall outside symbol sizes.** `Item_Clear` compiles to 24 bytes
— 20 of instructions plus a 4-byte `0x7ffe` literal — but the symbol CSV says
20, so `split/code.bin/Item_Clear.o` is cut at 20 and the exact compare fails.
The literal really does live at `Item_Clear+0x14` in the original; Ghidra just
does not count it as part of the function. This affects 4 of the 14 New Leaf
`Item` functions and is independent of file layout. objdiff is unaffected — it
diffs instructions over the target symbol's extent and reports these as 100 %.

**objdiff's data diff is too slow to switch on.** See defect 4 — pairing a
megabyte-scale `.rodata` costs 45 minutes rather than 16 seconds. Worth
reporting upstream; until then the base ELF stays code-only in effect.

**C++ symbol names have to be mangled in the CSV.** armcc emits
`_ZN14AcInsectCommon3F17Ev`; Ghidra exports `AcInsectCommon::F17`. Nothing
bridges the two, so a C++ file whose CSV entries are demangled claims no
symbols at all. `3dsd ninja` now names the files this happens to and says why.
Teaching the pipeline to demangle would close the gap for simple methods, but
Ghidra's spelling is not a standard demangler's — it drops parameter lists
except where it needs them to disambiguate overloads — so it would be a
guess-and-check mapping rather than a conversion.

**`.s` / `.S` sources need `armasm` on PATH.** `_gather_sources` accepts them
and armcc dispatches to `armasm`, which is not resolved through the
`compilers:` install root.

**Duplicate global symbols still break the base link.** If two translation
units genuinely define the same global, `ld -r` fails and no base ELF is
produced. `3dsd objdiff` now warns when the base ELF is missing instead of
silently reporting 0 %, but the underlying conflict is a real error in the
sources and is left to the user to resolve.
