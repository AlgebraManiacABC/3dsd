/* Linker script for the objdiff base ELF (ld -r).
 *
 * armcc --split_sections gives every function AND every data object its own
 * `i.NAME` section, and every template instantiation a `t.NAME` one. objdiff
 * pairs base and target sections by name, and the target ELF only ever has
 * .text/.rodata/.data/.bss, so without this script a split build produces a
 * base full of `i.png_sig_cmp`-style sections that pair with nothing at all
 * and report 0%.
 *
 * Routing is by section flags, not by name: `i.png_sig_cmp` is code (AX) but
 * `i.png_libpng_ver` is data (WA), and only the flags tell them apart.
 *
 * Code is folded into .text so it pairs. Read-only data is folded into .rodata
 * so it pairs too -- but only because the target side is trimmed to match. The
 * cost of a data diff is quadratic in section length (measured: 0.3 s at 8 KB,
 * 51 s at 128 KB, 210 s at 256 KB), so pairing New Leaf's whole 1.13 MB
 * .rodata would take over an hour. `generate_target_elfs` keeps that from
 * happening by routing every data symbol the project has not actually
 * decompiled into a `.rodata.undecompiled` section, which nothing here emits
 * and objdiff therefore never pairs or diffs.
 *
 * Writable data goes to .data on the same terms. Most decompiled data is
 * writable rather than const -- on ikachan 90 of 110 objects, including the
 * game's own rcNpc tables -- so leaving it unpairable would have hidden nearly
 * all of it. Zero-initialised data stays in the invented `.rwdata`: it has no
 * bytes to compare, and pairing it would only add length to a quadratic diff.
 * It is carried through regardless, because .text relocations refer to these
 * symbols and objdiff needs them to name what a load is reading.
 *
 * Debug and unwind data is dropped; it would only add sections the target
 * cannot pair with.
 */
SECTIONS
{
  .text 0 :
  {
    INPUT_SECTION_FLAGS (SHF_EXECINSTR) *(i.* t.* .text*)
  }
  .rodata 0 :
  {
    INPUT_SECTION_FLAGS (!SHF_WRITE & !SHF_EXECINSTR) *(i.* t.*)
    *(.constdata* .conststring* .rodata*)
  }
  .data 0 :
  {
    INPUT_SECTION_FLAGS (SHF_WRITE) *(i.* t.*)
    *(.data*)
  }
  .rwdata 0 :
  {
    *(.bss* .zi*)
  }
  /DISCARD/ :
  {
    *(.debug*) *(.ARM.exidx*) *(.ARM.extab*)
    *(.comment) *(.arm_vfe*) *(.ARM.attributes)
  }
}
