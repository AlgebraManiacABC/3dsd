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
 * Code is folded into .text so it pairs. Data deliberately is NOT: it keeps
 * armcc's own `.constdata` name and an invented `.rwdata`, neither of which
 * the target ELF ever has. objdiff's data diff cost grows far faster than
 * linearly with section size -- pairing New Leaf's 1.13 MB .rodata takes
 * `3dsd progress` from 15 seconds to over 45 minutes. Data is still carried
 * through, because .text relocations refer to these symbols and objdiff needs
 * them to name what a load is reading.
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
  .constdata 0 :
  {
    INPUT_SECTION_FLAGS (!SHF_WRITE & !SHF_EXECINSTR) *(i.* t.*)
    *(.constdata* .conststring* .rodata*)
  }
  .rwdata 0 :
  {
    INPUT_SECTION_FLAGS (SHF_WRITE) *(i.* t.*)
    *(.data* .bss* .zi*)
  }
  /DISCARD/ :
  {
    *(.debug*) *(.ARM.exidx*) *(.ARM.extab*)
    *(.comment) *(.arm_vfe*) *(.ARM.attributes)
  }
}
