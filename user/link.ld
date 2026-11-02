/*
 * Every user program: a static ELF linked at 0x400000 (docs/design.md,
 * "Root-task image and address space"). Text, read-only data and writable
 * data each start a PT_LOAD segment on a page of its own, so the kernel can
 * map each with its permissions (RX, R, RW and NX) and no page holds two.
 * The ELF and program headers are in no segment.
 *
 * The stack, libsys's .libsys_stack, is a segment of its own one page above
 * the end of .bss: no segment covers the page between them, so nothing maps
 * there, and a stack overflow faults instead of overwriting .bss. The image
 * ends at the top of the stack; the kernel maps the IPC buffer and BootInfo
 * right after it.
 */
ENTRY(_start)

PHDRS
{
    text   PT_LOAD FLAGS(5);   /* R X */
    rodata PT_LOAD FLAGS(4);   /* R   */
    data   PT_LOAD FLAGS(6);   /* R W */
    stack  PT_LOAD FLAGS(6);   /* R W */
}

SECTIONS
{
    . = 0x400000;

    .text : ALIGN(4K)
    {
        *(.text._start)
        *(.text .text.*)
    } :text

    .rodata : ALIGN(4K)
    {
        *(.rodata .rodata.*)
    } :rodata

    .eh_frame_hdr : { *(.eh_frame_hdr) } :rodata
    .eh_frame : { KEEP(*(.eh_frame)) } :rodata

    .data : ALIGN(4K)
    {
        *(.data .data.*)
        *(.got .got.*)
    } :data

    .bss :
    {
        *(.bss .bss.*)
        *(COMMON)
    } :data

    /* The guard page. */
    . = ALIGN(4K) + 4K;

    .stack (NOLOAD) : ALIGN(4K)
    {
        KEEP(*(.libsys_stack))
        . = ALIGN(4K);
    } :stack

    /DISCARD/ :
    {
        *(.comment)
        *(.note .note.*)
    }
}
