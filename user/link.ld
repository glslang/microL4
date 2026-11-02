/*
 * Every user program: a static ELF linked at 0x400000 (docs/design.md,
 * "Root-task image and address space"). Text, read-only data and writable
 * data each start a PT_LOAD segment on a page of its own, so the kernel can
 * map each with its permissions (RX, R, RW and NX) and no page holds two.
 * The ELF and program headers are in no segment.
 *
 * Stacks follow .bss, each a segment of its own above an unmapped guard
 * page that no segment covers, so an overflow faults instead of
 * overwriting what lies below: two thread stacks, .thread_stack.0 and
 * .thread_stack.1 (the root task's spawn.rs; a program without them gets
 * empty segments, which the kernel ignores), then libsys's .libsys_stack.
 * The image ends at the top of the libsys stack; the kernel maps the IPC
 * buffer and BootInfo right after it.
 */
ENTRY(_start)

PHDRS
{
    text    PT_LOAD FLAGS(5);   /* R X */
    rodata  PT_LOAD FLAGS(4);   /* R   */
    data    PT_LOAD FLAGS(6);   /* R W */
    thread0 PT_LOAD FLAGS(6);   /* R W */
    thread1 PT_LOAD FLAGS(6);   /* R W */
    stack   PT_LOAD FLAGS(6);   /* R W */
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

    /* A guard page below each stack. */
    . = ALIGN(4K) + 4K;

    .thread_stack0 (NOLOAD) : ALIGN(4K)
    {
        KEEP(*(.thread_stack.0))
        . = ALIGN(4K);
    } :thread0

    . = ALIGN(4K) + 4K;

    .thread_stack1 (NOLOAD) : ALIGN(4K)
    {
        KEEP(*(.thread_stack.1))
        . = ALIGN(4K);
    } :thread1

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
