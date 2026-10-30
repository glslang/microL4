/*
 * The kernel image. It is linked at KERNEL_VIRT_BASE (l4core::handoff) and
 * the loader maps it there, contiguously, at whatever physical address it
 * allocated. The first section of each PT_LOAD segment starts on a page, so
 * that text, read-only data and writable data get separate page permissions.
 * .bss follows .data in the writable segment without page alignment.
 *
 * The __*_start and __*_end symbols bound what the kernel's own page tables
 * map with each permission (docs/design.md, "The kernel half"): text RX,
 * rodata R, data RW and NX. The stacks at the end of the data segment each
 * sit above a 4 KiB guard page that those tables leave unmapped.
 */
ENTRY(_start)

PHDRS
{
    text   PT_LOAD FLAGS(5);   /* R X */
    rodata PT_LOAD FLAGS(4);   /* R   */
    data   PT_LOAD FLAGS(6);   /* R W */
}

/* l4core's KERNEL_IMAGE_MAX: the whole image, .rootimage included (M5). */
KERNEL_IMAGE_MAX = 16M;
GUARD = 4K;
KERNEL_STACK_SIZE = 64K;
IST_STACK_SIZE = 8K;

SECTIONS
{
    . = 0xFFFFFFFF80000000;
    __kernel_start = .;

    .text : ALIGN(4K)
    {
        __text_start = .;
        *(.text._start)
        *(.text .text.*)
    } :text

    /* The Hyper-V hypercall page (M9): one page of its own, RX. */
    .hvcall : ALIGN(4K)
    {
        __hvcall_start = .;
        KEEP(*(.hvcall))
        . = __hvcall_start + 4K;
        __hvcall_end = .;
        __text_end = .;
    } :text

    .rodata : ALIGN(4K)
    {
        __rodata_start = .;
        *(.rodata .rodata.*)
    } :rodata

    .eh_frame_hdr : { *(.eh_frame_hdr) } :rodata
    .eh_frame : { KEEP(*(.eh_frame)) __rodata_end = .; } :rodata

    .data : ALIGN(4K)
    {
        __data_start = .;
        *(.data .data.*)
        *(.got .got.*)
    } :data

    .bss :
    {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(16);
        __bss_end = .;
    } :data

    /*
     * The kernel stack and the four IST stacks (#DF, NMI, #MC, #DB), each
     * above a guard page. Like .bss they take no file space, and _start does
     * not need them zeroed.
     */
    .stacks (NOLOAD) : ALIGN(4K)
    {
        __kernel_stack_guard = .;
        . += GUARD;
        __kernel_stack_bottom = .;
        . += KERNEL_STACK_SIZE;
        __kernel_stack_top = .;
        __ist1_guard = .;
        . += GUARD;
        . += IST_STACK_SIZE;
        __ist1_top = .;
        __ist2_guard = .;
        . += GUARD;
        . += IST_STACK_SIZE;
        __ist2_top = .;
        __ist3_guard = .;
        . += GUARD;
        . += IST_STACK_SIZE;
        __ist3_top = .;
        __ist4_guard = .;
        . += GUARD;
        . += IST_STACK_SIZE;
        __ist4_top = .;
    } :data

    . = ALIGN(4K);
    __data_end = .;
    __kernel_end = .;

    /DISCARD/ :
    {
        *(.comment)
        *(.note .note.*)
    }
}

ASSERT(__hvcall_end - __hvcall_start == 4K, "the .hvcall section must be one page")
ASSERT(__kernel_end - __kernel_start <= KERNEL_IMAGE_MAX, "the kernel image is over KERNEL_IMAGE_MAX (16 MiB)")
