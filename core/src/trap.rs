//! Traps: the host-testable part of the kernel's descriptor tables, trap
//! entry and fatal reports (`docs/design.md`, "Rings and segments",
//! "Kernel entry and exit", "Interrupts" → "Vector map"; ADR 0008).
//!
//! - The vector map: each vector's name and kind, which exceptions push an
//!   error code, which run on an IST stack, which cannot occur here, and
//!   what vectors 32 to 255 are for.
//! - The selectors and the encodings of the GDT, the TSS and an IDT gate.
//! - The 22-word trap frame the entry stubs build and the handlers read.
//! - What a trap taken in ring 0 means, and the panic report for one, with
//!   the `#PF` error code decoded.
//!
//! `arch` reads the hardware, builds the tables from these values and
//! assembles the stubs from [`ERROR_CODE_VECTORS`] and [`FATAL_VECTORS`].

use core::fmt;
use core::ops::Range;

// ---------------------------------------------------------------------------
// The vector map
// ---------------------------------------------------------------------------

/// `#DB`, debug: IST4.
pub const DEBUG: u8 = 1;
/// NMI: IST2, fatal from either ring.
pub const NMI: u8 = 2;
/// `#BP`, breakpoint: the only gate with DPL 3.
pub const BREAKPOINT: u8 = 3;
/// `#DF`, double fault: IST1, fatal from either ring.
pub const DOUBLE_FAULT: u8 = 8;
/// `#PF`, page fault.
pub const PAGE_FAULT: u8 = 14;
/// `#MC`, machine check: IST3, fatal from either ring.
pub const MACHINE_CHECK: u8 = 18;

/// The first vector that is not a CPU exception.
pub const FIRST_INTERRUPT: u8 = 0x20;
/// The 8259 PIC's 16 lines, remapped to `0x20`-`0x2F` and masked.
pub const PIC_BASE: u8 = 0x20;
/// The first of the 192 device vectors; IRQ number = vector - `DEVICE_BASE`.
pub const DEVICE_BASE: u8 = 0x30;
/// The last device vector.
pub const DEVICE_LAST: u8 = 0xEF;
/// The first of the vectors reserved for IPIs, `0xF0`-`0xFC`.
pub const IPI_BASE: u8 = 0xF0;
/// The local APIC timer.
pub const TIMER: u8 = 0xFD;
/// The local APIC error interrupt.
pub const APIC_ERROR: u8 = 0xFE;
/// The local APIC spurious vector.
pub const SPURIOUS: u8 = 0xFF;

/// Bit `v` is set for each exception `v` for which the CPU pushes an error
/// code and the stub therefore pushes none: `#DF` and 10 to 14. Vectors 17,
/// 21, 29 and 30 push one too when raised as exceptions, but none can be
/// raised here, so their stubs push a zero like every other vector's, which
/// also reads an MSI injected on them correctly (`docs/design.md`, Entry).
pub const ERROR_CODE_VECTORS: u32 = (1 << DOUBLE_FAULT) | (0b11111 << 10);

/// Bit `v` is set for NMI, `#DF` and `#MC`: fatal from either ring, on their
/// IST stacks. Their stubs go straight to the fatal handler, without
/// `swapgs`, and never read GS or the interrupted RSP.
pub const FATAL_VECTORS: u32 = (1 << NMI) | (1 << DOUBLE_FAULT) | (1 << MACHINE_CHECK);

/// Bit `v` is set for each exception that cannot occur in this
/// configuration and panics from either ring: 9 and 15 (reserved), 17
/// (`#AC`, CR0.AM = 0), 20 (`#VE`, never enabled), 21 (`#CP`, no CET), 28
/// to 30 (AMD SEV only) and the reserved 22 to 27 and 31.
pub const CANNOT_OCCUR_VECTORS: u32 = (1 << 9) | (1 << 15) | (1 << 17) | 0xFFF0_0000;

/// What the kernel does with a vector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A CPU exception a thread can cause: from ring 3 a fault for its
    /// handler (M5), from ring 0 a kernel bug.
    Exception,
    /// NMI, `#DF` or `#MC`: fatal from either ring.
    Fatal,
    /// An exception that cannot occur here; only an injected MSI reaches it.
    /// Fatal from either ring.
    CannotOccur,
    /// An 8259 PIC line, `0x20`-`0x2F`: never expected, the PIC is masked.
    Pic { line: u8 },
    /// A device vector, `0x30`-`0xEF`, and its IRQ number.
    Device { irq: u8 },
    /// Reserved for IPIs, `0xF0`-`0xFC`.
    Ipi,
    /// The local APIC timer, `0xFD`.
    Timer,
    /// The local APIC error interrupt, `0xFE`.
    ApicError,
    /// The local APIC spurious vector, `0xFF`.
    Spurious,
}

/// The vector map (`docs/design.md`, "Vector map").
pub const fn kind(v: u8) -> Kind {
    match v {
        0..=0x1F if FATAL_VECTORS >> v & 1 == 1 => Kind::Fatal,
        0..=0x1F if CANNOT_OCCUR_VECTORS >> v & 1 == 1 => Kind::CannotOccur,
        0..=0x1F => Kind::Exception,
        0x20..=0x2F => Kind::Pic { line: v - PIC_BASE },
        0x30..=0xEF => Kind::Device {
            irq: v - DEVICE_BASE,
        },
        0xF0..=0xFC => Kind::Ipi,
        TIMER => Kind::Timer,
        APIC_ERROR => Kind::ApicError,
        SPURIOUS => Kind::Spurious,
    }
}

/// Whether the CPU pushes an error code for vector `v`, so that its stub
/// must not push a zero in its place.
pub const fn cpu_pushes_error_code(v: u8) -> bool {
    v < FIRST_INTERRUPT && ERROR_CODE_VECTORS >> v & 1 == 1
}

/// The IST stack vector `v` runs on, 1 to 4, or 0 for the current stack (or
/// RSP0 from ring 3): IST1 `#DF`, IST2 NMI, IST3 `#MC`, IST4 `#DB`.
pub const fn ist(v: u8) -> u8 {
    match v {
        DOUBLE_FAULT => 1,
        NMI => 2,
        MACHINE_CHECK => 3,
        DEBUG => 4,
        _ => 0,
    }
}

/// The gate's DPL: 3 for `#BP`, so that `int3` is a breakpoint in ring 3,
/// and 0 for every other vector, so that `int n` from ring 3 raises `#GP`.
pub const fn gate_dpl(v: u8) -> u8 {
    if v == BREAKPOINT { 3 } else { 0 }
}

/// The mnemonic and name of each exception; an empty mnemonic for the
/// reserved vectors. 28 to 30 are AMD's.
const EXCEPTIONS: [(&str, &str); 32] = [
    ("#DE", "divide error"),
    ("#DB", "debug"),
    ("NMI", "non-maskable interrupt"),
    ("#BP", "breakpoint"),
    ("#OF", "overflow"),
    ("#BR", "bound range exceeded"),
    ("#UD", "invalid opcode"),
    ("#NM", "device not available"),
    ("#DF", "double fault"),
    ("", "coprocessor segment overrun"),
    ("#TS", "invalid TSS"),
    ("#NP", "segment not present"),
    ("#SS", "stack-segment fault"),
    ("#GP", "general protection"),
    ("#PF", "page fault"),
    ("", "reserved"),
    ("#MF", "x87 floating-point error"),
    ("#AC", "alignment check"),
    ("#MC", "machine check"),
    ("#XM", "SIMD floating-point exception"),
    ("#VE", "virtualization exception"),
    ("#CP", "control protection"),
    ("", "reserved"),
    ("", "reserved"),
    ("", "reserved"),
    ("", "reserved"),
    ("", "reserved"),
    ("", "reserved"),
    ("#HV", "hypervisor injection"),
    ("#VC", "VMM communication"),
    ("#SX", "security exception"),
    ("", "reserved"),
];

/// A vector, displayed with its name: `#PF page fault (vector 14)`,
/// `interrupt 0x30 (device IRQ 0)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vector(pub u8);

impl fmt::Display for Vector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let v = self.0;
        if v < FIRST_INTERRUPT {
            let (mnemonic, name) = EXCEPTIONS[v as usize];
            if !mnemonic.is_empty() {
                write!(f, "{mnemonic} ")?;
            }
            return write!(f, "{name} (vector {v})");
        }
        write!(f, "interrupt {v:#04x} (")?;
        match kind(v) {
            Kind::Pic { line } => write!(f, "8259 PIC line {line}")?,
            Kind::Device { irq } => write!(f, "device IRQ {irq}")?,
            Kind::Ipi => f.write_str("IPI")?,
            Kind::Timer => f.write_str("local APIC timer")?,
            Kind::ApicError => f.write_str("local APIC error")?,
            Kind::Spurious => f.write_str("local APIC spurious")?,
            Kind::Exception | Kind::Fatal | Kind::CannotOccur => {}
        }
        f.write_str(")")
    }
}

// ---------------------------------------------------------------------------
// Segments and descriptor tables
// ---------------------------------------------------------------------------

/// Kernel code, 64-bit, DPL 0: GDT index 1.
pub const KERNEL_CS: u16 = 0x08;
/// Kernel data, DPL 0: GDT index 2.
pub const KERNEL_DS: u16 = 0x10;
/// User data, DPL 3: GDT index 3 with RPL 3.
pub const USER_DS: u16 = 0x1B;
/// User code, 64-bit, DPL 3: GDT index 4 with RPL 3.
pub const USER_CS: u16 = 0x23;
/// The TSS: GDT indices 5 and 6.
pub const TSS_SELECTOR: u16 = 0x28;

/// GDT entries: null, kernel code, kernel data, user data, user code and
/// the two halves of the TSS descriptor. There is no 32-bit code descriptor.
pub const GDT_ENTRIES: usize = 7;

// Code and data descriptors: base 0, limit 0xFFFFF with 4 KiB granularity
// (ignored in 64-bit mode). The accessed bit is set in each, so the CPU never
// writes the GDT to set it; it writes only the TSS descriptor's busy bit.
/// Present, DPL 0, code execute/read accessed, L = 1, D = 0.
const KERNEL_CODE: u64 = 0x00AF_9B00_0000_FFFF;
/// Present, DPL 0, data read/write accessed.
const KERNEL_DATA: u64 = 0x00CF_9300_0000_FFFF;
/// Present, DPL 3, data read/write accessed.
const USER_DATA: u64 = 0x00CF_F300_0000_FFFF;
/// Present, DPL 3, code execute/read accessed, L = 1, D = 0.
const USER_CODE: u64 = 0x00AF_FB00_0000_FFFF;

/// The GDT of "Rings and segments", with the TSS at `tss_base`.
pub const fn gdt(tss_base: u64) -> [u64; GDT_ENTRIES] {
    let [lo, hi] = tss_descriptor(tss_base);
    [0, KERNEL_CODE, KERNEL_DATA, USER_DATA, USER_CODE, lo, hi]
}

/// A 64-bit TSS's size in bytes.
pub const TSS_SIZE: usize = 104;

/// The 16-byte system descriptor of an available 64-bit TSS at `base`, DPL
/// 0, with limit `TSS_SIZE - 1`.
pub const fn tss_descriptor(base: u64) -> [u64; 2] {
    const AVAILABLE_TSS: u64 = 0x89; // present, DPL 0, type 9
    let limit = (TSS_SIZE - 1) as u64;
    let lo = (limit & 0xFFFF)
        | (base & 0xFF_FFFF) << 16
        | AVAILABLE_TSS << 40
        | (limit >> 16 & 0xF) << 48
        | (base >> 24 & 0xFF) << 56;
    [lo, base >> 32]
}

/// The 64-bit TSS. Its 8-byte fields sit at 4-byte offsets, hence
/// `packed(4)`.
#[repr(C, packed(4))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tss {
    reserved0: u32,
    /// RSP0 to RSP2; ring-3 entries load RSP0. RSP1 and RSP2 are unused.
    pub rsp: [u64; 3],
    reserved1: u64,
    /// IST1 to IST7, at indices 0 to 6.
    pub ist: [u64; 7],
    reserved2: u64,
    reserved3: u16,
    /// The I/O map base: [`TSS_SIZE`], past the limit, so there is no
    /// bitmap and every port is denied to ring 3.
    pub iomap_base: u16,
}

impl Tss {
    /// A TSS with `rsp0`, the kernel stack top, and IST1 to IST4 at the tops
    /// of the `#DF`, NMI, `#MC` and `#DB` stacks.
    pub const fn new(rsp0: u64, ist: [u64; 4]) -> Tss {
        Tss {
            reserved0: 0,
            rsp: [rsp0, 0, 0],
            reserved1: 0,
            ist: [ist[0], ist[1], ist[2], ist[3], 0, 0, 0],
            reserved2: 0,
            reserved3: 0,
            iomap_base: TSS_SIZE as u16,
        }
    }
}

/// The IDT gate for vector `v`: a 64-bit interrupt gate on [`KERNEL_CS`] to
/// `handler`, with [`ist`] and [`gate_dpl`] for `v`. Every gate is an
/// interrupt gate, so every entry runs with IF = 0.
pub const fn idt_gate(handler: u64, v: u8) -> [u64; 2] {
    const INTERRUPT_GATE: u64 = 0x8E; // present, type 0xE
    let attributes = INTERRUPT_GATE | (gate_dpl(v) as u64) << 5;
    let lo = (handler & 0xFFFF)
        | (KERNEL_CS as u64) << 16
        | (ist(v) as u64) << 32
        | attributes << 40
        | (handler >> 16 & 0xFFFF) << 48;
    [lo, handler >> 32]
}

// ---------------------------------------------------------------------------
// The trap frame
// ---------------------------------------------------------------------------

/// The trap frame, 22 words, lowest address first (`docs/design.md`,
/// Entry). The CPU pushes `ss` to `rip` and, for some vectors, `error`; the
/// stub pushes a zero `error` for the rest, then `vector`, then `rax` to
/// `r15`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TrapFrame {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rbp: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rbx: u64,
    pub rax: u64,
    pub vector: u64,
    pub error: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

/// The frame's size in words.
pub const FRAME_WORDS: usize = 22;
/// Byte offset of `vector` in the frame: where RSP points once the stub has
/// pushed it.
pub const FRAME_VECTOR: usize = core::mem::offset_of!(TrapFrame, vector);
/// Byte offset of the saved `cs`.
pub const FRAME_CS: usize = core::mem::offset_of!(TrapFrame, cs);

impl TrapFrame {
    /// The ring the trap came from: the saved CS's RPL.
    pub const fn ring(&self) -> u8 {
        (self.cs & 3) as u8
    }
}

// ---------------------------------------------------------------------------
// Traps taken in ring 0
// ---------------------------------------------------------------------------

/// What a trap taken in ring 0 means (`docs/design.md`, "Interrupts and
/// exceptions taken in ring 0").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KernelTrap {
    /// An interrupt taken in the idle loop: discard the frame and run the
    /// interrupt path for this vector.
    IdleInterrupt(u8),
    /// Anything else is a kernel bug: panic with the [`Report`].
    Fatal,
}

/// Decides a ring-0 trap: a vector of 32 or more is an interrupt the kernel
/// takes only with RIP inside `idle` (the idle loop's code); every other
/// trap is fatal, as is a frame whose vector is not a vector.
pub fn kernel_trap(frame: &TrapFrame, idle: &Range<u64>) -> KernelTrap {
    match u8::try_from(frame.vector) {
        Ok(v) if v >= FIRST_INTERRUPT && idle.contains(&frame.rip) => KernelTrap::IdleInterrupt(v),
        _ => KernelTrap::Fatal,
    }
}

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

/// A `#PF` error code, displayed decoded: `not present, supervisor read`,
/// `present, user instruction fetch, protection key`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageFaultError(pub u64);

impl PageFaultError {
    /// P: the page was present, so this is a protection violation.
    pub const PRESENT: u64 = 1 << 0;
    /// W/R: a write.
    pub const WRITE: u64 = 1 << 1;
    /// U/S: a ring-3 access.
    pub const USER: u64 = 1 << 2;
    /// RSVD: a reserved bit was set in a paging-structure entry.
    pub const RESERVED: u64 = 1 << 3;
    /// I/D: an instruction fetch.
    pub const FETCH: u64 = 1 << 4;
    /// PK: a protection-key violation.
    pub const PROTECTION_KEY: u64 = 1 << 5;
    /// SS: a shadow-stack access.
    pub const SHADOW_STACK: u64 = 1 << 6;
    /// HLAT: during HLAT paging.
    pub const HLAT: u64 = 1 << 7;
    /// SGX: an SGX access-control violation.
    pub const SGX: u64 = 1 << 15;

    const KNOWN: u64 = Self::PRESENT
        | Self::WRITE
        | Self::USER
        | Self::RESERVED
        | Self::FETCH
        | Self::PROTECTION_KEY
        | Self::SHADOW_STACK
        | Self::HLAT
        | Self::SGX;

    /// Whether every bit of `bits` is set.
    pub const fn has(self, bits: u64) -> bool {
        self.0 & bits == bits
    }
}

impl fmt::Display for PageFaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let present = if self.has(Self::PRESENT) {
            "present"
        } else {
            "not present"
        };
        let ring = if self.has(Self::USER) {
            "user"
        } else {
            "supervisor"
        };
        let access = if self.has(Self::FETCH) {
            "instruction fetch"
        } else if self.has(Self::WRITE) {
            "write"
        } else {
            "read"
        };
        write!(f, "{present}, {ring} {access}")?;
        for (bit, name) in [
            (Self::RESERVED, "reserved bit set"),
            (Self::PROTECTION_KEY, "protection key"),
            (Self::SHADOW_STACK, "shadow stack"),
            (Self::HLAT, "HLAT"),
            (Self::SGX, "SGX"),
        ] {
            if self.has(bit) {
                write!(f, ", {name}")?;
            }
        }
        match self.0 & !Self::KNOWN {
            0 => Ok(()),
            other => write!(f, ", other bits {other:#x}"),
        }
    }
}

/// The selector error code of `#TS`, `#NP`, `#SS` and `#GP`, displayed
/// decoded: `IDT vector 48`, `GDT selector 0x28`, with `external, ` first
/// if an event outside the program caused it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelectorError(pub u64);

impl fmt::Display for SelectorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 & 1 != 0 {
            f.write_str("external, ")?;
        }
        let index = (self.0 & 0xFFFF) >> 3;
        if self.0 & 2 != 0 {
            write!(f, "IDT vector {index}")
        } else if self.0 & 4 != 0 {
            write!(f, "LDT selector {:#x}", index << 3)
        } else {
            write!(f, "GDT selector {:#x}", index << 3)
        }
    }
}

// ---------------------------------------------------------------------------
// Stacks and the fatal report
// ---------------------------------------------------------------------------

/// Which kernel stack an address is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stack {
    /// The kernel stack.
    Kernel,
    /// IST stack 1 to 4.
    Ist(u8),
    /// Neither: a kernel bug moved RSP.
    Unknown,
}

impl fmt::Display for Stack {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Stack::Kernel => f.write_str("the kernel stack"),
            Stack::Ist(n) => write!(f, "IST{n}"),
            Stack::Unknown => f.write_str("an unknown stack"),
        }
    }
}

/// Where the kernel stack and the four IST stacks are.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StackLayout {
    pub kernel: Range<u64>,
    /// IST1 to IST4, at indices 0 to 3.
    pub ist: [Range<u64>; 4],
}

impl StackLayout {
    /// The stack holding `addr`.
    pub fn stack_of(&self, addr: u64) -> Stack {
        if self.kernel.contains(&addr) {
            return Stack::Kernel;
        }
        match self.ist.iter().position(|r| r.contains(&addr)) {
            Some(i) => Stack::Ist(i as u8 + 1),
            None => Stack::Unknown,
        }
    }
}

/// How many bytes at the top of `stack` are used, given that everything
/// below its deepest use still holds `paint`: the stack's size less the
/// painted words at its bottom.
pub fn high_water(stack: &[u64], paint: u64) -> usize {
    let untouched = stack.iter().take_while(|&&w| w == paint).count();
    (stack.len() - untouched) * 8
}

/// The report of a fatal trap: one line naming the vector, the ring, the
/// error code (decoded for `#PF` and the selector faults), CR2 for `#PF` and
/// `#DF`, RIP, RSP, RFLAGS, CS and the stack the frame is on; then the
/// general registers.
pub struct Report<'a> {
    pub frame: &'a TrapFrame,
    /// CR2, read before anything else could fault.
    pub cr2: u64,
    /// The stack holding the frame.
    pub stack: Stack,
}

impl fmt::Display for Report<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let t = self.frame;
        let Ok(v) = u8::try_from(t.vector) else {
            return write!(f, "trap frame with bad vector {:#x}", t.vector);
        };
        write!(f, "{} in ring {}", Vector(v), t.ring())?;
        if v >= FIRST_INTERRUPT && t.ring() == 0 {
            f.write_str(", outside the idle loop")?;
        }
        write!(f, ": error {:#x}", t.error)?;
        match v {
            PAGE_FAULT => write!(f, " ({})", PageFaultError(t.error))?,
            10..=13 if t.error != 0 => write!(f, " ({})", SelectorError(t.error))?,
            _ => {}
        }
        if v == PAGE_FAULT || v == DOUBLE_FAULT {
            write!(f, ", CR2 {:#x}", self.cr2)?;
        }
        write!(
            f,
            ", RIP {:#x}, RSP {:#x}, RFLAGS {:#x}, CS {:#x}, frame on {}",
            t.rip, t.rsp, t.rflags, t.cs, self.stack
        )?;
        let regs = [
            ("rax", t.rax),
            ("rbx", t.rbx),
            ("rcx", t.rcx),
            ("rdx", t.rdx),
            ("rsi", t.rsi),
            ("rdi", t.rdi),
            ("rbp", t.rbp),
            ("r8", t.r8),
            ("r9", t.r9),
            ("r10", t.r10),
            ("r11", t.r11),
            ("r12", t.r12),
            ("r13", t.r13),
            ("r14", t.r14),
            ("r15", t.r15),
        ];
        for (i, (name, value)) in regs.iter().enumerate() {
            let sep = if i % 4 == 0 { "\n" } else { "" };
            write!(f, "{sep}  {name:>3} {value:#018x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{offset_of, size_of};
    use std::string::ToString;
    use std::vec::Vec;

    fn exceptions(pred: impl Fn(u8) -> bool) -> Vec<u8> {
        (0..32).filter(|&v| pred(v)).collect()
    }

    #[test]
    fn error_codes_are_pushed_for_8_and_10_to_14_only() {
        // SDM vol. 3, table 6-1, less the four that cannot be raised here.
        assert_eq!(exceptions(cpu_pushes_error_code), [8, 10, 11, 12, 13, 14]);
        for v in 32..=255 {
            assert!(!cpu_pushes_error_code(v), "vector {v}");
        }
    }

    #[test]
    fn ist_stacks_serve_df_nmi_mc_and_db_only() {
        assert_eq!(ist(DOUBLE_FAULT), 1);
        assert_eq!(ist(NMI), 2);
        assert_eq!(ist(MACHINE_CHECK), 3);
        assert_eq!(ist(DEBUG), 4);
        let with_ist: Vec<u8> = (0..=255).filter(|&v| ist(v) != 0).collect();
        assert_eq!(with_ist, [1, 2, 8, 18]);
    }

    #[test]
    fn only_breakpoint_has_dpl_3() {
        let open: Vec<u8> = (0..=255).filter(|&v| gate_dpl(v) != 0).collect();
        assert_eq!(open, [3]);
        assert_eq!(gate_dpl(BREAKPOINT), 3);
    }

    #[test]
    fn exception_kinds_follow_the_vector_map() {
        assert_eq!(exceptions(|v| kind(v) == Kind::Fatal), [2, 8, 18]);
        assert_eq!(
            exceptions(|v| kind(v) == Kind::CannotOccur),
            [9, 15, 17, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31]
        );
        assert_eq!(
            exceptions(|v| kind(v) == Kind::Exception),
            [0, 1, 3, 4, 5, 6, 7, 10, 11, 12, 13, 14, 16, 19]
        );
        // The fatal ones are exactly the vectors whose stubs skip `swapgs`.
        assert_eq!(exceptions(|v| FATAL_VECTORS >> v & 1 == 1), [2, 8, 18]);
        // No vector that cannot occur takes an error code from the CPU.
        assert_eq!(CANNOT_OCCUR_VECTORS & ERROR_CODE_VECTORS, 0);
    }

    #[test]
    fn interrupt_kinds_follow_the_vector_map() {
        assert_eq!(kind(0x20), Kind::Pic { line: 0 });
        assert_eq!(kind(0x2F), Kind::Pic { line: 15 });
        assert_eq!(kind(0x30), Kind::Device { irq: 0 });
        assert_eq!(kind(DEVICE_LAST), Kind::Device { irq: 191 });
        assert_eq!(kind(0xF0), Kind::Ipi);
        assert_eq!(kind(0xFC), Kind::Ipi);
        assert_eq!(kind(0xFD), Kind::Timer);
        assert_eq!(kind(0xFE), Kind::ApicError);
        assert_eq!(kind(0xFF), Kind::Spurious);
        let devices = (0..=255)
            .filter(|&v| matches!(kind(v), Kind::Device { .. }))
            .count();
        assert_eq!(devices, 192);
    }

    #[test]
    fn vectors_display_their_names() {
        assert_eq!(Vector(14).to_string(), "#PF page fault (vector 14)");
        assert_eq!(
            Vector(2).to_string(),
            "NMI non-maskable interrupt (vector 2)"
        );
        assert_eq!(Vector(15).to_string(), "reserved (vector 15)");
        assert_eq!(Vector(21).to_string(), "#CP control protection (vector 21)");
        assert_eq!(Vector(0x21).to_string(), "interrupt 0x21 (8259 PIC line 1)");
        assert_eq!(Vector(0x30).to_string(), "interrupt 0x30 (device IRQ 0)");
        assert_eq!(Vector(0xF3).to_string(), "interrupt 0xf3 (IPI)");
        assert_eq!(
            Vector(0xFF).to_string(),
            "interrupt 0xff (local APIC spurious)"
        );
        for v in 0..=255 {
            assert!(!Vector(v).to_string().is_empty());
        }
    }

    #[test]
    fn gdt_matches_rings_and_segments() {
        let g = gdt(0);
        assert_eq!(g[0], 0);
        // Index = selector / 8; descriptor DPL = the selector's RPL.
        for (sel, dpl, code) in [
            (KERNEL_CS, 0, true),
            (KERNEL_DS, 0, false),
            (USER_DS, 3, false),
            (USER_CS, 3, true),
        ] {
            let d = g[sel as usize >> 3];
            assert_eq!(d >> 47 & 1, 1, "{sel:#x} present");
            assert_eq!(d >> 45 & 3, dpl, "{sel:#x} DPL");
            assert_eq!(sel as u64 & 3, dpl, "{sel:#x} RPL");
            assert_eq!(d >> 44 & 1, 1, "{sel:#x} code or data");
            assert_eq!(d >> 43 & 1, code as u64, "{sel:#x} executable");
            assert_eq!(d >> 40 & 1, 1, "{sel:#x} accessed");
            if code {
                // 64-bit code: L = 1 and D = 0. There is no 32-bit code
                // descriptor, so ring 3 cannot enter compatibility mode.
                assert_eq!(d >> 53 & 3, 0b01, "{sel:#x} L and D");
            }
        }
        // sysretq loads SS = STAR[63:48] + 8 and CS = STAR[63:48] + 16
        // from 0x13: user data, then user code.
        assert_eq!(0x13 + 8, USER_DS);
        assert_eq!(0x13 + 16, USER_CS);
        assert_eq!(TSS_SELECTOR as usize >> 3, 5);
    }

    #[test]
    fn tss_descriptor_encodes_base_and_limit() {
        let base = 0xFFFF_FFFF_8012_3450;
        let g = gdt(base);
        let [lo, hi] = [g[5], g[6]];
        assert_eq!([lo, hi], tss_descriptor(base));
        let limit = (lo & 0xFFFF) | (lo >> 48 & 0xF) << 16;
        assert_eq!(limit, 103);
        let decoded = (lo >> 16 & 0xFF_FFFF) | (lo >> 56 & 0xFF) << 24 | (hi & 0xFFFF_FFFF) << 32;
        assert_eq!(decoded, base);
        // Present, DPL 0, system descriptor of type 9 (available 64-bit TSS).
        assert_eq!(lo >> 40 & 0xFF, 0x89);
        assert_eq!(hi >> 32, 0, "upper half of the second word is reserved");
    }

    #[test]
    fn tss_layout_is_the_sdm_one() {
        assert_eq!(size_of::<Tss>(), TSS_SIZE);
        assert_eq!(offset_of!(Tss, rsp), 4);
        assert_eq!(offset_of!(Tss, ist), 36);
        assert_eq!(offset_of!(Tss, iomap_base), 102);
        let t = Tss::new(0x1000, [0x2000, 0x3000, 0x4000, 0x5000]);
        let (rsp, ist, iomap) = (t.rsp, t.ist, t.iomap_base);
        assert_eq!(rsp, [0x1000, 0, 0]);
        assert_eq!(ist, [0x2000, 0x3000, 0x4000, 0x5000, 0, 0, 0]);
        // Past the limit (103): no bitmap, so ring 3 has no port.
        assert!(iomap as usize > TSS_SIZE - 1);
    }

    #[test]
    fn idt_gates_are_interrupt_gates() {
        let handler = 0xFFFF_FFFF_8000_1234;
        for v in 0..=255u8 {
            let [lo, hi] = idt_gate(handler, v);
            let offset = (lo & 0xFFFF) | (lo >> 48 & 0xFFFF) << 16 | hi << 32;
            assert_eq!(offset, handler, "vector {v}");
            assert_eq!(lo >> 16 & 0xFFFF, KERNEL_CS as u64);
            assert_eq!(lo >> 32 & 7, ist(v) as u64);
            assert_eq!(lo >> 35 & 0x1F, 0, "reserved bits");
            assert_eq!(lo >> 40 & 0xF, 0xE, "64-bit interrupt gate");
            assert_eq!(lo >> 45 & 3, gate_dpl(v) as u64);
            assert_eq!(lo >> 47 & 1, 1, "present");
        }
        assert_eq!(idt_gate(handler, 14), [0x8000_8E00_0008_1234, 0xFFFF_FFFF]);
        assert_eq!(idt_gate(handler, 3)[0] >> 40 & 0xFF, 0xEE);
        assert_eq!(idt_gate(handler, 8)[0], 0x8000_8E01_0008_1234);
    }

    #[test]
    fn frame_layout_is_the_design_one() {
        assert_eq!(size_of::<TrapFrame>(), FRAME_WORDS * 8);
        // A multiple of 16, so the stubs call Rust with RSP aligned.
        assert_eq!(size_of::<TrapFrame>() % 16, 0);
        assert_eq!(offset_of!(TrapFrame, r15), 0);
        assert_eq!(offset_of!(TrapFrame, rbp), 8 * 8);
        assert_eq!(offset_of!(TrapFrame, rax), 14 * 8);
        assert_eq!(FRAME_VECTOR, 15 * 8);
        assert_eq!(offset_of!(TrapFrame, error), 16 * 8);
        assert_eq!(offset_of!(TrapFrame, rip), 17 * 8);
        assert_eq!(FRAME_CS, 18 * 8);
        assert_eq!(offset_of!(TrapFrame, rflags), 19 * 8);
        assert_eq!(offset_of!(TrapFrame, rsp), 20 * 8);
        assert_eq!(offset_of!(TrapFrame, ss), 21 * 8);
        // The stub tests the saved CS this far above the vector it pushed.
        assert_eq!(FRAME_CS - FRAME_VECTOR, 24);
    }

    fn frame(vector: u64, rip: u64) -> TrapFrame {
        TrapFrame {
            vector,
            rip,
            cs: KERNEL_CS as u64,
            ..TrapFrame::default()
        }
    }

    #[test]
    fn ring_0_interrupts_are_taken_only_in_the_idle_loop() {
        let idle = 0x1000..0x1010;
        let take = |vector, rip| kernel_trap(&frame(vector, rip), &idle);
        assert_eq!(take(0xFF, 0x1000), KernelTrap::IdleInterrupt(0xFF));
        assert_eq!(take(0x20, 0x100F), KernelTrap::IdleInterrupt(0x20));
        assert_eq!(take(0xFD, 0x1008), KernelTrap::IdleInterrupt(0xFD));
        // Outside the loop, its end included.
        assert_eq!(take(0xFF, 0x0FFF), KernelTrap::Fatal);
        assert_eq!(take(0xFF, 0x1010), KernelTrap::Fatal);
        // Exceptions are fatal in the idle loop too.
        for v in 0..32 {
            assert_eq!(take(v, 0x1004), KernelTrap::Fatal, "vector {v}");
        }
        // A frame whose vector is not one.
        assert_eq!(take(0x100, 0x1004), KernelTrap::Fatal);
        assert_eq!(take(u64::MAX, 0x1004), KernelTrap::Fatal);
    }

    #[test]
    fn page_fault_errors_decode() {
        let d = |e| PageFaultError(e).to_string();
        assert_eq!(d(0), "not present, supervisor read");
        assert_eq!(d(0x2), "not present, supervisor write");
        assert_eq!(d(0x3), "present, supervisor write");
        assert_eq!(d(0x4), "not present, user read");
        assert_eq!(d(0x15), "present, user instruction fetch");
        assert_eq!(d(0x11), "present, supervisor instruction fetch");
        assert_eq!(d(0x9), "present, supervisor read, reserved bit set");
        assert_eq!(d(0x27), "present, user write, protection key");
        assert_eq!(d(0x43), "present, supervisor write, shadow stack");
        assert_eq!(d(0x81), "present, supervisor read, HLAT");
        assert_eq!(d(0x8007), "present, user write, SGX");
        assert_eq!(
            d(0x1_0100),
            "not present, supervisor read, other bits 0x10100"
        );
        assert!(PageFaultError(0x15).has(PageFaultError::FETCH));
        assert!(!PageFaultError(0x15).has(PageFaultError::WRITE));
    }

    #[test]
    fn selector_errors_decode() {
        let d = |e| SelectorError(e).to_string();
        // `int 0x30` against a DPL-0 gate: #GP with 8n + 2.
        assert_eq!(d(0x30 * 8 + 2), "IDT vector 48");
        assert_eq!(d(0x28), "GDT selector 0x28");
        assert_eq!(d(0x2C), "LDT selector 0x28");
        assert_eq!(d(0x19), "external, GDT selector 0x18");
    }

    fn layout() -> StackLayout {
        StackLayout {
            kernel: 0x1_0000..0x2_0000,
            ist: [
                0x2_1000..0x2_3000,
                0x2_4000..0x2_6000,
                0x2_7000..0x2_9000,
                0x2_A000..0x2_C000,
            ],
        }
    }

    #[test]
    fn stacks_are_named_by_address() {
        let l = layout();
        assert_eq!(l.stack_of(0x1_0000), Stack::Kernel);
        assert_eq!(l.stack_of(0x1_FFF8), Stack::Kernel);
        assert_eq!(l.stack_of(0x2_0000), Stack::Unknown, "guard page");
        assert_eq!(l.stack_of(0x2_2F50), Stack::Ist(1));
        assert_eq!(l.stack_of(0x2_5000), Stack::Ist(2));
        assert_eq!(l.stack_of(0x2_8000), Stack::Ist(3));
        assert_eq!(l.stack_of(0x2_BFF8), Stack::Ist(4));
        assert_eq!(l.stack_of(0x2_C000), Stack::Unknown);
        assert_eq!(Stack::Ist(2).to_string(), "IST2");
        assert_eq!(Stack::Kernel.to_string(), "the kernel stack");
    }

    #[test]
    fn high_water_counts_from_the_deepest_overwritten_word() {
        const P: u64 = 0x5A5A_5A5A_5A5A_5A5A;
        assert_eq!(high_water(&[P; 8], P), 0);
        assert_eq!(high_water(&[P, P, P, 0, P, 1, 2, 3], P), 5 * 8);
        assert_eq!(high_water(&[0; 8], P), 64);
        assert_eq!(high_water(&[], P), 0);
    }

    #[test]
    fn page_fault_report() {
        let t = TrapFrame {
            rax: 0xAAAA,
            r15: 0x1515,
            vector: PAGE_FAULT as u64,
            error: 0,
            rip: 0xFFFF_FFFF_8000_1234,
            cs: KERNEL_CS as u64,
            rflags: 0x86,
            rsp: 0xFFFF_FFFF_8010_0F00,
            ss: KERNEL_DS as u64,
            ..TrapFrame::default()
        };
        let r = Report {
            frame: &t,
            cr2: 0xFFFF_9600_0000_0000,
            stack: Stack::Kernel,
        }
        .to_string();
        let lines: Vec<&str> = r.lines().collect();
        assert_eq!(
            lines[0],
            "#PF page fault (vector 14) in ring 0: error 0x0 (not present, supervisor read), \
             CR2 0xffff960000000000, RIP 0xffffffff80001234, RSP 0xffffffff80100f00, \
             RFLAGS 0x86, CS 0x8, frame on the kernel stack"
        );
        assert_eq!(
            lines[1],
            "  rax 0x000000000000aaaa  rbx 0x0000000000000000  rcx 0x0000000000000000  \
             rdx 0x0000000000000000"
        );
        assert_eq!(lines.len(), 5);
        assert!(lines[4].ends_with("r15 0x0000000000001515"));
    }

    #[test]
    fn other_reports() {
        let report = |vector, error, ring, stack| {
            let t = TrapFrame {
                vector,
                error,
                cs: if ring == 3 { USER_CS } else { KERNEL_CS } as u64,
                ..TrapFrame::default()
            };
            let r = Report {
                frame: &t,
                cr2: 0x1000,
                stack,
            };
            r.to_string().lines().next().unwrap().to_string()
        };
        let df = report(8, 0, 0, Stack::Ist(1));
        assert!(
            df.starts_with("#DF double fault (vector 8) in ring 0: error 0x0, CR2 0x1000, RIP")
        );
        assert!(df.ends_with("frame on IST1"));
        // CR2 is shown only for #PF and #DF.
        let gp = report(13, 0x182, 3, Stack::Kernel);
        assert!(gp.starts_with(
            "#GP general protection (vector 13) in ring 3: error 0x182 (IDT vector 48), RIP"
        ));
        let irq = report(0x30, 0, 0, Stack::Kernel);
        assert!(irq.starts_with(
            "interrupt 0x30 (device IRQ 0) in ring 0, outside the idle loop: error 0x0, RIP"
        ));
        let bad = report(0x1234, 0, 0, Stack::Unknown);
        assert_eq!(bad, "trap frame with bad vector 0x1234");
        assert_eq!(
            report(2, 0, 0, Stack::Ist(2)).split(':').next(),
            Some("NMI non-maskable interrupt (vector 2) in ring 0")
        );
    }
}
