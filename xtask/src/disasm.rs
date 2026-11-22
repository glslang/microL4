//! The release kernel's disassembly check (`docs/design.md`, "A release
//! kernel without UART code"; ADR 0021).
//!
//! `cargo xtask test` disassembles the kernel built without `debug` and
//! fails on
//!
//! - a call or jump to one of the functions of
//!   `kernel/src/arch/x86_64/io.rs` from a function other than the three
//!   the design allows ([`IO_CALLERS`]: the IOPort executor, `pic::init`
//!   and `arch::exit`, each `#[inline(never)]` so that it keeps its
//!   symbol);
//! - an address inside io.rs's functions anywhere but as a direct call's
//!   or jump's target: loaded, compared or stored by an instruction, or
//!   stored in the kernel's data, as a function pointer would be;
//! - an `in` or `out`, string forms included, outside io.rs's functions;
//! - an immediate in `0x3F8` to `0x3FF`, COM1's ports, moved into `dx`,
//!   `edx` or `rdx`;
//! - a call or jump to one of io.rs's functions whose port argument (`di`,
//!   `edi` or `rdi`) the straight-line code before it set to such an
//!   immediate: those functions take the port as their first argument and
//!   move it into `dx` themselves, so this is how a caller would name COM1;
//! - any symbol whose name contains `serial`.
//!
//! The first two rules hold whatever the port: UART code needs `in` and
//! `out`, which only io.rs has, so it must reach io.rs through one of the
//! three callers, whose code a reader checks once; the port rules are a
//! second line. The disassembler is `llvm-objdump` from rustup's
//! `llvm-tools` component, which `tools/setup.sh` adds: the LLVM that
//! compiled the kernel, so it decodes whatever rustc emits, with no crate
//! to add. Failing that, an `llvm-objdump` on `PATH` will do. Its
//! Intel-syntax listing is plain to scan line by line, and its symbol
//! table, with sizes, says which addresses are io.rs's and its callers';
//! the data sections come from the ELF's section headers. So that a
//! listing this scanner misreads cannot pass by finding nothing, the check
//! also insists on io.rs's functions with an `in` and an `out` in them,
//! on calls to them from the allowed callers, and on data to scan.

use std::fmt::Write as _;
use std::fs;
use std::ops::{Range, RangeInclusive};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{Result, compile, image, output, rel};

/// io.rs's functions, demangled.
const IO_MODULE: &str = "kernel::arch::x86_64::io::";
/// COM1's ports.
const COM1: RangeInclusive<u64> = 0x3F8..=0x3FF;
/// The registers `in` and `out` take a port in.
const DX: &[&str] = &["dx", "edx", "rdx"];
/// The registers that carry io.rs's port argument.
const PORT_ARG: &[&str] = &["dil", "di", "edi", "rdi"];
/// Every `in` and `out`.
const PORT_IO: &[&str] = &[
    "in", "ins", "insb", "insw", "insd", "out", "outs", "outsb", "outsw", "outsd",
];
/// The string instructions, which move `rdi`.
const STRING_OPS: &[&str] = &[
    "stos", "stosb", "stosw", "stosd", "stosq", "movs", "movsb", "movsw", "movsd", "movsq", "cmps",
    "cmpsb", "cmpsw", "cmpsd", "cmpsq", "scas", "scasb", "scasw", "scasd", "scasq", "ins", "insb",
    "insw", "insd",
];
/// What objdump may print before a mnemonic.
const PREFIXES: &[&str] = &[
    "rep", "repe", "repz", "repne", "repnz", "lock", "data16", "data32", "addr16", "addr32",
    "notrack", "bnd", "cs", "ds", "es", "fs", "gs", "ss",
];
/// Fewer instructions than this is no kernel.
const MIN_INSTRUCTIONS: usize = 1000;
/// The functions a release kernel may call io.rs's from, demangled: the
/// IOPort executor, `pic::init` and `arch::exit` (`docs/design.md`, "A
/// release kernel without UART code"). Each is `#[inline(never)]`, so its
/// symbol bounds its code; a function that inlines one of them, or a
/// clone LLVM makes of one under another name, fails the check.
pub const IO_CALLERS: &[&str] = &[
    "<kernel::arch::x86_64::objects::Objects as l4core::ioport::IoPorts>::port_in",
    "<kernel::arch::x86_64::objects::Objects as l4core::ioport::IoPorts>::port_out",
    "kernel::arch::x86_64::pic::init",
    "kernel::arch::x86_64::exit",
];
/// The section holding the root task's ELF, which the kernel copies and
/// never follows: its bytes are not kernel data.
const ROOT_IMAGE: &str = ".rootimage";

/// What a scan of a listing found.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Scan {
    pub instructions: usize,
    /// io.rs's functions, and the `in` and `out` instructions in them.
    pub io_functions: usize,
    pub io_ins: usize,
    pub io_outs: usize,
    /// Direct calls and jumps to io.rs's functions from [`IO_CALLERS`].
    pub io_calls: usize,
    /// Each broken rule, one line each.
    pub findings: Vec<String>,
}

/// Checks `kernel`, the release kernel's ELF. Returns a line for the log.
pub fn check(kernel: &Path) -> Result<String> {
    let objdump = objdump()?;
    let symbols = output(
        Command::new(&objdump)
            .args(["--syms", "--demangle"])
            .arg(kernel),
    )?;
    let listing = output(
        Command::new(&objdump)
            .args([
                "--disassemble",
                "--demangle",
                "--no-show-raw-insn",
                "-M",
                "intel",
            ])
            .arg(kernel),
    )?;
    let mut scan = scan(&symbols, &listing);
    let what = format!("{} ({})", rel(kernel), objdump.display());
    let elf = fs::read(kernel).map_err(|e| format!("{}: {e}", rel(kernel)))?;
    let data =
        data(&symbols, &elf).ok_or_else(|| format!("{what}: cannot read its section headers"))?;
    scan.findings.extend(data.findings);
    if !scan.findings.is_empty() {
        let mut e = format!(
            "the release kernel {what} fails the disassembly check \
             (docs/design.md, \"A release kernel without UART code\"):"
        );
        for f in &scan.findings {
            write!(e, "\n  {f}")?;
        }
        return Err(e.into());
    }
    if scan.instructions < MIN_INSTRUCTIONS
        || scan.io_functions == 0
        || scan.io_ins == 0
        || scan.io_outs == 0
        || scan.io_calls == 0
        || data.bytes == 0
    {
        return Err(format!(
            "the listing of {what} is not one this check can read: {} instructions, \
             {} functions in {IO_MODULE} with {} in and {} out, {} calls to them, \
             {} bytes of data",
            scan.instructions,
            scan.io_functions,
            scan.io_ins,
            scan.io_outs,
            scan.io_calls,
            data.bytes
        )
        .into());
    }
    Ok(format!(
        "disassembly: {} instructions of the release kernel; in and out only in io.rs's {} \
         functions ({} in, {} out), called {} times, only from the IOPort executor, \
         pic::init and arch::exit; their addresses in no other instruction and in none of \
         {} bytes of data; no COM1 port in dx or passed to them, no serial symbol",
        scan.instructions, scan.io_functions, scan.io_ins, scan.io_outs, scan.io_calls, data.bytes
    ))
}

/// `llvm-objdump` from the toolchain's `llvm-tools`, else from `PATH`.
fn objdump() -> Result<PathBuf> {
    let rustlib = compile::rustlib()?;
    if let Ok(entries) = fs::read_dir(&rustlib) {
        for e in entries.flatten() {
            let tool = e.path().join("bin/llvm-objdump");
            if tool.is_file() {
                return Ok(tool);
            }
        }
    }
    if image::on_path("llvm-objdump") {
        return Ok("llvm-objdump".into());
    }
    Err(
        "llvm-objdump not found: run `rustup component add llvm-tools` (tools/setup.sh does)"
            .into(),
    )
}

/// Scans `listing` (`llvm-objdump --disassemble --demangle
/// --no-show-raw-insn -M intel`) against `symbols` (`llvm-objdump --syms
/// --demangle`) of the same file.
pub fn scan(symbols: &str, listing: &str) -> Scan {
    let mut s = Scan::default();
    let mut callers = Vec::new();
    for sym in symbols.lines().filter_map(Symbol::parse) {
        if sym.name.to_ascii_lowercase().contains("serial") {
            s.findings.push(format!("symbol {}", sym.name));
        }
        if sym.function && sym.size > 0 && IO_CALLERS.contains(&base_name(sym.name)) {
            callers.push(sym.addr..sym.addr + sym.size);
        }
    }
    let io = io_functions(symbols);
    s.io_functions = io.len();
    // The io.rs function `addr` lies in, if any.
    let io_at = |addr: u64| io.iter().position(|r: &Range<u64>| r.contains(&addr));
    let in_io = |addr: u64| io_at(addr).is_some();
    let may_call = |addr: u64| callers.iter().any(|r: &Range<u64>| r.contains(&addr));

    let mut function = "";
    // The immediate the port argument last got on the straight-line code
    // before this instruction, if that is what it last got.
    let mut port_arg = None;
    for line in listing.lines() {
        if let Some(name) = header(line) {
            function = name;
            port_arg = None;
            continue;
        }
        let Some((addr, text)) = instruction(line) else {
            continue;
        };
        s.instructions += 1;
        let (mnemonic, operands) = split(text);
        let ops: Vec<&str> = operands.split(',').map(str::trim).collect();
        let at = || {
            let words: Vec<&str> = text.split_whitespace().collect();
            format!("{addr:#x} in {function}: {}", words.join(" "))
        };

        if PORT_IO.contains(&mnemonic) {
            if !in_io(addr) {
                s.findings
                    .push(format!("{} outside io.rs: {}", mnemonic, at()));
            } else if mnemonic.starts_with("in") {
                s.io_ins += 1;
            } else {
                s.io_outs += 1;
            }
        }
        let mov = matches!(mnemonic, "mov" | "movabs");
        let imm = ops.get(1).copied().and_then(immediate);
        if mov && DX.contains(&ops[0]) && imm.is_some_and(|v| COM1.contains(&v)) {
            s.findings
                .push(format!("a COM1 port moved into {}: {}", ops[0], at()));
        }
        // A direct call or jump names its target as its one operand.
        let branch = mnemonic == "call" || mnemonic.starts_with('j');
        let target = if branch && ops.len() == 1 {
            immediate(ops[0])
        } else {
            None
        };
        if let Some(t) = target.filter(|&t| in_io(t)) {
            if may_call(addr) {
                s.io_calls += 1;
            } else if io_at(addr) != io_at(t) {
                // A jump inside one of io.rs's functions is its own.
                s.findings.push(format!(
                    "io.rs's function called from a function that may not call it: {}",
                    at()
                ));
            }
        }
        for v in numbers(text) {
            if in_io(v) && Some(v) != target {
                s.findings.push(format!(
                    "io.rs's address {v:#x} other than as a call's or jump's target: {}",
                    at()
                ));
            }
        }
        if target.is_some_and(in_io)
            && let Some(port) = port_arg.filter(|p| COM1.contains(p))
        {
            s.findings.push(format!(
                "io.rs's function called with port {port:#x}: {}",
                at()
            ));
        }
        port_arg = match mnemonic {
            // After a call the argument registers are lost; after these, the
            // next instruction is reached from somewhere else.
            "call" | "jmp" | "ret" | "ud2" | "iretq" | "sysretq" => None,
            _ if mov && PORT_ARG.contains(&ops[0]) => imm,
            "cmp" | "test" | "push" | "bt" => port_arg,
            _ if PORT_ARG.contains(&ops[0]) => None,
            // String instructions move rdi; exchanges write both operands.
            m if STRING_OPS.contains(&m) => None,
            m if (m.contains("xchg") || m == "xadd")
                && ops.iter().any(|o| PORT_ARG.contains(o)) =>
            {
                None
            }
            _ => port_arg,
        };
    }
    s
}

/// io.rs's functions in `symbols` (`llvm-objdump --syms --demangle`):
/// their address ranges.
fn io_functions(symbols: &str) -> Vec<Range<u64>> {
    symbols
        .lines()
        .filter_map(Symbol::parse)
        .filter(|sym| sym.function && sym.size > 0 && sym.name.starts_with(IO_MODULE))
        .map(|sym| sym.addr..sym.addr + sym.size)
        .collect()
}

/// A symbol's name without the ` (.llvm.123)` suffix the demangler gives
/// a local that LLVM renamed.
fn base_name(name: &str) -> &str {
    name.strip_suffix(')')
        .and_then(|n| n.rsplit_once(" (."))
        .map_or(name, |(n, _)| n)
}

/// What a scan of the kernel's data found.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Data {
    /// Bytes scanned.
    pub bytes: usize,
    pub findings: Vec<String>,
}

/// Scans the kernel's data for the addresses of io.rs's functions: every
/// allocated section the file holds bytes for, but code, which the
/// listing covers, and [`ROOT_IMAGE`]. A function pointer to one of them,
/// in a table or a static, would be such an address, at any alignment.
/// `None` if `elf` is not a 64-bit little-endian ELF whose section headers
/// can be read.
pub fn data(symbols: &str, elf: &[u8]) -> Option<Data> {
    const SHF_ALLOC: u64 = 2;
    const SHF_EXECINSTR: u64 = 4;
    let io = io_functions(symbols);
    let mut d = Data::default();
    for sec in sections(elf)? {
        if sec.flags & SHF_ALLOC == 0 || sec.flags & SHF_EXECINSTR != 0 || sec.name == ROOT_IMAGE {
            continue;
        }
        d.bytes += sec.bytes.len();
        for (i, w) in sec.bytes.windows(8).enumerate() {
            let v = u64::from_le_bytes(w.try_into().unwrap());
            if io.iter().any(|r| r.contains(&v)) {
                d.findings.push(format!(
                    "io.rs's address {v:#x} stored in {} at {:#x}",
                    sec.name,
                    sec.addr + i as u64
                ));
            }
        }
    }
    Some(d)
}

/// One section of an ELF file.
struct Section<'a> {
    name: &'a str,
    flags: u64,
    addr: u64,
    /// Its bytes in the file; none for `SHT_NOBITS`.
    bytes: &'a [u8],
}

/// The sections of a 64-bit little-endian ELF file, from its section
/// headers and their string table.
fn sections(elf: &[u8]) -> Option<Vec<Section<'_>>> {
    const SHT_NOBITS: u32 = 8;
    let bytes = |at: usize, n: usize| elf.get(at..at.checked_add(n)?);
    let u16_at = |at| Some(u16::from_le_bytes(bytes(at, 2)?.try_into().ok()?));
    let u32_at = |at| Some(u32::from_le_bytes(bytes(at, 4)?.try_into().ok()?));
    let u64_at = |at| Some(u64::from_le_bytes(bytes(at, 8)?.try_into().ok()?));
    let size = |v: u64| usize::try_from(v).ok();
    // ELFCLASS64, ELFDATA2LSB.
    if bytes(0, 6)? != b"\x7fELF\x02\x01" {
        return None;
    }
    let shoff = size(u64_at(0x28)?)?;
    let (entsize, count, names) = (u16_at(0x3A)?, u16_at(0x3C)?, u16_at(0x3E)?);
    let header = |i: u16| shoff.checked_add(usize::from(i) * usize::from(entsize));
    let strtab = size(u64_at(header(names)?.checked_add(0x18)?)?)?;
    let mut out = Vec::new();
    for i in 0..count {
        let h = header(i)?;
        let name = elf.get(strtab.checked_add(size(u32_at(h)?.into())?)?..)?;
        let name = std::str::from_utf8(&name[..name.iter().position(|&b| b == 0)?]).ok()?;
        out.push(Section {
            name,
            flags: u64_at(h + 8)?,
            addr: u64_at(h + 0x10)?,
            bytes: if u32_at(h + 4)? == SHT_NOBITS {
                &[]
            } else {
                bytes(size(u64_at(h + 0x18)?)?, size(u64_at(h + 0x20)?)?)?
            },
        });
    }
    Some(out)
}

/// Every number in an instruction's text, as far as the first `<symbol>`
/// objdump adds: hex as objdump prints it, or decimal, and one after a
/// `-` as the two's complement it stands for, so that a sign-extended
/// 32-bit address (`[8*rcx - 0x7fff53f0]`) reads as the address. Digits
/// inside a register name (`r14d`, `xmm0`) are not numbers.
fn numbers(text: &str) -> Vec<u64> {
    let text = text.split('<').next().unwrap_or("");
    let b = text.as_bytes();
    let mut out = Vec::new();
    let mut negative = false;
    let mut i = 0;
    while i < b.len() {
        let in_word = i > 0 && (b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_');
        match b[i] {
            b'-' => negative = true,
            b' ' | b'\t' => {}
            c if c.is_ascii_digit() && !in_word => {
                let hex = b[i..].starts_with(b"0x");
                let start = if hex { i + 2 } else { i };
                let digits = b[start..]
                    .iter()
                    .take_while(|c| {
                        if hex {
                            c.is_ascii_hexdigit()
                        } else {
                            c.is_ascii_digit()
                        }
                    })
                    .count();
                let radix = if hex { 16 } else { 10 };
                if let Ok(v) = u64::from_str_radix(&text[start..start + digits], radix) {
                    out.push(if negative { v.wrapping_neg() } else { v });
                }
                negative = false;
                i = start + digits;
                continue;
            }
            _ => negative = false,
        }
        i += 1;
    }
    out
}

/// One line of `llvm-objdump --syms`.
struct Symbol<'a> {
    addr: u64,
    size: u64,
    function: bool,
    name: &'a str,
}

impl<'a> Symbol<'a> {
    /// `ffffffff80009080 l     F .text\t0000000000000006 .hidden <name>`.
    fn parse(line: &'a str) -> Option<Self> {
        let (left, right) = line.split_once('\t')?;
        let words: Vec<&str> = left.split_whitespace().collect();
        let (&addr, rest) = words.split_first()?;
        let flags = rest.get(..rest.len().checked_sub(1)?)?;
        let (size, name) = right.split_once(' ')?;
        let name = [".hidden ", ".protected ", ".internal "]
            .iter()
            .fold(name, |n, p| n.strip_prefix(p).unwrap_or(n));
        Some(Symbol {
            addr: u64::from_str_radix(addr, 16).ok()?,
            size: u64::from_str_radix(size, 16).ok()?,
            function: flags.iter().any(|f| f.contains('F')),
            name,
        })
    }
}

/// The function a listing line starts: `ffffffff80009080 <name>:`.
fn header(line: &str) -> Option<&str> {
    let (addr, rest) = line.split_once(" <")?;
    u64::from_str_radix(addr, 16).ok()?;
    rest.strip_suffix(">:")
}

/// An instruction's address and text: `ffffffff80009084: \tout\tdx, al`.
fn instruction(line: &str) -> Option<(u64, &str)> {
    let (addr, text) = line.split_once(':')?;
    let addr = u64::from_str_radix(addr.trim_start(), 16).ok()?;
    (text.starts_with(char::is_whitespace) && !text.trim().is_empty()).then_some((addr, text))
}

/// An instruction's mnemonic, past any prefix, and its operands, without
/// the `# comment` or `<symbol>` objdump adds.
fn split(text: &str) -> (&str, &str) {
    let mut rest = text.trim();
    loop {
        let (word, tail) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
        rest = tail.trim_start();
        if !PREFIXES.contains(&word) || rest.is_empty() {
            let end = rest.find(['#', '<']).unwrap_or(rest.len());
            return (word, rest[..end].trim());
        }
    }
}

/// An operand that is a number: hex as objdump prints it, or decimal.
fn immediate(op: &str) -> Option<u64> {
    match op.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => op.parse().ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Three io.rs functions and their callers, as llvm-objdump 23 prints
    /// a release kernel built from M7's tree.
    const SYMBOLS: &str = "\
kernel:\tfile format elf64-x86-64

SYMBOL TABLE:
0000000000000000 l    df *ABS*\t0000000000000000 07knga48gagpujek8ccpl84o9
ffffffff80005130 l     F .text\t0000000000000100 .hidden kernel::arch::x86_64::pic::init
ffffffff80009070 l     F .text\t0000000000000004 .hidden kernel::arch::x86_64::io::inb
ffffffff80009080 l     F .text\t0000000000000006 .hidden kernel::arch::x86_64::io::outb
ffffffff80009090 l     F .text\t0000000000000006 .hidden kernel::arch::x86_64::io::outl
ffffffff800029b0 l     F .text\t0000000000000144 .hidden <l4core::cap::Cap as core::fmt::Debug>::fmt (.llvm.7137323558937314377)
ffffffff80078000 l     O .bss\t0000000000000001 .hidden kernel::arch::x86_64::rootimage::TAKEN
";

    const LISTING: &str = "\
kernel:\tfile format elf64-x86-64

Disassembly of section .text:

ffffffff80005130 <kernel::arch::x86_64::pic::init>:
ffffffff80005130:      \ttest\tedi, edi
ffffffff80005132:      \tje\t0xffffffff800051e4 <kernel::arch::x86_64::pic::init+0xb4>
ffffffff80005139:      \tmov\tedi, 0x20
ffffffff8000513e:      \tmov\tesi, 0x11
ffffffff80005143:      \tcall\t0xffffffff80009080 <kernel::arch::x86_64::io::outb>
ffffffff800051cf:      \tmov\tedi, 0x21
ffffffff800051d4:      \tcall\t0xffffffff80009070 <kernel::arch::x86_64::io::inb>
ffffffff800051d9:      \tmov\tedi, 0xa1
ffffffff800051de:      \tpop\trax
ffffffff800051df:      \tjmp\t0xffffffff80009070 <kernel::arch::x86_64::io::inb>
ffffffff800051e4:      \tret
ffffffff800051e5:      \tint3
ffffffff800051e6:      \tcmp\trsi, 0x3ff
ffffffff800051ed:      \tmov\tqword ptr [rsp + 0x3f8], 0x0
ffffffff800051f9:      \tlea\tedx, [rip + 0x3f8]      # 0x43a <g+0x3e5>
ffffffff80005200:      \tjb\t0xffffffff80008b49 <l4core::vspace::paging::map_boot_tables::<kernel::arch::x86_64::objects::Objects, core::iter::adapters::chain::Chain<A, B>>+0x3f9>
ffffffff80005206:      \tmov\teax, 0x3f8
ffffffff8000520b:      \tmov\tedx, 0x3f7
\t\t...

ffffffff80009070 <kernel::arch::x86_64::io::inb>:
ffffffff80009070:      \tmov\tedx, edi
ffffffff80009072:      \tin\tal, dx
ffffffff80009073:      \tret
ffffffff80009074:      \tint3

ffffffff80009080 <kernel::arch::x86_64::io::outb>:
ffffffff80009080:      \tmov\teax, esi
ffffffff80009082:      \tmov\tedx, edi
ffffffff80009084:      \tout\tdx, al
ffffffff80009085:      \tret

ffffffff80009090 <kernel::arch::x86_64::io::outl>:
ffffffff80009090:      \tmov\teax, esi
ffffffff80009092:      \tmov\tedx, edi
ffffffff80009094:      \tout\tdx, eax
ffffffff80009095:      \tret
";

    /// `LISTING` with `lines` added to the end of `pic::init`, which its
    /// symbol's size covers to `0xffffffff80005230`.
    fn planted(lines: &str) -> Scan {
        let at = LISTING.find("\t\t...").unwrap();
        let listing = format!("{}{lines}\n{}", &LISTING[..at], &LISTING[at..]);
        scan(SYMBOLS, &listing)
    }

    #[test]
    fn a_clean_listing_passes() {
        let s = scan(SYMBOLS, LISTING);
        assert_eq!(
            s,
            Scan {
                instructions: 30,
                io_functions: 3,
                io_ins: 1,
                io_outs: 2,
                io_calls: 3,
                findings: vec![],
            }
        );
    }

    /// `LISTING` with a function `name` at `0xffffffff80006000`, 0x40
    /// bytes, holding `lines`.
    fn with_function(name: &str, lines: &str) -> Scan {
        let symbols =
            format!("{SYMBOLS}ffffffff80006000 l     F .text\t0000000000000040 .hidden {name}\n");
        let at = LISTING.find("\nffffffff80009070 <").unwrap() + 1;
        let listing = format!(
            "{}ffffffff80006000 <{name}>:\n{lines}\n\n{}",
            &LISTING[..at],
            &LISTING[at..]
        );
        scan(&symbols, &listing)
    }

    #[test]
    fn io_rs_is_called_only_from_the_three_callers() {
        let calls = "ffffffff80006004:      \tcall\t0xffffffff80009080 <kernel::arch::x86_64::io::outb>\n\
                     ffffffff80006010:      \tje\t0xffffffff80009070 <kernel::arch::x86_64::io::inb>\n\
                     ffffffff80006016:      \tjmp\t0xffffffff80009090 <kernel::arch::x86_64::io::outl>";
        for name in IO_CALLERS {
            let s = with_function(name, calls);
            assert_eq!((s.io_calls, &s.findings[..]), (6, &[][..]), "{name}");
            // LLVM's suffix for a renamed local.
            let s = with_function(&format!("{name} (.llvm.14046764917069186953)"), calls);
            assert_eq!((s.io_calls, &s.findings[..]), (6, &[][..]), "{name}");
        }
        for name in [
            "kernel::arch::x86_64::com::put",
            "kernel::arch::x86_64::init",
            "kernel::arch::x86_64::pic::init::helper",
            "<kernel::arch::x86_64::objects::Objects as l4core::ioport::IoPorts>::port_in.specialized.1",
            "l4core::ioport::invoke_port::<kernel::arch::x86_64::objects::Objects>",
        ] {
            let s = with_function(name, calls);
            assert_eq!(s.io_calls, 3, "{name}: pic::init's");
            assert_eq!(s.findings.len(), 3, "{name}: {:?}", s.findings);
            for (f, addr) in s.findings.iter().zip(["80006004", "80006010", "80006016"]) {
                assert!(
                    f.starts_with("io.rs's function called from a function that may not call it: ")
                        && f.contains(&format!("0xffffffff{addr} in {name}: ")),
                    "{f}"
                );
            }
        }
        // A call to a function that is not io.rs's is no call to io.rs,
        // and a jump inside one of io.rs's functions is its own.
        let s = with_function("f", "ffffffff80006004:      \tcall\t0xffffffff80009088 <g>");
        assert_eq!(s.findings, Vec::<String>::new());
        let listing = LISTING.replace(
            "ffffffff80009073:      \tret",
            "ffffffff80009073:      \tjne\t0xffffffff80009070 <kernel::arch::x86_64::io::inb>",
        );
        assert_eq!(scan(SYMBOLS, &listing).findings, Vec::<String>::new());
        // But a jump from one into another is a call from io.rs.
        let listing = LISTING.replace(
            "ffffffff80009073:      \tret",
            "ffffffff80009073:      \tjmp\t0xffffffff80009080 <kernel::arch::x86_64::io::outb>",
        );
        assert_eq!(scan(SYMBOLS, &listing).findings.len(), 1);
    }

    #[test]
    fn io_rs_s_addresses_appear_only_as_branch_targets() {
        for line in [
            // A function pointer, rip-relative: objdump names the target.
            "lea\trax, [rip + 0x3f4a]      # 0xffffffff80009080 <kernel::arch::x86_64::io::outb>",
            // Sign-extended 32-bit immediates and displacements.
            "mov\trax, -0x7fff6f80",
            "mov\tqword ptr [rsp + 0x8], -0x7fff6f70",
            "cmp\trax, -0x7fff6f7c",
            "push\t-0x7fff6f90",
            "mov\trax, qword ptr [8*rcx - 0x7fff6f80]",
            "movabs\trax, 0xffffffff80009084",
            "mov\trax, -2147446656",
            // An indirect call through io.rs's code is no direct call.
            "call\tqword ptr [rip + 0x3f4a]      # 0xffffffff80009070 <kernel::arch::x86_64::io::inb>",
        ] {
            let s = planted(&format!("ffffffff80005210:      \t{line}"));
            assert_eq!(s.findings.len(), 1, "{line}: {:?}", s.findings);
            assert!(
                s.findings[0].starts_with("io.rs's address 0xffffffff800090")
                    && s.findings[0].contains("other than as a call's or jump's target"),
                "{line}: {:?}",
                s.findings
            );
        }
        // Next to io.rs, and inside a symbol annotation, is not io.rs.
        for line in [
            "lea\trax, [rip + 0x3f4a]      # 0xffffffff80009086 <x>",
            "mov\trax, -0x7fff6f7a",
            "call\t0xffffffff80001000 <f+0xffffffff80009080>",
            "mov\tr14d, 0x9080",
        ] {
            let s = planted(&format!("ffffffff80005210:      \t{line}"));
            assert_eq!(s.findings, Vec::<String>::new(), "{line}");
        }
    }

    #[test]
    fn finds_in_and_out_outside_io_rs() {
        for line in [
            "ffffffff80005210:      \tout\tdx, al",
            "ffffffff80005210:      \tout\t0x80, al",
            "ffffffff80005210:      \tin\teax, dx",
            "ffffffff80005210:      \tin\tal, 0x80",
            "ffffffff80005210:      \trep\t\toutsb\tdx, byte ptr [rsi]",
            "ffffffff80005210:      \trep\t\tinsd\tdword ptr es:[rdi], dx",
            "ffffffff80005210:      \toutsw\tdx, word ptr [rsi]",
            "ffffffff80005210:      \tinsb\tbyte ptr es:[rdi], dx",
        ] {
            let s = planted(line);
            assert_eq!(s.findings.len(), 1, "{line:?}: {:?}", s.findings);
            assert!(
                s.findings[0].contains("outside io.rs")
                    && s.findings[0]
                        .contains("0xffffffff80005210 in kernel::arch::x86_64::pic::init"),
                "{:?}",
                s.findings
            );
        }
    }

    #[test]
    fn io_rs_is_its_functions_bounds_not_the_header_above() {
        // Past `outl`'s 6 bytes, though no header says so.
        let listing = format!("{LISTING}ffffffff80009096:      \tout\tdx, al\n");
        let s = scan(SYMBOLS, &listing);
        assert_eq!(s.findings.len(), 1, "{:?}", s.findings);
        assert!(s.findings[0].contains("in kernel::arch::x86_64::io::outl"));
    }

    #[test]
    fn finds_com1_ports_moved_into_dx() {
        for (line, reg) in [
            ("ffffffff80005210:      \tmov\tdx, 0x3f8", "dx"),
            ("ffffffff80005210:      \tmov\tedx, 0x3ff", "edx"),
            ("ffffffff80005210:      \tmov\trdx, 0x3fb", "rdx"),
            ("ffffffff80005210:      \tmovabs\trdx, 0x3fa", "rdx"),
            ("ffffffff80005210:      \tmov\tedx, 1021", "edx"),
        ] {
            let s = planted(line);
            assert_eq!(
                s.findings,
                [format!(
                    "a COM1 port moved into {reg}: 0xffffffff80005210 in \
                     kernel::arch::x86_64::pic::init: {}",
                    line.split_once(":      \t").unwrap().1.replace('\t', " ")
                )],
                "{line:?}"
            );
        }
    }

    #[test]
    fn finds_calls_to_io_rs_with_a_com1_port() {
        let call_outb =
            "ffffffff80005220:      \tcall\t0xffffffff80009080 <kernel::arch::x86_64::io::outb>";
        let tail_inb =
            "ffffffff80005220:      \tjmp\t0xffffffff80009070 <kernel::arch::x86_64::io::inb>";
        for (set, call) in [
            ("mov\tedi, 0x3f8", call_outb),
            ("mov\tdi, 0x3fd", tail_inb),
            ("mov\trdi, 0x3ff", call_outb),
        ] {
            let lines = format!(
                "ffffffff80005210:      \t{set}\n\
                 ffffffff80005215:      \tmov\tesi, 0x41\n\
                 ffffffff80005218:      \tcmp\tedi, 0x0\n\
                 ffffffff8000521b:      \tje\t0xffffffff80005220 <kernel::arch::x86_64::pic::init+0xf0>\n\
                 {call}"
            );
            let s = planted(&lines);
            assert_eq!(s.findings.len(), 1, "{set}: {:?}", s.findings);
            assert!(
                s.findings[0].starts_with("io.rs's function called with port 0x3f"),
                "{:?}",
                s.findings
            );
        }
    }

    #[test]
    fn a_port_argument_overwritten_or_lost_is_not_com1() {
        for between in [
            "mov\tedi, ebx",
            "mov\tedi, 0x20",
            "lea\trdi, [rsp + 0x8]",
            "pop\trdi",
            "xor\tedi, edi",
            "call\t0xffffffff80001000 <core::fmt::write>",
            "ret",
            "rep\t\tstosb\tbyte ptr es:[rdi], al",
            "xchg\teax, edi",
        ] {
            let lines = format!(
                "ffffffff80005210:      \tmov\tedi, 0x3f8\n\
                 ffffffff80005215:      \t{between}\n\
                 ffffffff80005220:      \tcall\t0xffffffff80009080 <kernel::arch::x86_64::io::outb>"
            );
            assert_eq!(planted(&lines).findings, Vec::<String>::new(), "{between}");
        }
        // A COM1 number passed to some other function is not a port.
        let lines = "ffffffff80005210:      \tmov\tedi, 0x3f8\n\
                     ffffffff80005220:      \tcall\t0xffffffff80001000 <core::fmt::write>";
        assert_eq!(planted(lines).findings, Vec::<String>::new());
        // Nor does it carry over into the next function.
        let symbols = format!(
            "{SYMBOLS}ffffffff80009068 l     F .text\t0000000000000008 .hidden kernel::arch::x86_64::exit\n"
        );
        let listing = LISTING.replace(
            "ffffffff80009070 <kernel",
            "ffffffff80009060:      \tmov\tedi, 0x3f8\n\nffffffff80009068 <kernel::arch::x86_64::exit>:\n\
             ffffffff80009068:      \tjmp\t0xffffffff80009070 <kernel::arch::x86_64::io::inb>\n\n\
             ffffffff80009070 <kernel",
        );
        assert_eq!(scan(&symbols, &listing).findings, Vec::<String>::new());
    }

    #[test]
    fn finds_serial_symbols() {
        let symbols = format!(
            "{SYMBOLS}ffffffff80015f30 l     F .text\t0000000000000056 .hidden kernel::arch::x86_64::serial::init\n\
             ffffffff80015f90 g     O .data\t0000000000000008 SERIAL_PORT\n"
        );
        assert_eq!(
            scan(&symbols, LISTING).findings,
            [
                "symbol kernel::arch::x86_64::serial::init",
                "symbol SERIAL_PORT"
            ]
        );
    }

    #[test]
    fn parses_symbols_and_instructions() {
        let sym = Symbol::parse(
            "ffffffff800029b0 l     F .text\t0000000000000144 .hidden <A as B>::fmt (.llvm.71)",
        )
        .unwrap();
        assert_eq!(
            (sym.addr, sym.size, sym.function, sym.name),
            (0xffffffff800029b0, 0x144, true, "<A as B>::fmt (.llvm.71)")
        );
        let data = Symbol::parse("ffffffff80078000 g     O .bss\t0000000000000001 TAKEN").unwrap();
        assert!(!data.function);
        assert!(Symbol::parse("SYMBOL TABLE:").is_none());
        assert_eq!(
            header("ffffffff80009070 <kernel::arch::x86_64::io::inb>:"),
            Some("kernel::arch::x86_64::io::inb")
        );
        assert_eq!(header("Disassembly of section .text:"), None);
        assert_eq!(instruction("Disassembly of section .text:"), None);
        assert_eq!(instruction("kernel:\tfile format elf64-x86-64"), None);
        assert_eq!(
            split("\trep\t\toutsb\tdx, byte ptr [rsi]"),
            ("outsb", "dx, byte ptr [rsi]")
        );
        assert_eq!(
            split("\tlea\tedx, [rip + 0x3f8]      # 0x43a <g>"),
            ("lea", "edx, [rip + 0x3f8]")
        );
        assert_eq!(
            split("\tjmp\t0xffffffff80009070 <io::inb>"),
            ("jmp", "0xffffffff80009070")
        );
        assert_eq!(split("\tret"), ("ret", ""));
        assert_eq!(split("\tlock"), ("lock", ""));
        assert_eq!(immediate("0x3f8"), Some(0x3f8));
        assert_eq!(immediate("1016"), Some(1016));
        assert_eq!(immediate("edx"), None);
        assert_eq!(immediate("qword ptr [rsp + 0x3f8]"), None);
        assert_eq!(
            numbers("\tmov\tr15d, byte ptr [8*r14 - 0x7ffc8b80]      # 0x43a <g+0x3e5>"),
            [8, 0xffffffff80037480, 0x43a]
        );
        assert_eq!(numbers("\tmov\teax, -1"), [u64::MAX]);
        assert_eq!(numbers("\tcvtsi2sd\txmm0, rax"), Vec::<u64>::new());
        assert_eq!(numbers("\tmov\tedx, 1021"), [1021]);
        assert_eq!(base_name("<A as B>::fmt (.llvm.71)"), "<A as B>::fmt");
        assert_eq!(base_name("a::b"), "a::b");
        assert_eq!(base_name("<(u8, u16) as T>::f"), "<(u8, u16) as T>::f");
    }

    /// A 64-bit ELF with the sections `(name, type, flags, address,
    /// bytes)`, and its section-name table last.
    fn elf(sections: &[(&str, u32, u64, u64, &[u8])]) -> Vec<u8> {
        let mut names = vec![0u8];
        let mut body = Vec::new();
        let mut headers = vec![[0u8; 64]];
        let base = 64;
        let mut name_at = Vec::new();
        for (name, ..) in sections.iter().chain([&(".shstrtab", 3, 0, 0, &[][..])]) {
            name_at.push(names.len() as u32);
            names.extend_from_slice(name.as_bytes());
            names.push(0);
        }
        for (i, &(_, kind, flags, addr, bytes)) in sections.iter().enumerate() {
            let mut h = [0u8; 64];
            h[0..4].copy_from_slice(&name_at[i].to_le_bytes());
            h[4..8].copy_from_slice(&kind.to_le_bytes());
            h[8..16].copy_from_slice(&flags.to_le_bytes());
            h[16..24].copy_from_slice(&addr.to_le_bytes());
            h[24..32].copy_from_slice(&((base + body.len()) as u64).to_le_bytes());
            h[32..40].copy_from_slice(&(bytes.len() as u64).to_le_bytes());
            headers.push(h);
            if kind != 8 {
                body.extend_from_slice(bytes);
            }
        }
        let mut h = [0u8; 64];
        h[0..4].copy_from_slice(&name_at[sections.len()].to_le_bytes());
        h[4..8].copy_from_slice(&3u32.to_le_bytes());
        h[24..32].copy_from_slice(&((base + body.len()) as u64).to_le_bytes());
        h[32..40].copy_from_slice(&(names.len() as u64).to_le_bytes());
        headers.push(h);
        body.extend_from_slice(&names);
        let mut out = vec![0u8; 64];
        out[..6].copy_from_slice(b"\x7fELF\x02\x01");
        let shoff = (base + body.len()) as u64;
        out[0x28..0x30].copy_from_slice(&shoff.to_le_bytes());
        out[0x3A..0x3C].copy_from_slice(&64u16.to_le_bytes());
        out[0x3C..0x3E].copy_from_slice(&(headers.len() as u16).to_le_bytes());
        out[0x3E..0x40].copy_from_slice(&((headers.len() - 1) as u16).to_le_bytes());
        out.extend_from_slice(&body);
        for h in headers {
            out.extend_from_slice(&h);
        }
        out
    }

    #[test]
    fn finds_io_rs_s_addresses_in_data() {
        const AX: u64 = 6;
        const A: u64 = 2;
        const WA: u64 = 3;
        let outb = 0xffffffff80009080u64.to_le_bytes();
        let inside_outl = 0xffffffff80009095u64.to_le_bytes();
        let next_to_outb = 0xffffffff80009086u64.to_le_bytes();
        let mut rodata = vec![7u8; 40];
        rodata[3..11].copy_from_slice(&outb);
        rodata[24..32].copy_from_slice(&next_to_outb);
        let mut words = vec![0u8; 16];
        words[8..].copy_from_slice(&inside_outl);
        let pointer: &[u8] = &outb;
        let file = elf(&[
            (".text", 1, AX, 0xffffffff80000000, pointer),
            (".rodata", 1, A, 0xffffffff80033000, &rodata),
            (".rootimage", 1, A, 0xffffffff80041000, pointer),
            (".data", 1, WA, 0xffffffff80094000, &words),
            (".bss", 8, WA, 0xffffffff80095000, &[0; 16]),
            (".debug_info", 1, 0, 0, pointer),
        ]);
        assert_eq!(
            data(SYMBOLS, &file),
            Some(Data {
                bytes: 56,
                findings: vec![
                    "io.rs's address 0xffffffff80009080 stored in .rodata at 0xffffffff80033003"
                        .into(),
                    "io.rs's address 0xffffffff80009095 stored in .data at 0xffffffff80094008"
                        .into(),
                ],
            })
        );
        let clean = elf(&[(".rodata", 1, A, 0xffffffff80033000, &[1, 2, 3])]);
        assert_eq!(data(SYMBOLS, &clean).map(|d| d.findings.len()), Some(0));
        // Not an ELF, or one cut short.
        assert_eq!(data(SYMBOLS, b"\x7fELF\x01\x01"), None);
        assert_eq!(data(SYMBOLS, &file[..file.len() - 40]), None);
    }

    /// The M7 red team's UART writer
    /// (`docs/redteam/m7-disasm-computed-port.md`): a release kernel with
    /// this function, called at boot, passed `cargo xtask test release` and
    /// wrote its text on COM1. Its port is a base read back from memory
    /// plus an offset, as a driver that keeps its base in a struct computes
    /// it, so no COM1 immediate reaches `dx` or `edi`. llvm-objdump 23's
    /// listing of it (a few alignment `nop`s and the overflow panic path
    /// left out), with io.rs's `inb` and `outb` at that build's addresses.
    const COMPUTED_PORT_SYMBOLS: &str = "\
ffffffff8000ac10 l     F .text\t0000000000000006 .hidden kernel::arch::x86_64::io::outb
ffffffff8000abe0 l     F .text\t0000000000000004 .hidden kernel::arch::x86_64::io::inb
ffffffff8000cf10 l     F .text\t000000000000007f .hidden kernel::arch::x86_64::redteam_uart (.llvm.14046764917069186953)
";
    const COMPUTED_PORT_LISTING: &str = "\
ffffffff8000abe0 <kernel::arch::x86_64::io::inb>:
ffffffff8000abe0:      \tmov\tedx, edi
ffffffff8000abe2:      \tin\tal, dx
ffffffff8000abe3:      \tret
ffffffff8000ac10 <kernel::arch::x86_64::io::outb>:
ffffffff8000ac10:      \tmov\tedx, edi
ffffffff8000ac12:      \tmov\teax, esi
ffffffff8000ac14:      \tout\tdx, al
ffffffff8000ac15:      \tret
ffffffff8000cf10 <kernel::arch::x86_64::redteam_uart (.llvm.14046764917069186953)>:
ffffffff8000cf17:      \tmov\tword ptr [rsp + 0x6], 0x3f8
ffffffff8000cf1e:      \tlea\trax, [rsp + 0x6]
ffffffff8000cf23:      \tmovzx\tebx, word ptr [rsp + 0x6]
ffffffff8000cf28:      \tcmp\tbx, -0x6
ffffffff8000cf2c:      \tja\t0xffffffff8000cf83 <kernel::arch::x86_64::redteam_uart (.llvm.14046764917069186953)+0x73>
ffffffff8000cf2e:      \tlea\tebp, [rbx + 0x5]
ffffffff8000cf31:      \tmov\teax, 0x1
ffffffff8000cf36:      \txor\tr14d, r14d
ffffffff8000cf40:      \tmovzx\tr15d, byte ptr [r14 - 0x7ffc8b80]
ffffffff8000cf48:      \tmov\tr14, rax
ffffffff8000cf50:      \tmov\tedi, ebp
ffffffff8000cf52:      \tcall\t0xffffffff8000abe0 <kernel::arch::x86_64::io::inb>
ffffffff8000cf57:      \ttest\tal, 0x20
ffffffff8000cf59:      \tje\t0xffffffff8000cf50 <kernel::arch::x86_64::redteam_uart (.llvm.14046764917069186953)+0x40>
ffffffff8000cf5b:      \tmovzx\tesi, r15b
ffffffff8000cf5f:      \tmov\tedi, ebx
ffffffff8000cf61:      \tcall\t0xffffffff8000ac10 <kernel::arch::x86_64::io::outb>
ffffffff8000cf82:      \tret
";

    /// The guarantee: a release kernel with UART code fails the check. The
    /// port rules alone find nothing here, which is the red team's
    /// finding; the call-site rule finds both calls.
    #[test]
    fn a_computed_com1_port_fails_the_check() {
        let s = scan(COMPUTED_PORT_SYMBOLS, COMPUTED_PORT_LISTING);
        assert_eq!(
            (s.io_functions, s.io_ins, s.io_outs, s.io_calls),
            (2, 1, 1, 0)
        );
        let at = "in kernel::arch::x86_64::redteam_uart (.llvm.14046764917069186953): call";
        assert_eq!(
            s.findings,
            [
                format!(
                    "io.rs's function called from a function that may not call it: \
                     0xffffffff8000cf52 {at} 0xffffffff8000abe0 <kernel::arch::x86_64::io::inb>"
                ),
                format!(
                    "io.rs's function called from a function that may not call it: \
                     0xffffffff8000cf61 {at} 0xffffffff8000ac10 <kernel::arch::x86_64::io::outb>"
                ),
            ]
        );
    }

    /// The M7 fix round's re-review: a COM1 writer that reaches the UART
    /// through the IOPort executor, `Objects`' `IoPorts::port_in` and
    /// `port_out`. They are safe trait methods that take any port, so the
    /// writer sits in the kernel crate outside `arch`, with no `unsafe`,
    /// and names COM1 as immediates in `esi`, port_out's port argument. A
    /// release kernel that called it once after `arch::init` passed `cargo
    /// xtask test`'s disassembly check and wrote its text on COM1; only
    /// `release`'s `next:` failed it, because it printed at boot. In a
    /// clean release kernel `l4core::ioport::invoke_port::<Objects>` is
    /// the only caller of `port_in` and `port_out`. llvm-objdump's listing
    /// (the loop and the panic path trimmed), with that build's addresses.
    const EXECUTOR_SYMBOLS: &str = "\
ffffffff8000acb0 l     F .text\t0000000000000004 .hidden kernel::arch::x86_64::io::inb
ffffffff8000ace0 l     F .text\t0000000000000006 .hidden kernel::arch::x86_64::io::outb
ffffffff8001d9a0 l     F .text\t000000000000002a .hidden <kernel::arch::x86_64::objects::Objects as l4core::ioport::IoPorts>::port_in
ffffffff8001d9d0 l     F .text\t0000000000000021 .hidden <kernel::arch::x86_64::objects::Objects as l4core::ioport::IoPorts>::port_out
ffffffff80001560 l     F .text\t00000000000000c2 .hidden kernel::viaexec::put
";
    const EXECUTOR_LISTING: &str = "\
ffffffff80001560 <kernel::viaexec::put>:
ffffffff800015a0:      \tmov\trdi, r15
ffffffff800015a3:      \tmov\tesi, 0x3f8
ffffffff800015a8:      \tmov\tedx, 0x1
ffffffff800015ad:      \tmov\tecx, ebp
ffffffff800015af:      \tcall\t0xffffffff8001d9d0 <<kernel::arch::x86_64::objects::Objects as l4core::ioport::IoPorts>::port_out>
ffffffff800015e5:      \tmov\trdi, r15
ffffffff800015e8:      \tmov\tesi, 0x3fd
ffffffff800015ed:      \tmov\tedx, 0x1
ffffffff800015f2:      \tcall\t0xffffffff8001d9a0 <<kernel::arch::x86_64::objects::Objects as l4core::ioport::IoPorts>::port_in>
ffffffff800015f7:      \ttest\tal, 0x20
ffffffff80001609:      \tret

ffffffff8000acb0 <kernel::arch::x86_64::io::inb>:
ffffffff8000acb0:      \tmov\tedx, edi
ffffffff8000acb2:      \tin\tal, dx
ffffffff8000acb3:      \tret

ffffffff8000ace0 <kernel::arch::x86_64::io::outb>:
ffffffff8000ace0:      \tmov\teax, esi
ffffffff8000ace2:      \tmov\tedx, edi
ffffffff8000ace4:      \tout\tdx, al
ffffffff8000ace5:      \tret

ffffffff8001d9a0 <<kernel::arch::x86_64::objects::Objects as l4core::ioport::IoPorts>::port_in>:
ffffffff8001d9a0:      \tpush\trax
ffffffff8001d9a1:      \tmov\tedi, esi
ffffffff8001d9a3:      \tcmp\tdl, 0x1
ffffffff8001d9ba:      \tcall\t0xffffffff8000acb0 <kernel::arch::x86_64::io::inb>
ffffffff8001d9bf:      \tmovzx\teax, al
ffffffff8001d9c2:      \tpop\trcx
ffffffff8001d9c3:      \tret

ffffffff8001d9d0 <<kernel::arch::x86_64::objects::Objects as l4core::ioport::IoPorts>::port_out>:
ffffffff8001d9d0:      \tmov\tedi, esi
ffffffff8001d9d2:      \tcmp\tdl, 0x1
ffffffff8001d9ea:      \tmov\tesi, ecx
ffffffff8001d9ec:      \tjmp\t0xffffffff8000ace0 <kernel::arch::x86_64::io::outb>
";

    /// The gap: the call-site rule stops at the IOPort executor, whose
    /// callers nothing checks, and the port rules look only at io.rs's
    /// port argument, so the writer above passes.
    #[test]
    fn a_writer_through_the_ioport_executor_passes_the_check() {
        let s = scan(EXECUTOR_SYMBOLS, EXECUTOR_LISTING);
        assert_eq!(
            (s.io_functions, s.io_ins, s.io_outs, s.io_calls),
            (2, 1, 1, 2)
        );
        assert_eq!(s.findings, Vec::<String>::new());
    }

    /// The guarantee the design states ("A release kernel without UART
    /// code"): UART code fails the check whatever path it takes to `in`
    /// and `out`, so both of the writer's calls into the IOPort executor
    /// are findings.
    #[test]
    #[ignore = "M7 fix-round re-review: the IOPort executor's callers are not checked"]
    fn a_writer_through_the_ioport_executor_fails_the_check() {
        let s = scan(EXECUTOR_SYMBOLS, EXECUTOR_LISTING);
        for addr in ["800015af", "800015f2"] {
            let at = format!("0xffffffff{addr} in kernel::viaexec::put: call");
            assert!(
                s.findings.iter().any(|f| f.contains(&at)),
                "{at}: {:?}",
                s.findings
            );
        }
    }
}
