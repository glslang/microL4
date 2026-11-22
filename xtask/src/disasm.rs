//! The release kernel's disassembly check (`docs/design.md`, "A release
//! kernel without UART code"; ADR 0021).
//!
//! `cargo xtask test` disassembles the kernel built without `debug` and
//! fails on
//!
//! - an `in` or `out`, string forms included, outside the functions of
//!   `kernel/src/arch/x86_64/io.rs`;
//! - an immediate in `0x3F8` to `0x3FF`, COM1's ports, moved into `dx`,
//!   `edx` or `rdx`;
//! - a call or jump to one of io.rs's functions whose port argument (`di`,
//!   `edi` or `rdi`) the straight-line code before it set to such an
//!   immediate: those functions take the port as their first argument and
//!   move it into `dx` themselves, so this is how a caller would name COM1;
//! - any symbol whose name contains `serial`.
//!
//! The disassembler is `llvm-objdump` from rustup's `llvm-tools` component,
//! which `tools/setup.sh` adds: the LLVM that compiled the kernel, so it
//! decodes whatever rustc emits, with no crate to add and no ELF symbol
//! reader to write. Failing that, an `llvm-objdump` on `PATH` will do. Its
//! Intel-syntax listing is plain to scan line by line, and its symbol
//! table, with sizes, says which addresses are io.rs's. So that a listing
//! this scanner misreads cannot pass by finding nothing, the check also
//! insists on io.rs's functions with an `in` and an `out` in them.

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

/// What a scan of a listing found.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Scan {
    pub instructions: usize,
    /// io.rs's functions, and the `in` and `out` instructions in them.
    pub io_functions: usize,
    pub io_ins: usize,
    pub io_outs: usize,
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
    let scan = scan(&symbols, &listing);
    let what = format!("{} ({})", rel(kernel), objdump.display());
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
    {
        return Err(format!(
            "the listing of {what} is not one this check can read: {} instructions, \
             {} functions in {IO_MODULE} with {} in and {} out",
            scan.instructions, scan.io_functions, scan.io_ins, scan.io_outs
        )
        .into());
    }
    Ok(format!(
        "disassembly: {} instructions of the release kernel; in and out only in io.rs's {} \
         functions ({} in, {} out), no COM1 port in dx or passed to them, no serial symbol",
        scan.instructions, scan.io_functions, scan.io_ins, scan.io_outs
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
    let mut io = Vec::new();
    for sym in symbols.lines().filter_map(Symbol::parse) {
        if sym.name.to_ascii_lowercase().contains("serial") {
            s.findings.push(format!("symbol {}", sym.name));
        }
        if sym.function && sym.size > 0 && sym.name.starts_with(IO_MODULE) {
            io.push(sym.addr..sym.addr + sym.size);
        }
    }
    s.io_functions = io.len();
    let in_io = |addr: u64| io.iter().any(|r: &Range<u64>| r.contains(&addr));

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
        if (mnemonic == "call" || mnemonic.starts_with('j'))
            && immediate(ops[0]).is_some_and(in_io)
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
ffffffff80005130 l     F .text\t00000000000000b5 .hidden kernel::arch::x86_64::pic::init
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

    /// `LISTING` with `lines` added to the end of `pic::init`.
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
                findings: vec![],
            }
        );
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
        let listing = LISTING.replace(
            "ffffffff80009070 <kernel",
            "ffffffff80009060:      \tmov\tedi, 0x3f8\n\nffffffff80009068 <f>:\n\
             ffffffff80009068:      \tjmp\t0xffffffff80009070 <kernel::arch::x86_64::io::inb>\n\n\
             ffffffff80009070 <kernel",
        );
        assert_eq!(scan(SYMBOLS, &listing).findings, Vec::<String>::new());
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
    }
}
