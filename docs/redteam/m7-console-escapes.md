# M7 red team: a console client's escape sequences rewrite the screen

**Severity:** low. A client cannot read another client's input or move the
focus, but it can make the screen lie about both: it can erase console's
focus status line and forge one, or overwrite lines console showed for other
clients. A user who trusts the screen can then type a secret for the wrong
client.

**Where:** `user/console/src/terminal.rs`, `Terminal::write` and
`Terminal::read` (the prompt), on any VT100-compatible terminal, which is
what QEMU's `-nographic` serial and Hyper-V's named pipe feed.

**Status:** open; not fixed, as the brief asks.

## What breaks

`docs/design.md` ("Output") turns each `\n` of a client's `Write` into
`\r\n` and sends every other byte as it is. So a client's output reaches the
wire with its control bytes intact: CR, BS, ESC and every CSI sequence. Line
ownership and the breaks console inserts keep the bytes of each line
contiguous on the wire, but the terminal executes the sequences, and the
cursor can leave the client's own line:

```
client 2 ("evil") has focus; the screen shows
    [console] focus 2 (evil)
client 2 writes  ESC [1A  ESC [2K  "[console] focus 1 (root)\n"  "root# "  and reads
the screen now shows
    [console] focus 1 (root)
    root# _
```

`ESC [1A` moves up onto console's status line, `ESC [2K` erases it, and the
forged one takes its place. The user, believing root has focus, types into
client 2's Read. The same sequences overwrite any earlier line, another
client's output or input line included (console redraws an input line only
when it next shows it), and an `Attach` name of up to 16 bytes can carry
them into the status line itself. Terminals that answer queries (`ESC [6n`,
and on some an OSC title report) would also feed bytes back into the
focused client's input; console's input parser skips CSI replies, and an
OSC reply's text would be typed as ordinary bytes.

The design's guarantees as written still hold on the wire: routing is a
function of the byte stream, and no client byte falls inside another's
line. What fails is the guarantee as a user sees it: that a client cannot
write into another client's line or appear to change the focus.

## The test

Host tests in `user/console/src/tests/redteam.rs`, over a small VT100 screen
model (printable bytes, CR, LF, BS, `ESC [n A`, `ESC [2K`, `ESC [K`):

- `a_client_s_escape_sequences_reach_the_terminal_unchanged` passes today:
  client 2 forges `[console] focus 1 (root)` over the real status line, the
  screen shows no trace of `focus 2 (evil)`, and the typed `hunter2` goes to
  client 2.
- `a_client_cannot_rewrite_console_s_status_line` states the guarantee and
  fails today; it is `#[ignore]`d so the default run passes. Run it with
  `cargo test -p console -- --ignored`.

How sure: certain for the bytes console emits (the tests run the real
`Terminal`); the screen effect depends on the terminal, and every
VT100-compatible one, xterm and the Windows console included, executes
these two sequences.

## Proposed fix

Filter client bytes in `Terminal::write`, `Terminal::read`'s prompt and
`Terminal::attach`'s name: pass `0x20`-`0x7E`, `\n` (as `\r\n`) and perhaps
`\t`; show every other byte visibly (`^[` for ESC, `\xNN`) or drop it. M8's
raw mode, which must pass escape sequences for `term`, can lift the filter
only for the focused client in raw mode. Record in `docs/design.md`
("Output") that client output is filtered and why, and add the filtered
bytes to the proptest's model. A distinct mark on status lines (a prefix no
client can print once filtered) is then optional.
