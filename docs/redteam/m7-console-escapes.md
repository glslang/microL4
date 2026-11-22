# M7 red team: a console client's escape sequences rewrite the screen

**Severity:** low. A client cannot read another client's input or move the
focus, but it can make the screen lie about both: it can erase console's
focus status line and forge one, or overwrite lines console showed for other
clients. A user who trusts the screen can then type a secret for the wrong
client.

**Where:** `user/console/src/terminal.rs`, `Terminal::write` and
`Terminal::read` (the prompt), on any VT100-compatible terminal, which is
what QEMU's `-nographic` serial and Hyper-V's named pipe feed.

**Status:** fixed in the M7 fix round, commit `8162512` ("console: show a
client's control bytes, do not send them"; [The fix](#the-fix)).

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

- `a_client_s_escape_sequences_reach_the_terminal_unchanged` passed before
  the fix: client 2 forged `[console] focus 1 (root)` over the real status
  line, the screen showed no trace of `focus 2 (evil)`, and the typed
  `hunter2` went to client 2. The fix round turned it into
  `a_client_s_escape_sequences_are_shown_not_obeyed`.
- `a_client_cannot_rewrite_console_s_status_line` states the guarantee; it
  failed before the fix and was `#[ignore]`d. It passes now, and is no
  longer ignored.

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

## The fix

M7 fix round, in `user/console/src/terminal.rs`:

- A client's bytes reach the terminal through `put_shown`: printable ASCII
  and tab as they are, the C0 controls and DEL in caret notation (`^[`,
  `^M`, `^?`), and every byte from `0x80` up as `\xNN` (`console::shown`).
  That covers `Write`'s lines and 512-byte pieces, `Flush`, a `Read`'s
  prompt and the `Attach` name in a status line. The `\r\n` ending a line
  is console's own. M8's raw mode (label `0x125`, still `BadLabel`) is
  where `term`'s bytes would pass as they are.
- `user/console/src/tests/redteam.rs`: the attack now shows its escapes as
  text below the real status line
  (`a_client_s_escape_sequences_are_shown_not_obeyed`), the guarantee passes,
  and `no_client_byte_moves_the_cursor_up` tries the same through a prompt, a
  flush, a 512-byte line and a name.
- `user/console/src/tests.rs`: golden
  `a_clients_control_bytes_are_shown_not_sent` for every byte's form; the
  proptest writes control and arbitrary bytes, shows them by a model of its
  own, and fails any client or prompt byte that reaches the terminal as a
  control byte but tab and the line's CR LF.
- `docs/design.md` ("Output" and the console invariants) states the rule.
- Done in M7 fix round 2: a distinct mark on status lines. console puts
  its own in reverse video (`ESC [7m` before, `ESC [0m` after:
  `console::STATUS_ON` and `STATUS_OFF`), which a client, whose ESC shows
  as `^[`, cannot ask for. A client can still print a line that reads like
  `[console] focus 1 (root)`, but only on a line of its own, below the real
  status line, which it can no longer erase, and in plain text. The screen
  model now keeps reverse video, and the guarantee test
  (`a_client_cannot_rewrite_console_s_status_line`) has the client print
  two look-alikes, one plain and one with its own SGR 7 escapes, and finds
  that only console's status line is in reverse video.
