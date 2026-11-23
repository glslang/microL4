# M8 red team: a reply cut short at the input queue's end turns a typed byte into a key

**Severity:** low. Only term's own client can ask for a reply, so the
client can only confuse itself, and only while its input queue is nearly
full; but it needs no hostile intent, only an app that asks DSR or DA
while a paste waits unread, and the key it gets is one the user did not
type. A VT100 never sends half a reply.

**Where:** `user/term/src/server.rs`, `Input::reply` and `Input::push`;
`docs/design.md`, "Input and the term protocol" ("past that they are
dropped and counted").

**Status:** fixed in the M8 fix round, commit `e4fca76` ("term: a reply
is queued whole or dropped whole, before an unfinished key";
[The fix](#the-fix)). Found by the M8 red team at `e9b9afb`.

## What breaks

The input queue holds the keys `ReadRaw` brings and the replies DSR and DA
queue, 512 bytes in all. `Input::push` queues as many bytes of a reply as
fit and drops the rest, so a reply that meets a nearly full queue leaves a
prefix of itself, and the host test
`bytes_past_the_queues_512_are_dropped_and_counted` pins that behaviour:
with 510 bytes queued, DSR 6 queues `ESC [` and drops `1;1R`. The next byte
typed then follows `ESC [` in the client's stream:

```
510 bytes typed, not yet read (a paste)        x x ... x
the client writes ESC [ 6 n                    x x ... x ESC [
the user types A (an unknown key to tui)       x x ... x ESC [ A
```

`ESC [ A` is what a VT100's Up key sends, and what tui's decoder
(`docs/design.md`, "`tui`": "`ESC [ A`, `ESC O A`, `k` | Up") and most
apps read as Up. With DA (`ESC [ ? 1 ; 2 c`) cut to `ESC [`, a typed `B`
becomes Down; cut to `ESC [ ?` or `ESC [ 1`, the next typed byte is
swallowed as a sequence's final byte, so a typed `q` no longer quits. The
counts stay honest (`Stats` MR5 counts the dropped bytes), but the
guarantee the brief states, that DSR and DA replies cannot be used to
inject keys, fails: the client reads a key that neither the user nor term
meant, assembled from half a reply and a typed byte.

The decoder's state survives the end of a `Read`, as it must for a key
split by console, so reading the queue between the reply and the key does
not help; and the client cannot tell a cut reply from a typed `ESC [`.

## The test

`a_reply_cut_short_never_turns_a_typed_byte_into_a_key` in
`user/term/src/tests/redteam.rs`, `#[ignore]`d until the fix. It drives a
host `term::Server` over a `Session`, as `term::run` does: 510 keys
queued, the client's `Write` of DSR 6 (then, in a second run, DA), a
`Read`, one typed byte, a `Read`. It asserts the guarantee, that the
client reads the typed bytes with the reply whole or not at all between
them, and failed before the fix:

```
the client reads \e[A after the paste: the Up key, which nobody typed
```

It was run with `cargo test -p term --lib redteam -- --ignored`; it passes
now in the default run.

How sure: certain for the bytes term queues (the test runs the real
`Server`, `Session` and parser); that `ESC [ A` decodes as Up is tui's
documented table.

## Proposed fix

Queue a reply whole or not at all: in `Input::reply`, if `bytes.len()`
exceeds the room left, drop all of it and count it in MR5, as a key that
finds the queue full is. Replies are at most 9 bytes, so no reply is ever
lost to a queue with room for it. Keys keep the per-byte rule: they come
from console in arbitrary splits anyway. Update the design's sentence on
the queue's limit ("a reply that does not fit whole is dropped whole"),
change `bytes_past_the_queues_512_are_dropped_and_counted`'s last case
(510 queued: the reply is dropped, MR5 + 6, nothing queued), and un-ignore
the red-team test.

## The fix

M8 fix round, in `user/term/src/server.rs`, as proposed, with a second rule
for what the M8 fresh review found next to it:

- **Whole or not at all.** `Input::reply` queues a reply only if the queue
  has room for all of it; otherwise it drops every byte and counts them in
  `Stats` MR5. MR6 counts only replies queued. Keys keep the per-byte rule.
  `bytes_past_the_queues_512_are_dropped_and_counted` now ends with 510
  queued and DSR 6 dropped whole (MR5 + 6, MR6 unchanged, the queue as it
  was), then with 506 queued and DSR 6 fitting exactly. The red-team test
  is no longer ignored and passes.
- **Before an unfinished key.** Reviewer T showed that a reply queued whole
  can still land inside a key: console hands over what its raw queue holds
  at each `ReadRaw`, so a key can come in two, and a reply queued between
  them cut F5 (`ESC [ 1 5 ~`) into an unknown key, `5` and `~`. Now, if
  the bytes still queued end in an unfinished escape sequence (ESC alone,
  or ESC `[` or ESC `O` with only parameter and intermediate bytes, the
  sequences tui's decoder waits on; `term::server::unfinished`), the reply
  goes before that sequence's ESC, so the key reaches the client whole,
  after it. Host tests: `an_unfinished_key_is_found_from_its_last_esc`,
  `a_reply_goes_before_an_unfinished_key_at_every_split` (F5, `ESC O A`
  and ESC alone split at every point, behind two typed bytes),
  `replies_before_an_unfinished_key_keep_their_order_and_their_limit`, and
  reviewer T's `a_reply_never_lands_inside_a_key_that_came_in_two_read_raws`
  in `user/term/src/tests/review.rs`, no longer ignored.
- **The limit.** Once the client has read a key's first part, those bytes
  have left the queue, and term has no timer to hold a reply back until
  the key ends, so a reply queued before the rest comes still lands inside
  the key. That is the case whenever the client already waits in `Read` as
  the key's first part comes, since term releases it at once. tui never
  asks DSR or DA. `a_reply_lands_inside_a_key_whose_first_part_the_client_has_read`
  records how it behaves.
- `docs/design.md` ("Input and the term protocol") states both rules, the
  limit, MR5 and MR6 as built, that RIS does not clear the input queue (it
  is the client's, not the screen's), and that keys released to a saved
  `Read` whose caller root suspended are lost uncounted.
