# Threat Model

## Assumptions

The encrypted mDNS extension operates under the following assumptions:

- All participating peers hold an identical 32-byte PSK
- Communication occurs over LAN multicast (layer 2/3 broadcast domain)
- No key distribution or negotiation protocol is provided; key exchange is the
  application's responsibility
- An attacker can observe all multicast traffic on the LAN segment
- An attacker cannot break XChaCha20-Poly1305 computationally

## Protected

### Passive Eavesdropping — PROTECTED

XChaCha20-Poly1305 encrypts the DNS payload. An observer without the PSK sees
only the 52 bytes of authenticated header (magic, version, flags, sender_id,
session_id, sequence, epoch, random nonce) and opaque ciphertext. Service names,
hostnames, port numbers, IP addresses, and TXT records are not readable.

### Packet Injection and Forgery — PROTECTED

The Poly1305 authentication tag covers the full packet (header + ciphertext or
header + plaintext in auth-only mode). Any packet that does not authenticate
correctly with the PSK is silently dropped. An attacker without the PSK cannot
produce a packet that passes authentication.

### Replay Attacks — PROTECTED for tracked sessions

Each sender numbers its packets with a 64-bit sequence counter (the first
packet carries 1) and stamps them with a random, nonzero 64-bit session ID
drawn once, when the socket is constructed. A restarted sender therefore opens
a new session; sequence numbers are only ever compared within one session. Both
fields sit inside the authenticated header, so neither can be altered without
the PSK.

Each receiver keeps an independent anti-replay sliding window for every
(`sender_id`, session ID) pair it has seen. A packet whose sequence number is
inside its session's window and already marked, or below the window's left
edge, is rejected. The window width is `replay_window_size` (default 64
slots). No packet, whatever its sequence number, ever resets a window.

State is bounded in two places:

- `max_sessions_per_sender` (default 8) windows are kept per sender; when a
  sender opens one more, its least recently used session is evicted.
- `max_senders` (default 256) senders are tracked; when a new sender is seen
  and the table is full, the least recently used sender, with all its
  sessions, is evicted.

**Residual: a packet of an untracked session is accepted once.** The receiver
uses no clock and keeps no persistent state, so it cannot tell a replayed
packet of a session it does not track from a first delivery. A session is
untracked if it

- was never seen by this receiver,
- was evicted by the per-sender session limit (`max_sessions_per_sender`),
- was evicted together with its sender by the sender limit (`max_senders`), or
- was recorded before the receiver restarted (the restarted receiver starts
  with empty state).

An accepted packet of an untracked session makes that session tracked, so
further replays of it are rejected for as long as it stays tracked. An
attacker holding recorded packets from more than `max_sessions_per_sender`
sessions of one sender (or from more than `max_senders` senders) can replay
them in rotation: each replay evicts another session, so recorded packets keep
being accepted, and the evictions can also drop the live session's window, so
recent packets of the live session become replayable once. This thrashing
lasts until key rotation (below). Raising the two limits raises the number of
recordings the attacker needs and the memory spent (see Anti-Replay Details),
but does not remove the residual.

Replay protection rejects duplicates and stale sequence numbers; it does not
bound delay. A packet the receiver has not yet seen, delayed in transit and
delivered later, is accepted if its sequence number is ahead of or inside its
session's window and unmarked.

Key rotation (`update_key()` with a fresh key) is the remedy for recordings:
once a receiver has rotated and its grace period has expired, packets stamped
with an earlier epoch are rejected before any replay check: by epoch, or, for
the epoch just before the current one, by the AEAD verification under the
fresh key. During
the grace period, previous-epoch packets are still subject to the windows
above.

### Content Tampering — PROTECTED

The AEAD tag verification rejects any packet in which the ciphertext, the
plaintext payload (auth-only mode), or the header bytes have been modified in
transit. A single changed bit causes authentication failure.

## Not Protected

### Traffic Analysis — NOT PROTECTED

Multicast packet sizes, inter-packet timing, multicast group membership, and
the sender_id, session_id, sequence, and epoch header fields are observable
without the PSK. An observer can determine how many distinct senders are
active, their relative message frequency, how many packets each has sent in its
current session, when a sender restarted (a new session_id), when the group
rotated keys (a new epoch), and which multicast group address is in use.

### Compromised PSK — NOT PROTECTED

Any peer that obtains the PSK can decrypt all traffic on the multicast group,
inject authenticated packets under any sender_id, and replay previously
captured packets. The security boundary is the PSK itself; the library
provides no mechanism to detect or respond to PSK compromise.

### Forward Secrecy — NOT PROVIDED

XChaCha20-Poly1305 with a static PSK provides no forward secrecy. If an
attacker records multicast traffic and later obtains the PSK (e.g., via
compromise of a peer device), all previously recorded traffic is decryptable.
Key rotation (`update_key()`) limits the exposure window for past traffic to the
period covered by the rotated-away key, but only if previous recordings are not
retained.

### Key Distribution — NOT PROVIDED

The library does not implement Diffie-Hellman key exchange, certificate-based
identity, or any other authenticated key establishment protocol. Bootstrapping
the shared PSK and distributing updated keys after rotation are the
application's responsibility.

### Cleartext Downgrade via accept_cleartext — NOT PROTECTED

`encrypt_options::accept_cleartext = true` forwards packets identified as
cleartext to the application without any authentication. Detection works on
the packet as received:

- A packet that does not start with the 0x4D43 magic bytes is cleartext in
  `magic_byte` and `attempt_decrypt` mode, whatever its size. Any sender on the
  LAN bypasses every confidentiality, integrity, and replay guarantee simply by
  sending such a packet.
- A packet that starts with the magic bytes and is shorter than 44 bytes (the
  shortest header any wire version has used) is cleartext only in
  `attempt_decrypt` mode.
- A packet that starts with the magic bytes and is 44 bytes or longer is never
  delivered as cleartext, whatever its version byte or header contents. It is
  authenticated if it parses as a current-version header (version 0x02) and is
  dropped otherwise or when authentication fails. Consequently a packet of the
  earlier wire version (version 0x01) is rejected in every configuration.

This is an unauthenticated downgrade path: enable it only during migration,
with the understanding that the threat model degrades to plain mDNS for all
accepted cleartext, and disable it once all peers are upgraded.

A related in-band ambiguity exists: a legitimate cleartext DNS packet whose
transaction ID happens to be 0x4D43 starts with the magic bytes. In
`magic_byte` mode it is dropped at every size. In `attempt_decrypt` mode it is
delivered when shorter than 44 bytes and dropped at 44 bytes or more.
Legacy-unicast transaction IDs are arbitrary, so this collision is unavoidable
for in-band detection; the expected impact is one dropped legacy-unicast
exchange per 65536.

### Denial of Service — NOT PROTECTED

An attacker on the LAN can flood the multicast group with malformed or
unauthenticated packets. A packet that starts with the magic bytes, carries the
current version, is at least 68 bytes long (`encrypted_overhead`), and names a
usable epoch incurs an AEAD verification before being dropped; other packets
are classified and dropped without one. Volumetric flooding can exhaust CPU or socket
buffers. The library provides no rate-limiting or DoS mitigation.

### Insider Threat — NOT PROTECTED

Any peer that holds the PSK is fully trusted by the protocol. A compromised
peer can read all traffic, forge messages from any sender_id, and perform
coordinated replay attacks. The PSK grants symmetric access without
per-peer identity or authorization.

## Anti-Replay Details

The anti-replay mechanism uses a left-shift sliding-window bitmap per
(sender, session) pair, following RFC 4303 semantics:

- Bit `i` in the window represents sequence number `max_seq - i`
- A received sequence number `s > max_seq` advances the window left by
  `s - max_seq` positions, clearing vacated bits
- A sequence number inside the window that has already been seen is rejected
- A sequence number to the left of the window (older than `max_seq -
  replay_window_size`) is rejected
- The first packet of a session the receiver does not track opens a window
  positioned at that packet's sequence number and is accepted

No sequence number, however far it jumps, resets a window.

`replay_window_size` (default 64, `uint16_t`) controls the number of
out-of-order packets tolerated per session. The bitmap is sized to the
configured window: each tracked session holds `ceil(replay_window_size / 64)`
`uint64_t` words, i.e. 8 bytes at the default of 64 and 8 KiB at the maximum
of 65535. A tracked sender therefore costs at most

```
max_sessions_per_sender * ceil(replay_window_size / 64) * 8   bytes
```

of bitmap: 64 bytes at the defaults (64, 8), up to 64 KiB per sender with the
default session limit and the maximum window, and about 16 MiB across the
default `max_senders` of 256 in that worst case. Container bookkeeping adds to
these figures. Windows are created as sessions appear, so the worst case is
reached only when every tracked sender has opened that many sessions. A value
of 0 for `replay_window_size` or `max_sessions_per_sender` is rejected at
socket construction. Values of `replay_window_size` beyond a few hundred buy
little on a LAN — UDP multicast reordering rarely exceeds tens of packets —
and only increase memory.

`max_sessions_per_sender` (default 8) bounds the windows kept per sender. A
sender normally has one live session; the others cover earlier boots whose
packets may still be recorded. Evicting the least recently used session
discards its window, which is the source of the accepted-once residual
described under Replay Attacks.

`max_senders` (default 256) limits the number of per-sender state entries held
in memory; 0 fails validation. When a new sender is seen and the table is
full, the least recently used sender is evicted together with its sessions. An
attacker who has recorded packets from more than `max_senders` distinct senders
can replay them to force eviction, and a peer holding the PSK can forge
packets under many `sender_id` values to the same effect; either allows replay
of packets from an evicted sender. This is an accepted trade-off for bounded
memory usage.
