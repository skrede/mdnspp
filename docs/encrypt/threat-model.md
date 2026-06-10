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
only the 44-byte authenticated header (magic, version, flags, sender_id,
sequence, epoch, random nonce) and opaque ciphertext. Service names, hostnames,
port numbers, IP addresses, and TXT records are not readable.

### Packet Injection and Forgery — PROTECTED

The Poly1305 authentication tag covers the full packet (header + ciphertext or
header + plaintext in auth-only mode). Any packet that does not authenticate
correctly with the PSK is silently dropped. An attacker without the PSK cannot
produce a packet that passes authentication.

### Replay Attacks — PROTECTED within a sender session

Each sender maintains a monotonically increasing 64-bit sequence number. Each
receiver maintains a per-sender anti-replay sliding window. Packets whose
sequence number falls inside the window and has already been seen are rejected.
Packets whose sequence number is below the window's left edge are also rejected,
unless the backward distance exceeds the restart threshold (see Anti-Replay
Details). The window width is `replay_window_size` (default 64 slots).

Sequence numbers are per-sender, tracked independently for each `sender_id`.
The receiver tracks up to `max_senders` (default 256) distinct senders; when
this limit is exceeded the least recently used entry is evicted.

The guarantee is scoped to a single sender session (one boot of a sender
process) observed by a continuously running receiver. Restart caveats:

- **Receiver restart**: a restarted receiver starts with empty window state and
  will accept replays of traffic recorded before its restart, for the current
  epoch (and the previous epoch during a grace window).
- **Sender restart / restart heuristic**: a restarted sender resumes at a
  randomized sequence position (top 24 bits from the CSPRNG, low 40 bits zero).
  Receivers interpret a backward jump larger than the restart threshold (2^39)
  as a sender restart and re-initialize that sender's window. Consequence: an
  attacker can replay packets recorded more than 2^39 sequence numbers in the
  past — in practice, packets from an earlier boot of the sender — and they
  will be accepted once per window reset. Cross-boot replay is therefore not
  prevented; this matches the receiver-restart caveat above.
- **Sequence randomization residual risk**: two boots of the same sender draw
  the same 24-bit start with probability 2^-24 (about 6 × 10^-8). In that case
  the restarted sender's packets fall at or below the receiver's recorded
  maximum without crossing the restart threshold and are classified as replays
  until the counter passes the old maximum.

Key rotation (`update_key()` with a fresh key) re-establishes a clean replay
boundary: packets from earlier epochs are rejected outside the grace window
regardless of sequence numbers.

### Content Tampering — PROTECTED

The AEAD tag verification rejects any packet in which the ciphertext, the
plaintext payload (auth-only mode), or the header bytes have been modified in
transit. A single changed bit causes authentication failure.

## Not Protected

### Traffic Analysis — NOT PROTECTED

Multicast packet sizes, inter-packet timing, multicast group membership, and
the sender_id field (visible in the header) are observable without the PSK.
An observer can determine how many distinct senders are active, their relative
message frequency, and which multicast group address is in use.

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
cleartext to the application without any authentication. With
`cleartext_detection::magic_byte` (the default detection mode), any sender on
the LAN bypasses every confidentiality, integrity, and replay guarantee simply
by sending a packet that does not start with the 0x4D43 magic bytes. This is an
unauthenticated downgrade path: enable it only during migration, with the
understanding that the threat model degrades to plain mDNS for all accepted
cleartext, and disable it once all peers are upgraded.

A related in-band ambiguity exists in `magic_byte` mode: a legitimate cleartext
DNS packet whose transaction ID happens to be 0x4D43 is misclassified as
encrypted and dropped (it fails AEAD verification). Legacy-unicast transaction
IDs are arbitrary, so this collision is unavoidable for in-band detection; the
expected impact is one dropped legacy-unicast exchange per 65536.

### Denial of Service — NOT PROTECTED

An attacker on the LAN can flood the multicast group with malformed or
unauthenticated packets. Each received packet incurs authentication-check
overhead before being dropped. Volumetric flooding can exhaust CPU or socket
buffers. The library provides no rate-limiting or DoS mitigation.

### Insider Threat — NOT PROTECTED

Any peer that holds the PSK is fully trusted by the protocol. A compromised
peer can read all traffic, forge messages from any sender_id, and perform
coordinated replay attacks. The PSK grants symmetric access without
per-peer identity or authorisation.

## Anti-Replay Details

The anti-replay mechanism uses a left-shift sliding-window bitmap per sender,
following RFC 4303 semantics:

- Bit `i` in the window represents sequence number `max_seq - i`
- A received sequence number `s > max_seq` advances the window left by
  `s - max_seq` positions, clearing vacated bits
- A sequence number inside the window that has already been seen is rejected
- A sequence number to the left of the window (older than `max_seq -
  replay_window_size`) is rejected, unless the backward distance is at least
  the restart threshold (`replay_window::restart_threshold`, 2^39), in which
  case the sender's window is re-initialized at the new position and the
  packet is accepted (sender restart or 64-bit sequence wrap)

`replay_window_size` (default 64, `uint16_t`) controls the number of
out-of-order packets tolerated per sender. The bitmap is sized to the
configured window: each tracked sender holds `ceil(replay_window_size / 64)`
`uint64_t` words, i.e. 8 bytes at the default of 64 and 8 KiB at the maximum
of 65535 (about 2 MiB across the default `max_senders` of 256). The full
configured range is supported; a value of 0 is rejected at socket construction.
Values beyond a few hundred buy little on a LAN — UDP multicast reordering
rarely exceeds tens of packets — and only increase per-sender memory.

The sender's sequence counter starts at a per-boot randomized position: the
top 24 bits are drawn from libsodium's CSPRNG, the low 40 bits are zero (see
`random_sequence_start()`). Randomized starts are therefore at least 2^40
apart, comfortably above the 2^39 restart threshold, while legitimate
in-session reordering never approaches it.

`max_senders` (default 256) limits the number of per-sender state entries held
in memory. When a new sender is seen and the table is full, the least recently
used entry is evicted and its state is reset. An attacker can trigger eviction
by spoofing many distinct sender_id values, potentially allowing replay of
packets from an evicted sender; this is an accepted trade-off for bounded
memory usage.
