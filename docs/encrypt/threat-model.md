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

### Replay Attacks — PROTECTED

Each sender maintains a monotonically increasing 64-bit sequence number. Each
receiver maintains a per-sender anti-replay sliding window. Packets whose
sequence number falls inside the window and has already been seen are rejected.
Packets whose sequence number is below the window's left edge are also rejected.
The window width is `replay_window_size` (default 64 slots).

Sequence numbers are per-sender, tracked independently for each `sender_id`.
The receiver tracks up to `max_senders` (default 256) distinct senders; when
this limit is exceeded the least recently used entry is evicted.

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
  replay_window_size`) is unconditionally rejected

`replay_window_size` (default 64) controls the number of out-of-order packets
tolerated per sender. Larger values accommodate higher reordering at the cost
of more memory per sender entry.

`max_senders` (default 256) limits the number of per-sender state entries held
in memory. When a new sender is seen and the table is full, the least recently
used entry is evicted and its state is reset. An attacker can trigger eviction
by spoofing many distinct sender_id values, potentially allowing replay of
packets from an evicted sender; this is an accepted trade-off for bounded
memory usage.
