# Encrypted mDNS

Encrypted mDNS is not defined by any RFC. It is a project-specific extension
that wraps standard mDNS multicast traffic with XChaCha20-Poly1305 authenticated
encryption, using a pre-shared symmetric key (PSK) shared among all participating
peers. The extension is implemented as a composable policy wrapper
(`encrypted_policy<P>`) that layers transparently on top of any existing policy.

## Use Cases

Encrypted mDNS addresses scenarios where standard mDNS traffic must be confined
to a group of trusted peers on a shared LAN segment:

- **LAN privacy**: prevent passive eavesdropping of service announcements on
  shared or semi-trusted networks (e.g., open office WiFi, shared hosting)
- **Hostile network segments**: reject forged or injected mDNS packets from
  devices that do not hold the PSK
- **Isolated device groups**: create logically separate mDNS namespaces on the
  same physical network by assigning different PSKs to different groups

## Assumptions and Limitations

The encrypted mDNS extension operates under the following assumptions:

- All participating peers share an identical 32-byte PSK
- Key distribution is the application's responsibility; the library provides
  no key negotiation protocol
- There is no forward secrecy: if the PSK is compromised after the fact,
  past recorded traffic can be decrypted
- Multicast group membership and packet timing remain visible to any observer
  on the network

See [Threat Model](threat-model.md) for a full assessment of protected and
unprotected attack scenarios.

## Table of Contents

| Document | Description |
|---|---|
| [Encrypted mDNS Guide](encrypted-mdns.md) | Comprehensive guide: PSK setup, basic usage, wire format, cleartext handling, and all convenience aliases |
| [Key Rotation](key-rotation.md) | Deep-dive: epoch semantics, dual-key overlap, grace period parameters, rotation coordination |
| [Auth-Only Mode](auth-only-mode.md) | Deep-dive: integrity without confidentiality, flags bit, receive_mode control |
| [Threat Model](threat-model.md) | Attack scenario verdicts: protected and unprotected scenarios with rationale |
| [API Reference](api/) | API reference for `encrypted_socket`, `encrypt_options`, `secure_key`, and related types |

## Examples

Working code demonstrating PSK lifecycle management is in
[examples/encrypt/](../../examples/encrypt/):

| Example | Demonstrates |
|---|---|
| [01_basic_observer.cpp](../../examples/encrypt/01_basic_observer.cpp) | PSK construction, `encrypted_observer` setup, transparent decryption |
| [02_key_rotation.cpp](../../examples/encrypt/02_key_rotation.cpp) | Key rotation lifecycle: epoch increment, dual-key overlap, grace period |
| [03_auth_only.cpp](../../examples/encrypt/03_auth_only.cpp) | Auth-only mode: integrity without confidentiality, `receive_mode` |
