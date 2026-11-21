# aead

Low-level packet sealing and opening with XChaCha20-Poly1305, plus the crypto helpers the encrypt layer is built on. `encrypted_socket` uses these functions internally; call them directly only to seal or open packets outside a socket, or to wipe key material.

## Header

```cpp
#include <mdnspp/encrypt/aead.h>
```

`aead.h` includes `mdnspp/encrypt/packet_header.h`, which defines `encrypted_packet_header` and the size constants (see [Packet Header](#packet-header)).

## Functions

### aead_encrypt

```cpp
std::error_code aead_encrypt(std::span<const std::byte, 32> key, const encrypted_packet_header &hdr,
                             std::span<const std::byte> plaintext, std::span<std::byte> out,
                             std::size_t &written);
```

Writes one wire packet to the front of `out`: the 52-byte header, then the payload, then the 16-byte Poly1305 tag.

- If `hdr.flags` has `flag_encrypted` set, the payload is the ciphertext of `plaintext` and the serialized header is the AAD.
- If `flag_encrypted` is clear (auth-only), the payload is `plaintext` in the clear and the tag covers the header and the plaintext as AAD.
- A random 24-byte nonce is drawn on every call and written into the output header; `hdr.nonce` is ignored. All other header fields are written as given, without checks.

Preconditions:

- `out.size() >= plaintext.size() + encrypted_overhead` (68 bytes).
- `out` must not overlap `plaintext`; even a partial overlap corrupts the input, because the header is written to the front of `out` before `plaintext` is read.

Errors, checked in this order:

| Error | Condition |
|-------|-----------|
| `std::errc::not_supported` | libsodium cannot be initialized |
| `encrypt_error::buffer_too_small` | `out` is smaller than `plaintext.size() + 68`; nothing is written |

`written` is set to the packet length (`plaintext.size() + 68`) on success and to `0` on every failure. The function does not allocate.

### aead_decrypt

```cpp
std::error_code aead_decrypt(std::span<const std::byte, 32> key, std::span<const std::byte> packet,
                             std::span<std::byte> out, std::size_t &written);
```

Authenticates a full wire packet (header, payload, tag) and writes the plaintext to the front of `out`. The `flag_encrypted` bit of the packet header selects decryption or, for auth-only packets, verification followed by a copy of the payload. Epoch, sender and replay checks are the caller's: `aead_decrypt` uses the key it is given.

Preconditions:

- `out.size() >= packet.size() - encrypted_overhead`.
- `out` must not overlap `packet`; a partial overlap is not supported.

Errors, checked in this order:

| Error | Condition |
|-------|-----------|
| `std::errc::not_supported` | libsodium cannot be initialized |
| `encrypt_error::invalid_header` | `packet` is shorter than `encrypted_overhead` (68 bytes) |
| `encrypt_error::invalid_header` | the magic is not `0x4D43` |
| `encrypt_error::unsupported_version` | the version byte is not `0x02` |
| `encrypt_error::buffer_too_small` | `out` is smaller than `packet.size() - 68` |
| `encrypt_error::decrypt_failed` | the tag does not verify (tampered packet or a different key) |

`written` is set to the plaintext length (`packet.size() - 68`) on success and to `0` on every failure; `out` holds no usable data after a failure. The function does not allocate.

### init_crypto

```cpp
bool init_crypto();
```

Initializes libsodium once and returns whether it succeeded. Thread-safe: the initialization runs under `std::call_once`, and every later call returns the cached result, so a failed initialization is not retried. Calling it first is not required: `aead_encrypt`, `aead_decrypt` and the `encrypted_socket` constructors call it themselves and report a failure as `std::errc::not_supported`.

### random_session_id

```cpp
uint64_t random_session_id() noexcept;
```

Returns a nonzero 64-bit value drawn from the libsodium CSPRNG. Every keyed `encrypted_socket` draws one at construction as its session ID, so each boot of a sender is a distinct replay-tracking session. The function does not report a failed libsodium initialization; check `init_crypto()` first.

### secure_zero

```cpp
void secure_zero(void *buf, std::size_t len) noexcept;
```

Overwrites `len` bytes at `buf` with zeros using `sodium_memzero`, which the compiler cannot remove as a dead store. Use it to wipe the source array of a `secure_key` (see [secure_key](secure_key.md)).

## Packet Header

```cpp
#include <mdnspp/encrypt/packet_header.h>
```

### Constants

| Constant | Type | Value | Description |
|----------|------|-------|-------------|
| `encrypted_magic` | `uint16_t` | `0x4D43` | The bytes `'M' 'C'` at the start of every encrypted packet |
| `encrypted_version` | `uint8_t` | `0x02` | The only wire version a receiver accepts |
| `encrypted_header_size` | `std::size_t` | `52` | Serialized header length |
| `encrypted_tag_size` | `std::size_t` | `16` | Poly1305 tag length |
| `encrypted_nonce_size` | `std::size_t` | `24` | XChaCha20 nonce length |
| `encrypted_overhead` | `std::size_t` | `68` | Header plus tag |
| `flag_encrypted` | `uint8_t` | `0x01` | Flags bit 0: set for encrypted packets, clear for auth-only |

### encrypted_packet_header

```cpp
struct encrypted_packet_header
{
    uint16_t magic{encrypted_magic};
    uint8_t version{encrypted_version};
    uint8_t flags{flag_encrypted};
    uint32_t sender_id{0};
    uint64_t session_id{0};
    uint64_t sequence{0};
    uint32_t epoch{0};
    std::array<std::byte, encrypted_nonce_size> nonce{};
};
```

The field layout on the wire is described in [Wire Format](../encrypted-mdns.md#wire-format).

### serialize_header

```cpp
std::array<std::byte, encrypted_header_size> serialize_header(const encrypted_packet_header &hdr);
```

Returns the 52 header bytes, integers in network byte order, the nonce last.

### deserialize_header

```cpp
encrypted_packet_header deserialize_header(const std::byte *buf);
```

Reads a header from `buf`, which must point to at least `encrypted_header_size` readable bytes. Fields are returned in host byte order; the magic and version are not checked.

## See Also

- [encrypt_error](encrypt_error.md) -- the error codes and their category
- [encrypted_socket](encrypted_socket.md) -- the socket that seals and opens every datagram with these functions
- [Auth-Only Mode](../auth-only-mode.md) -- integrity without confidentiality
- [secure_key](secure_key.md) -- RAII key container
