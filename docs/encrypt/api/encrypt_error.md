# encrypt_error

Error codes for encrypted mDNS packet processing failures. Integrates with the standard `<system_error>` machinery via a custom error category so that `encrypt_error` values are implicitly convertible to `std::error_code`.

## Header

```cpp
#include <mdnspp/encrypt/encrypt_error.h>
```

## encrypt_error Enum

```cpp
enum class encrypt_error : uint32_t
{
    decrypt_failed      = 1,
    replay_detected     = 2,
    invalid_header      = 4,
    unsupported_version = 5,
    buffer_too_small    = 7,
};
```

### Values

| Enumerator | Value | Description |
|------------|-------|-------------|
| `decrypt_failed` | `1` | AEAD decryption or authentication tag verification failed. The packet was either tampered with, corrupted, or encrypted with a different key. |
| `replay_detected` | `2` | The packet's sequence number was already seen within the replay window for its (`sender_id`, session) pair, or lies below that window. Produced by [`replay_window::check_and_record`](replay_window.md#check_and_record). |
| `invalid_header` | `4` | `aead_decrypt` was given a packet shorter than `encrypted_overhead` (68 bytes) or without the `0x4D43` magic. |
| `unsupported_version` | `5` | `aead_decrypt` was given a packet whose version byte is not `0x02`. |
| `buffer_too_small` | `7` | The caller-supplied output buffer cannot hold the result. Reported through `ec` by `encrypted_socket::send` when the plaintext exceeds `max_udp_payload - 68` bytes (8932), and by `aead_encrypt` / `aead_decrypt` when `out` is too small. |

## Where Codes Surface

The receive path of `encrypted_socket` drops a packet that fails classification, authentication, the mode check, or the replay check, and waits for the next datagram; these errors are not delivered to the receive handler. The codes reach the application from the send path (`buffer_too_small` through `ec`, or as the `std::system_error` thrown by the throwing `send`) and from direct use of the low-level functions declared in `mdnspp/encrypt/aead.h`:

```cpp
std::error_code aead_encrypt(std::span<const std::byte, 32> key, const encrypted_packet_header &hdr,
                             std::span<const std::byte> plaintext, std::span<std::byte> out,
                             std::size_t &written);

std::error_code aead_decrypt(std::span<const std::byte, 32> key, std::span<const std::byte> packet,
                             std::span<std::byte> out, std::size_t &written);
```

Both work on caller-provided buffers and do not allocate; their preconditions are listed in [aead](aead.md). `aead_encrypt` needs `out.size() >= plaintext.size() + 68`; `aead_decrypt` needs `out.size() >= packet.size() - 68`. `written` is the packet length (encrypt) or plaintext length (decrypt) on success and `0` on every failure. Both return `std::errc::not_supported` if libsodium cannot be initialized. `aead_decrypt` checks, in order: libsodium initialization (`std::errc::not_supported`), size (`invalid_header`), magic (`invalid_header`), version (`unsupported_version`), output capacity (`buffer_too_small`), then the tag (`decrypt_failed`).

## Free Functions

### encrypt_error_category

```cpp
const std::error_category &encrypt_error_category() noexcept;
```

Returns a reference to the singleton `std::error_category` for `encrypt_error` codes. The category's `name()` returns `"mdnspp.encrypt"` and `message()` returns a human-readable description for each code value.

### make_error_code

```cpp
std::error_code make_error_code(encrypt_error e);
```

Constructs a `std::error_code` from an `encrypt_error` enumerator using `encrypt_error_category()`. Enables `encrypt_error` values to be used wherever `std::error_code` is expected.

## is_error_code_enum Specialization

```cpp
template <>
struct std::is_error_code_enum<mdnspp::encrypt::encrypt_error> : std::true_type {};
```

This specialization (defined in the global namespace as required by the standard) enables implicit conversion of `encrypt_error` to `std::error_code` and comparison with `std::errc` values.

```cpp
std::error_code ec = mdnspp::encrypt::encrypt_error::decrypt_failed; // implicit
if (ec == mdnspp::encrypt::encrypt_error::replay_detected) { ... }
```

## Usage Example

```cpp
#include <mdnspp/encrypt/encrypt_error.h>

#include <system_error>
#include <iostream>

void report(std::error_code ec)
{
    if (ec.category() == mdnspp::encrypt::encrypt_error_category())
    {
        std::cout << "Encrypt error: " << ec.message() << std::endl;
    }
}

void example()
{
    std::error_code ec = mdnspp::encrypt::encrypt_error::decrypt_failed;
    report(ec); // prints: Encrypt error: decrypt failed
}
```

## See Also

- [encrypted_socket](encrypted_socket.md) -- where `encrypt_error` codes arise during packet processing
- [encrypt_options](encrypt_options.md) -- `replay_window_size`, `max_senders` and `max_sessions_per_sender` influence when `replay_detected` occurs and how long replay state is kept
