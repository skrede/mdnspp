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
    unknown_sender      = 3,
    invalid_header      = 4,
    unsupported_version = 5,
    sender_evicted      = 6,
};
```

### Values

| Enumerator | Value | Description |
|------------|-------|-------------|
| `decrypt_failed` | `1` | AEAD decryption or authentication tag verification failed. The packet was either tampered with, corrupted, or encrypted with a different key. |
| `replay_detected` | `2` | The packet's sequence number was already seen within the replay window for this sender. The packet is a duplicate or replay attack. |
| `unknown_sender` | `3` | The `sender_id` in the packet header is not recognized and the replay window has no slot for it. |
| `invalid_header` | `4` | The packet is too short to contain a valid encrypted packet header, or the header fields are malformed. |
| `unsupported_version` | `5` | The packet header version field indicates a protocol version not supported by this implementation. |
| `sender_evicted` | `6` | The sender's replay window entry was evicted to make room for a new sender (when `max_senders` is reached). |

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
- [encrypt_options](encrypt_options.md) -- `replay_window_size` and `max_senders` influence when `replay_detected` and `sender_evicted` occur
