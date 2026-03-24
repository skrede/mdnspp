# secure_key

RAII container for a 32-byte pre-shared key. The destructor zeros key material using a secure memory-zeroing primitive, preventing the key from persisting in freed memory or being observable via compiler-optimized dead store elimination.

## Header and Alias

| Form | Header |
|------|--------|
| `secure_key` | `#include <mdnspp/encrypt/secure_key.h>` |

```cpp
class secure_key;
```

## Constants

```cpp
static constexpr std::size_t key_size = 32;
```

Size of the key in bytes. All interfaces that accept or return key material use `std::array<std::byte, key_size>` or `std::span<const std::byte, key_size>` to enforce this at compile time.

## Constructors

### Default

```cpp
secure_key() = default;
```

Constructs a zero-initialized key. Not suitable for cryptographic use until assigned from a move operation or replaced by constructing with explicit key material.

### From key bytes (non-throwing)

```cpp
explicit secure_key(std::array<std::byte, key_size> key) noexcept;
```

Constructs from a 32-byte array. The array is moved into internal storage. The `noexcept` guarantee applies because no allocation is performed.

## Copy and Move

`secure_key` is non-copyable to prevent accidental key duplication. It is move-constructible and move-assignable.

```cpp
secure_key(const secure_key &) = delete;
secure_key &operator=(const secure_key &) = delete;

secure_key(secure_key &&other) noexcept;
secure_key &operator=(secure_key &&other) noexcept;
```

After a move, the source object holds a zero-filled key.

## Destructor

```cpp
~secure_key();
```

Zeroes the key storage using `secure_zero` (a libsodium `sodium_memzero` facade) before the object is destroyed. This prevents the key material from remaining accessible in freed stack or heap memory.

## Methods

### bytes

```cpp
std::span<const std::byte, key_size> bytes() const noexcept;
```

Returns a non-owning, fixed-extent span over the key material. The span is valid for the lifetime of the `secure_key` object. The extent is `key_size` (32), enforced at compile time.

## Usage Example

```cpp
#include <mdnspp/encrypt/secure_key.h>
#include <mdnspp/encrypt/encrypt_options.h>

#include <array>
#include <cstddef>

// Construct a key from raw bytes (e.g. from a configuration file or key exchange)
std::array<std::byte, mdnspp::secure_key::key_size> raw_key{};
// ... fill raw_key from your key source ...

mdnspp::encrypt_options opts;
opts.psk = mdnspp::secure_key{raw_key};
opts.sender_id = 42;
```

## See Also

- [encrypt_options](encrypt_options.md) -- uses `secure_key` as the `psk` field
- [encrypted_socket](encrypted_socket.md) -- `update_key()` accepts a `secure_key` by value
- [Key Rotation](../key-rotation.md) -- supplying a new key during key rotation
