# encrypted_socket

Transparent encrypt/decrypt wrapper around any `socket_like` socket. Satisfies the `socket_like` concept itself, so it can be composed directly into `encrypted_policy`. Outgoing packets are encrypted with XChaCha20-Poly1305 AEAD; incoming packets are decrypted and anti-replay-checked before being delivered to the receive handler.

## Thread Safety

- `update_key()` and `send()` may be called from any thread, concurrently with each other and with the receive path. The key, epoch, and grace-period state are guarded by an internal `std::mutex`; key material is copied under the lock and the AEAD operation runs outside it, so the critical section is a 32-byte copy.
- `async_receive()` arming and handler invocation follow the inner socket's executor semantics. The per-sender replay window is confined to the receive path and is not protected by the mutex; it must not be accessed from other threads.

## Header and Alias

| Form | Header |
|------|--------|
| `encrypted_socket<InnerSocket>` | `#include <mdnspp/encrypt/encrypted_socket.h>` |

```cpp
template <socket_like InnerSocket>
class encrypted_socket;
```

## Template Parameters

| Parameter | Constraint | Description |
|-----------|------------|-------------|
| `InnerSocket` | satisfies `socket_like` | The underlying socket used for actual network I/O. Typically the `socket_type` of a concrete policy such as `default_socket` or `asio_socket`. |

## Constructors

All four constructors accept a forwarding reference `Executor&&` to avoid copy-construction of the inner socket on compilers where by-value template parameters trigger premature instantiation (Apple Clang 16 bug). The requires-clause excludes `encrypted_socket` itself to prevent the forwarding constructor from shadowing move construction.

### Throwing, executor only

```cpp
template <typename Executor>
    requires (!std::is_same_v<std::remove_cvref_t<Executor>, encrypted_socket>)
explicit encrypted_socket(Executor &&ex);
```

Constructs the inner socket from `ex`. Encryption options are left at their defaults (zero key, `sender_id = 0`, `magic_byte` detection). This constructor exists to satisfy the `policy_like` constructibility requirements; a socket constructed this way holds no key and must be discarded, not used.

### Non-throwing, executor only

```cpp
template <typename Executor>
    requires (!std::is_same_v<std::remove_cvref_t<Executor>, encrypted_socket>)
explicit encrypted_socket(Executor &&ex, std::error_code &ec);
```

Same as above, but sets `ec` instead of throwing if the inner socket fails to construct.

### Throwing, with options

```cpp
template <typename Executor>
    requires (!std::is_same_v<std::remove_cvref_t<Executor>, encrypted_socket>)
explicit encrypted_socket(Executor &&ex, const encrypt_socket_options &opts);
```

Constructs the inner socket from `ex` and the base `socket_options` portion of `opts`. Validates `opts.encrypt` before copying the PSK: if `validate()` fails (`sender_id == 0`, all-zero PSK, or `replay_window_size == 0`), throws `std::system_error` with `std::errc::invalid_argument` and the key is never copied. Validation is active in all build configurations, including release builds. On success, copies the PSK, sets the starting epoch from `initial_epoch`, and configures the replay window, cleartext, and auth-only behaviour. This is the primary constructor for production use.

### Non-throwing, with options

```cpp
template <typename Executor>
    requires (!std::is_same_v<std::remove_cvref_t<Executor>, encrypted_socket>)
explicit encrypted_socket(Executor &&ex, const encrypt_socket_options &opts, std::error_code &ec);
```

Same as the throwing with-options constructor, but sets `ec` instead of throwing: on inner socket construction failure or on failed validation (`std::errc::invalid_argument`), `ec` is set, the key is not copied, and the socket must not be used.

## Copy and Move

`encrypted_socket` is non-copyable and non-movable. The previously defaulted move constructor was silently deleted by the atomic sequence counter and is now deleted explicitly, matching the non-movable peer convention; the internal mutex and the `this` capture in the receive path make moving unsound in any case.

```cpp
encrypted_socket(const encrypted_socket &) = delete;
encrypted_socket &operator=(const encrypted_socket &) = delete;

encrypted_socket(encrypted_socket &&) = delete;
encrypted_socket &operator=(encrypted_socket &&) = delete;
```

## Destructor

```cpp
~encrypted_socket();
```

Zeroes both the current key and the previous key (held during grace periods) using `secure_zero` before the object is destroyed.

## Methods

### close

```cpp
void close();
```

Closes the underlying inner socket. Ongoing `async_receive` operations complete with an error.

### send (throwing)

```cpp
void send(const endpoint &dest, std::span<const std::byte> plaintext);
```

Encrypts `plaintext` with the current epoch key and `sender_id`, then passes the resulting ciphertext to the inner socket's `send`. The sequence counter is incremented atomically; it starts at a per-boot randomized position (top 24 bits from the CSPRNG, low 40 bits zero, see `random_sequence_start()`) so that a restarted sender does not collide with the replay-window state receivers hold from its previous run. May be called from any thread (see Thread Safety).

When `auth_only` mode is enabled, the plaintext is included as additional authenticated data and no ciphertext is produced; the packet carries only the AEAD tag and header.

### send (non-throwing)

```cpp
void send(const endpoint &dest, std::span<const std::byte> plaintext, std::error_code &ec);
```

Same as the throwing overload, but sets `ec` instead of throwing if the underlying send fails.

### async_receive

```cpp
void async_receive(
    move_only_function<void(std::error_code, const recv_metadata &, std::span<std::byte>)> handler);
```

Arms the inner socket's receive loop. Inner-socket errors are forwarded to the handler with the error code set and an empty data span. For each received datagram, the socket:

1. Checks for the encrypted magic byte sequence (`0x4D 0x43`) according to `cleartext_detection`. Packets shorter than `encrypted_header_size` (44 bytes) cannot be encrypted packets; in `attempt_decrypt` mode with `accept_cleartext = true` they are forwarded as cleartext (a legitimate cleartext mDNS query can be ~28 bytes), otherwise they are dropped.
2. Deserializes the packet header to extract `sender_id`, `sequence`, `epoch`, and `flags`.
3. Filters by `receive_mode` (encrypted-only or auth-only-only).
4. Selects the key by epoch under the internal mutex: the current key for the current epoch and for one epoch ahead (epoch-counter skew with shared key material), or the previous key for one epoch behind within the grace period. The previous key is zeroized as soon as grace expiry is observed.
5. Decrypts with AEAD outside the lock. On failure in `attempt_decrypt` mode, forwards the raw packet as cleartext if `accept_cleartext` is set.
6. Checks the per-sender replay window. Duplicate or replayed sequences are silently dropped; a backward jump of at least `replay_window::restart_threshold` (2^39) re-initializes the sender's window (sender restart).
7. Calls `handler` with the decrypted plaintext.

### update_key

```cpp
void update_key(secure_key new_psk, grace_period gp);
```

Performs a key rotation. The current key becomes the previous key and is retained for decrypting packets from peers still using the old epoch. The new key is installed as the current key, the epoch counter is incremented by one, and the grace period timer is started. Thread-safe: may be called from any thread, concurrently with the receive path (see Thread Safety).

If `gp` sets neither `duration` nor `packet_count`, a duration bound of `default_grace_duration` (`std::chrono::seconds{30}`) is applied so the previous key cannot remain accepted indefinitely. The previous key is zeroized (`sodium_memzero`) as soon as grace expiry is observed on the receive path -- either when the wall-clock duration elapses or when the count of old-epoch packets received reaches the limit, whichever comes first -- and again at destruction.

### inner

```cpp
InnerSocket &inner() noexcept;
const InnerSocket &inner() const noexcept;
```

Returns a reference to the wrapped inner socket. Provides access to socket-specific operations not exposed through `socket_like` (e.g., `native_handle()` on platform socket types).

## Key State

| State | Description |
|-------|-------------|
| Current key | Used for all outgoing packets. Used for decrypting packets with the current epoch number, and tried for packets one epoch ahead (epoch-counter skew with shared key material). |
| Previous key | Retained after `update_key()`. Accepted for decrypting packets with epoch minus one, until the grace period expires. Zeroized on grace period expiry and on destruction. |
| Epoch | Monotonically increasing `uint32_t`. Starts at `encrypt_options::initial_epoch`, incremented on each `update_key()` call. Embedded in every outgoing packet header. |

## Usage Example

```cpp
#include <mdnspp/encrypt/defaults.h>
#include <mdnspp/encrypt/encrypt_options.h>
#include <mdnspp/encrypt/encrypt_socket_options.h>

#include <array>

// Construct an encrypted observer using a pre-shared key
std::array<std::byte, 32> raw_key{};
// ... fill raw_key ...

mdnspp::encrypt::encrypt_socket_options sock_opts;
sock_opts.encrypt.psk       = mdnspp::encrypt::secure_key{raw_key};
sock_opts.encrypt.sender_id = 1;
mdnspp::encrypt::secure_zero(raw_key.data(), raw_key.size());

mdnspp::context ctx;
mdnspp::encrypt::encrypted_observer obs{ctx, mdnspp::observer_options{}, std::move(sock_opts)};
obs.async_observe();
ctx.run();
```

## See Also

- [encrypt_options](encrypt_options.md) -- encryption configuration
- [encrypt_socket_options](encrypt_socket_options.md) -- combines socket and encryption options
- [encrypted_policy](encrypted_policy.md) -- policy wrapper that substitutes `encrypted_socket` for the inner socket type
- [secure_key](secure_key.md) -- RAII key container
- [Key Rotation](../key-rotation.md) -- grace period semantics and `update_key()` usage
