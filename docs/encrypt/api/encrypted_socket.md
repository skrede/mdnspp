# encrypted_socket

Transparent encrypt/decrypt wrapper around any `socket_like` socket. Satisfies the `socket_like` concept itself, so it can be composed directly into `encrypted_policy`. Outgoing packets are encrypted with XChaCha20-Poly1305 AEAD (or authenticated only, with `auth_only`); incoming packets are authenticated, mode-checked, and anti-replay-checked before being delivered to the receive handler.

## Thread Safety

- `send()` is as thread-safe as the inner socket's `send()`. Concurrent `send()` calls on one socket are not supported: the send buffer and the sequence counter are shared send-path state and are not synchronized.
- `update_key()` may be called from any thread, concurrently with `send()` and with the receive path. The key, epoch, and grace-period state are guarded by an internal `std::mutex`; key material is copied under the lock and the AEAD operation runs outside it, so the critical section is a 32-byte copy.
- `async_receive()` arming and handler invocation follow the inner socket's executor semantics. The replay windows and the receive buffer are confined to the receive path and are not protected by the mutex; they must not be accessed from other threads.

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

Constructs the inner socket from `ex`. This constructor exists to satisfy the `policy_like` constructibility requirements. The socket has no usable key: the non-throwing `send` reports `std::errc::operation_not_permitted` and sends nothing, the throwing `send` throws `std::system_error` with that code, `async_receive` never completes (the handler is discarded without being called), and `update_key` reports `std::errc::operation_not_permitted`. Discard such a socket and construct one with options.

### Non-throwing, executor only

```cpp
template <typename Executor>
    requires (!std::is_same_v<std::remove_cvref_t<Executor>, encrypted_socket>)
explicit encrypted_socket(Executor &&ex, std::error_code &ec);
```

Same as above, but sets `ec` instead of throwing if the inner socket fails to construct. The resulting socket has no usable key either way.

### Throwing, with options

```cpp
template <typename Executor>
    requires (!std::is_same_v<std::remove_cvref_t<Executor>, encrypted_socket>)
explicit encrypted_socket(Executor &&ex, const encrypt_socket_options &opts);
```

Constructs the inner socket from `ex` and the base `socket_options` portion of `opts`. Then checks, in order and before copying the PSK, that libsodium initializes and that `opts.encrypt` validates: if `validate()` fails (`sender_id == 0`, all-zero PSK, `replay_window_size == 0`, `max_senders == 0`, or `max_sessions_per_sender == 0`), throws `std::system_error` with `std::errc::invalid_argument` and the key is never copied. If libsodium cannot be initialized, throws `std::system_error` with `std::errc::not_supported`. Validation is active in all build configurations, including release builds. On success, copies the PSK, sets the starting epoch from `initial_epoch`, and draws a random nonzero session ID for this socket, and configures the replay window, cleartext, and auth-only behavior. This is the primary constructor for production use.

### Non-throwing, with options

```cpp
template <typename Executor>
    requires (!std::is_same_v<std::remove_cvref_t<Executor>, encrypted_socket>)
explicit encrypted_socket(Executor &&ex, const encrypt_socket_options &opts, std::error_code &ec);
```

Same as the throwing with-options constructor, but sets `ec` instead of throwing: on inner socket construction failure, on failed validation (`std::errc::invalid_argument`), or when libsodium cannot be initialized (`std::errc::not_supported`), `ec` is set and the key is not copied. Such a socket has no usable key and behaves like one built from an executor alone: `send` reports `std::errc::operation_not_permitted`, `async_receive` never completes, and `update_key` reports `std::errc::operation_not_permitted`.

## Copy and Move

`encrypted_socket` is non-copyable and non-movable. The copy constructor and copy assignment are deleted; because they are user-declared, no move operations are generated. The internal mutex and the `this` capture in the receive path make moving unsound in any case.

```cpp
encrypted_socket(const encrypted_socket &) = delete;
encrypted_socket &operator=(const encrypted_socket &) = delete;
```

## Destruction

The destructor is implicit. Destroying the socket destroys its key ring, which zeroes the current key and the previous key (held during grace periods) with `secure_zero`. The per-send key copy is zeroed when the send call returns.

## Methods

### close

```cpp
void close();
```

Closes the underlying inner socket and discards the pending receive handler without invoking it. A later `async_receive` call is ignored.

### send (throwing)

```cpp
void send(const endpoint &dest, std::span<const std::byte> plaintext);
```

Calls the non-throwing overload and throws `std::system_error` (message `mdnspp::encrypt: send`) carrying the resulting error code if it is set. There is a single send implementation.

### send (non-throwing)

```cpp
void send(const endpoint &dest, std::span<const std::byte> plaintext, std::error_code &ec);
```

Seals `plaintext` into the socket's send buffer with the current epoch key, the `sender_id`, this socket's session ID, and the next sequence number (the first packet carries 1), then passes the datagram to the inner socket's `send`. The encrypt layer allocates nothing per call; the send buffer is sized once at construction. Failures are reported through `ec`:

- `std::errc::operation_not_permitted` if the socket has no usable key (see Constructors); nothing is sent and the sequence number is not consumed.
- `encrypt_error::buffer_too_small` if the sealed packet would not fit in `max_udp_payload` (9000) bytes. The maximum plaintext is therefore `max_udp_payload - 68` (`encrypted_overhead`), i.e. 8932 bytes; a larger plaintext is not sent, the inner socket sees nothing, and the sequence number is not consumed.
- `std::errc::not_supported` if libsodium cannot be initialized; nothing is sent and the sequence number is not consumed.
- Whatever error the inner socket's `send` reports. The packet was sealed, so its sequence number is consumed.

The sequence counter advances only when a packet is sealed: a failed seal leaves it unchanged, and the next sealed packet carries the number the failed one would have had.

When `auth_only` mode is enabled, the plaintext is not encrypted: the packet carries the header, the plaintext, and the AEAD tag covering both (the `flag_encrypted` bit is cleared). The overhead is the same 68 bytes.

Each socket draws its session ID once at construction, so a restarted sender is a new session at receivers; the sequence counter is not randomized.

`send()` is as thread-safe as the inner socket's `send()`; concurrent `send()` calls on one socket are not supported (see Thread Safety).

### async_receive

```cpp
void async_receive(
    move_only_function<void(std::error_code, const recv_metadata &, std::span<std::byte>)> handler);
```

Arms the inner socket's receive loop. On a closed socket, or one without a usable key, the call returns without arming and the handler is discarded without being called. Inner-socket errors are forwarded to the handler unchanged. Every datagram that is not delivered (a drop) re-arms the receive without calling the handler; a delivered datagram completes the handler once. For each received datagram, the socket:

1. Classifies it according to `cleartext_detection` and `accept_cleartext`. A packet without the magic prefix is cleartext (forwarded when `accept_cleartext` is set and detection is not `reject_all`, dropped otherwise). A magic-prefixed packet shorter than `smallest_known_header_size` (44 bytes) is forwarded as cleartext only in `attempt_decrypt` mode with `accept_cleartext`, otherwise dropped. A magic-prefixed packet of 44 bytes or more is never forwarded as cleartext: it proceeds only if it is at least `encrypted_overhead` (68) bytes long and carries version `0x02`, and is dropped otherwise.
2. Reads the epoch from the header and selects the key under the internal mutex: the current key for the current epoch and for one epoch ahead, the previous key for one epoch behind within the grace period, and the current key for one epoch behind when no previous key is held (initial-epoch skew under the same key, tolerated in both directions). Any other epoch is dropped. The previous key is zeroized as soon as grace expiry is observed.
3. Authenticates and decrypts (for auth-only packets, verifies and copies the payload) into the socket's receive buffer, outside the lock. A failure is a drop; it never falls through to cleartext.
4. Checks `receive_mode` against the authenticated `flags` byte. A mismatch is a drop.
5. Checks the replay window of the packet's (`sender_id`, session ID) pair. A duplicate, or a sequence below the window, is a drop. A window is never reset by a packet; a packet of an untracked session is accepted once and opens a window (see the [Threat Model](../threat-model.md)).
6. Calls `handler` with the plaintext, a span into a socket buffer that is valid only for the duration of the call.

### update_key

```cpp
void update_key(secure_key new_psk, grace_period gp);
void update_key(secure_key new_psk, grace_period gp, std::error_code &ec);
```

Performs a key rotation. On a socket without a usable key (see Constructors) nothing changes: the non-throwing overload sets `ec` to `std::errc::operation_not_permitted` and the throwing overload throws `std::system_error` (message `mdnspp::encrypt: update_key`) with that code. On a keyed socket an all-zero `new_psk` (a default-constructed `secure_key`, which the constructors reject as well) is refused the same way with `std::errc::invalid_argument`, and the current key, the epoch and the grace state stay unchanged. Otherwise the non-throwing overload clears `ec`, and the current key becomes the previous key and is retained for decrypting packets from peers still using the old epoch. The new key is installed as the current key, the epoch counter is incremented by one, and the grace period timer is started. May be called from any thread, concurrently with `send()` and the receive path (see Thread Safety).

If `gp` sets neither `duration` nor `packet_count`, a duration bound of `default_grace_duration` (`std::chrono::seconds{30}`) is applied so the previous key cannot remain accepted indefinitely. The previous key is zeroized (`sodium_memzero`) as soon as grace expiry is observed at a key lookup, which every `send()` and every received encrypted packet performs -- either when the duration elapses (measured with `std::chrono::steady_clock`) or when the count of old-epoch packets accepted reaches the limit, whichever comes first -- and again at destruction. The count includes only packets accepted with the previous key (authenticated and not rejected as replays).

All peers must call `update_key()` with the same new key within the grace window: a peer that has not rotated drops new-epoch traffic until it does, and peers that have rotated stop accepting its old-epoch traffic once their grace period expires. There is no staged next-key mechanism. See [Key Rotation](../key-rotation.md).

### interface_index

```cpp
uint32_t interface_index() const noexcept;  // only when InnerSocket has interface_index()
```

Returns the inner socket's `interface_index()`: the index of the interface the socket is bound to, `0` when unbound. Declared only when `InnerSocket` declares it (the default, asio and mock sockets do; the in-process socket does not). The peers use it to drop multicast received on another interface (see [Receive interface attribution](../../socket-options.md#receive-interface-attribution)).

### inner

```cpp
InnerSocket &inner() noexcept;
const InnerSocket &inner() const noexcept;
```

Returns a reference to the wrapped inner socket. Provides access to socket-specific operations not exposed through `socket_like` (e.g., `native_handle()` on platform socket types).

## Key State

| State | Description |
|-------|-------------|
| Current key | Used for all outgoing packets. Used for decrypting packets with the current epoch number, and tried for packets one epoch ahead and, while no previous key is held, one epoch behind (initial-epoch skew under the same key, in both directions; it does not decrypt traffic of a peer that has rotated). |
| Previous key | Retained after `update_key()`. Accepted for decrypting packets with epoch minus one, until the grace period expires. Zeroized at the first send or receive key lookup after grace period expiry, and on destruction. |
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
