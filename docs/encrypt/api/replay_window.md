# replay_window

Anti-replay state of the encrypted receive path: one sliding window of sequence numbers per (`sender_id`, session ID) pair. Every `encrypted_socket` owns one, sized from its `encrypt_options`; construct one directly only when opening packets outside a socket. The acceptance rules and their residuals are assessed in the [Threat Model](../threat-model.md#replay-attacks--protected-for-tracked-sessions).

## Header

```cpp
#include <mdnspp/encrypt/replay_window.h>
```

```cpp
class replay_window
{
public:
    explicit replay_window(uint16_t window_size = 64, uint16_t max_senders = 256,
                           uint16_t max_sessions_per_sender = 8);
    replay_window(uint16_t window_size, uint16_t max_senders, uint16_t max_sessions_per_sender, std::error_code &ec);

    std::optional<encrypt_error> check_and_record(uint32_t sender_id, uint64_t session_id, uint64_t sequence);
    void reset();
};
```

`replay_window` is non-copyable and non-movable.

## Constructors

| Parameter | Meaning |
|-----------|---------|
| `window_size` | Sequence numbers tracked per session (`encrypt_options::replay_window_size`) |
| `max_senders` | Senders tracked; a new sender beyond the limit evicts the least recently used one with all its sessions |
| `max_sessions_per_sender` | Sessions tracked per sender; a new session beyond the limit replaces the sender's least recently used one |

A zero value of any of the three is invalid: the throwing constructor throws `std::system_error` with `std::errc::invalid_argument`; the `std::error_code` constructor sets `ec` to that code and raises each zero value to `1`, so the object stays usable. Otherwise `ec` is cleared.

Each tracked session costs `ceil(window_size / 64)` 64-bit words of bitmap: 8 bytes per session at the default window, 8 KiB at the maximum window of 65535. See [Replay window memory](encrypt_options.md#replay-window-memory) for the per-sender bound.

## Methods

### check_and_record

```cpp
std::optional<encrypt_error> check_and_record(uint32_t sender_id, uint64_t session_id, uint64_t sequence);
```

Returns `std::nullopt` if the packet is accepted, and records it; returns `encrypt_error::replay_detected` otherwise. Call it only for packets that have passed authentication: a forged sequence number would advance the window.

- The first packet of a session this object does not track is accepted and opens a window for the session.
- A sequence number above the session's highest one is accepted and slides the window forward.
- A sequence number that was already recorded, or that lies `window_size` or more below the highest one, is rejected.
- No packet ever resets a window.

### reset

```cpp
void reset();
```

Forgets every sender and session. A packet of any session is then accepted once again.

## See Also

- [encrypt_options](encrypt_options.md) -- `replay_window_size`, `max_senders` and `max_sessions_per_sender`
- [encrypt_error](encrypt_error.md) -- `replay_detected`
- [Threat Model](../threat-model.md) -- what the windows protect and the untracked-session residual
