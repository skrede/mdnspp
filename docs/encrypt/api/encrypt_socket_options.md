# encrypt_socket_options

Options struct passed to `encrypted_socket` constructors. Inherits all fields from `socket_options` (interface address, multicast group, loopback, TTL) and adds an `encrypt_options` member for encryption configuration.

## Header

```cpp
#include <mdnspp/encrypt/encrypt_socket_options.h>
```

## Declaration

```cpp
struct encrypt_socket_options : socket_options
{
    encrypt_options encrypt{};
};
```

## Inherited Fields

`encrypt_socket_options` inherits all fields from `socket_options`:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `interface_address` | `std::string` | `""` (empty) | IPv4 address of the NIC to bind. Empty means `INADDR_ANY`. |
| `multicast_group` | `endpoint` | `{"224.0.0.251", 5353}` | Multicast group address and port. |
| `multicast_loopback` | `loopback_mode` | `loopback_mode::enabled` | Whether multicast packets loop back to the local host. |
| `multicast_ttl` | `std::optional<uint8_t>` | `std::nullopt` | IP multicast TTL. |
| `port_override` | `std::optional<uint16_t>` | `std::nullopt` | inproc_policy source port override for testing. |

See [Socket Options](../../socket-options.md) for full field documentation.

## Additional Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `encrypt` | `encrypt_options` | default-constructed | Encryption configuration: PSK, sender_id, replay window, cleartext detection, receive mode. |

## Policy Integration

`encrypted_policy<Inner>` declares `socket_options_type = encrypt_socket_options`. The `policy_socket_options_t<P>` trait detects this member, causing `basic_*` constructors to accept and forward `encrypt_socket_options` instead of the base `socket_options` when the policy is `encrypted_policy`.

## Usage Example

```cpp
#include <mdnspp/encrypt/encrypt_socket_options.h>
#include <mdnspp/encrypt/secure_key.h>

#include <array>

std::array<std::byte, 32> raw_key{};
// ... fill raw_key from your key source ...

mdnspp::encrypt::encrypt_socket_options opts;
opts.interface_address     = "192.168.1.10"; // inherited from socket_options
opts.encrypt.psk           = mdnspp::encrypt::secure_key{raw_key};
opts.encrypt.sender_id     = 42;
opts.encrypt.recv_mode     = mdnspp::encrypt::receive_mode::encrypted_only;
```

## See Also

- [encrypt_options](encrypt_options.md) -- encryption parameters embedded in `encrypt_socket_options`
- [encrypted_socket](encrypted_socket.md) -- uses `encrypt_socket_options` in its third and fourth constructors
- [encrypted_policy](encrypted_policy.md) -- declares `socket_options_type = encrypt_socket_options`
- [Socket Options](../../socket-options.md) -- base `socket_options` field reference
