# ip_address

A raw IPv4 or IPv6 address: an address family and sixteen bytes. It is the address type of
`recv_metadata::destination` and, paired with a prefix length as `ip_network`, of
`network_interface::addresses`. Addresses in `endpoint` remain text (`std::string`).

## Header

```cpp
#include <mdnspp/ip_address.h>
```

---

## address_family

```cpp
enum class address_family : uint8_t { ipv4, ipv6 };
```

---

## ip_address

```cpp
struct ip_address {
    address_family family{address_family::ipv4};
    std::array<std::byte, 16> bytes{};

    bool is_multicast() const noexcept;
    bool operator==(const ip_address &) const = default;
};
```

| Member | Description |
|--------|-------------|
| `family` | The address family. Defaults to `address_family::ipv4`. |
| `bytes` | The address in network byte order. An IPv4 address occupies `bytes[0..3]`; the remaining twelve bytes are zero. An IPv6 address occupies all sixteen. The IPv6 zone (scope id) is not part of the address. |
| `is_multicast()` | `true` for an IPv4 address in `224.0.0.0/4` (first byte `0xE0` to `0xEF`) and for an IPv6 address in `ff00::/8` (first byte `0xFF`). |
| `operator==` | Compares the family and all sixteen bytes. Two addresses with equal bytes but different families are not equal. |

`ip_address` is a plain aggregate and can be built with designated initializers:

```cpp
mdnspp::ip_address group{.family = mdnspp::address_family::ipv4,
                         .bytes = {std::byte{224}, std::byte{0}, std::byte{0}, std::byte{251}}};
bool multicast = group.is_multicast(); // true
```

An IPv4 address must leave `bytes[4..15]` zero; equality compares every byte, so an IPv4
address with non-zero trailing bytes does not equal the same address built by the library.

---

## ip_network

```cpp
struct ip_network {
    ip_address address;
    uint8_t prefix_length{0};

    bool operator==(const ip_network &) const = default;
};
```

| Member | Description |
|--------|-------------|
| `address` | An address assigned to an interface. |
| `prefix_length` | The on-link prefix length in bits: 0 to 32 for IPv4, 0 to 128 for IPv6. `192.0.2.10` on a `255.255.255.0` network has prefix length 24. |
| `operator==` | Compares the address and the prefix length. |

`ip_network` is the element type of `network_interface::addresses`. A custom
`nic_monitor_options::enumerator` builds it with designated initializers:

```cpp
mdnspp::ip_network net{
    .address = {.family = mdnspp::address_family::ipv4,
                .bytes = {std::byte{192}, std::byte{0}, std::byte{2}, std::byte{10}}},
    .prefix_length = 24,
};
```

---

## See Also

- [recv_metadata](recv_metadata.md) — `destination`, the address a received packet was sent to
- [network_interface](../socket-options.md#network_interface-struct) — `addresses`, the addresses of an interface
