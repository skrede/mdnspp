# ip_address

A raw IPv4 or IPv6 address: an address family and sixteen bytes. It is the address type of
`recv_metadata::destination`. Addresses in `endpoint` remain text (`std::string`).

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

## See Also

- [recv_metadata](recv_metadata.md) — `destination`, the address a received packet was sent to
