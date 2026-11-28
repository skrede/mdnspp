#ifndef HPP_GUARD_MDNSPP_IP_ADDRESS_H
#define HPP_GUARD_MDNSPP_IP_ADDRESS_H

#include <array>
#include <cstddef>
#include <cstdint>

namespace mdnspp {

enum class address_family : uint8_t
{
    ipv4,
    ipv6,
};

// An IPv4 address occupies bytes 0..3 and leaves the rest zero, so the defaulted equality is exact.
struct ip_address
{
    address_family family{address_family::ipv4};
    std::array<std::byte, 16> bytes{};

    bool is_multicast() const noexcept
    {
        const auto first = std::to_integer<uint8_t>(bytes[0]);
        return family == address_family::ipv4 ? (first & 0xF0u) == 0xE0u : first == 0xFFu;
    }

    bool operator==(const ip_address &) const = default;
};

struct ip_network
{
    ip_address address;
    uint8_t prefix_length{0};

    bool operator==(const ip_network &) const = default;
};

}

#endif
