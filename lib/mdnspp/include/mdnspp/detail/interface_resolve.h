#ifndef HPP_GUARD_MDNSPP_DETAIL_INTERFACE_RESOLVE_H
#define HPP_GUARD_MDNSPP_DETAIL_INTERFACE_RESOLVE_H

#include "mdnspp/detail/ip_address_ops.h"
#include "mdnspp/detail/native_sockaddr.h"
#include "mdnspp/detail/interface_addresses.h"

#include "mdnspp/ip_address.h"
#include "mdnspp/service_info.h"
#include "mdnspp/socket_options.h"
#include "mdnspp/network_interface.h"

#include <string>
#include <vector>
#include <cstdint>
#include <concepts>
#include <optional>
#include <algorithm>
#include <string_view>
#include <system_error>

namespace mdnspp::detail {

struct interface_binding
{
    std::optional<uint32_t> index{};
    std::optional<std::string> name{};
    std::string address{};

    bool bound() const noexcept
    {
        return index.has_value() || name.has_value() || !address.empty();
    }
};

template <typename Opts>
interface_binding extract_interface_binding(const Opts &opts)
{
    interface_binding binding;
    if constexpr(requires { { opts.interface_index } -> std::convertible_to<std::optional<uint32_t>>; })
        binding.index = opts.interface_index;
    if constexpr(requires { { opts.interface_name } -> std::convertible_to<std::optional<std::string>>; })
        binding.name = opts.interface_name;
    if constexpr(requires { { opts.interface_address } -> std::convertible_to<std::string>; })
        binding.address = opts.interface_address;
    return binding;
}

inline bool address_is_ipv6(std::string_view address) noexcept
{
    return address.find(':') != std::string_view::npos;
}

// RFC 4007 section 11: the zone of a scoped address names the interface it belongs to.
inline uint32_t address_zone(std::string_view text)
{
    sockaddr_in6 addr{};
    return parse_ipv6(text, addr) ? addr.sin6_scope_id : 0;
}

inline const network_interface *
find_interface(const std::vector<network_interface> &interfaces, const interface_binding &binding) noexcept
{
    auto find = [&](auto pred) -> const network_interface *
    {
        auto it = std::ranges::find_if(interfaces, pred);
        return it != interfaces.end() ? &*it : nullptr;
    };

    if(binding.index.has_value())
        return find([&](const network_interface &nic) { return nic.index == *binding.index; });
    if(binding.name.has_value())
        return find([&](const network_interface &nic) { return nic.name == *binding.name; });
    if(!binding.address.empty())
    {
        const std::optional<ip_address> address = parse_ip_address(binding.address);
        const uint32_t zone = address_zone(binding.address);
        auto carries = [&](const network_interface &nic)
        {
            return contains(nic, *address) && (zone == 0 || nic.index == zone);
        };
        return address ? find(carries) : nullptr;
    }
    return nullptr;
}

inline std::string first_address_text(const network_interface &nic, bool ipv6)
{
    const ip_network *net = first_address(nic, ipv6 ? address_family::ipv6 : address_family::ipv4);
    return net != nullptr ? format_ip_address(net->address) : std::string{};
}

struct resolved_interface
{
    uint32_t index{0};
    std::optional<ip_address> ipv4{};
};

inline std::optional<ip_address>
bound_address(const network_interface *nic, const interface_binding &binding, address_family family)
{
    if(!binding.index.has_value() && !binding.name.has_value())
        return parse_ip_address(binding.address);
    const ip_network *net = nic != nullptr ? first_address(*nic, family) : nullptr;
    return net != nullptr ? std::optional{net->address} : std::nullopt;
}

// IPv4 multicast names its interface by address, which the kernel validates; IPv6 needs the interface index.
inline resolved_interface select_interface(const std::vector<network_interface> &interfaces,
                                           const interface_binding &binding, address_family family,
                                           std::error_code &ec)
{
    ec.clear();
    if(!binding.bound())
        return {};
    const network_interface *nic = find_interface(interfaces, binding);
    const std::optional<ip_address> address = bound_address(nic, binding, family);
    const bool located = nic != nullptr || family == address_family::ipv4;
    if(!located || !address.has_value() || address->family != family)
    {
        ec = std::make_error_code(std::errc::invalid_argument);
        return {};
    }
    return {nic != nullptr ? nic->index : 0, family == address_family::ipv4 ? address : std::nullopt};
}

inline resolved_interface
resolve_socket_interface(const socket_options &opts, address_family family, std::error_code &ec)
{
    ec.clear();
    const interface_binding binding = extract_interface_binding(opts);
    if(!binding.bound())
        return {};
    const std::vector<network_interface> interfaces = enumerate_interfaces(ec);
    if(ec)
        return {};
    return select_interface(interfaces, binding, family, ec);
}

inline const network_interface *
lowest_index_interface(const std::vector<network_interface> &interfaces, bool ipv6) noexcept
{
    const network_interface *best = nullptr;
    for(const auto &nic : interfaces)
    {
        if(nic.is_loopback || !nic.is_up)
            continue;
        if(!has_family(nic, ipv6 ? address_family::ipv6 : address_family::ipv4))
            continue;
        if(best == nullptr || nic.index < best->index)
            best = &nic;
    }
    return best;
}

inline std::string advertised_address(const std::vector<network_interface> &interfaces,
                                      const network_interface *bound, const interface_binding &binding, bool ipv6)
{
    std::string address;
    if(bound != nullptr)
        address = first_address_text(*bound, ipv6);
    else if(!binding.address.empty())
    {
        if(address_is_ipv6(binding.address) == ipv6)
            address = binding.address;
    }
    else if(!binding.bound())
    {
        if(const network_interface *nic = lowest_index_interface(interfaces, ipv6))
            address = first_address_text(*nic, ipv6);
    }
    return address;
}

// RFC 6762 §6.2: advertised addresses must be valid on the announcing link.
inline void resolve_advertised_addresses(const std::vector<network_interface> &interfaces,
                                         const interface_binding &binding, service_info &info)
{
    if(!info.auto_address)
        return;

    const network_interface *bound = find_interface(interfaces, binding);
    for(bool ipv6 : {false, true})
    {
        std::optional<std::string> &field = ipv6 ? info.address_ipv6 : info.address_ipv4;
        if(field.has_value())
            continue;
        std::string address = advertised_address(interfaces, bound, binding, ipv6);
        if(!address.empty())
            field = std::move(address);
    }
}

}

#endif
