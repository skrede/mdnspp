#ifndef HPP_GUARD_MDNSPP_DETAIL_INTERFACE_RESOLVE_H
#define HPP_GUARD_MDNSPP_DETAIL_INTERFACE_RESOLVE_H

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
        return find([&](const network_interface &nic)
        {
            return nic.ipv4_address == binding.address || nic.ipv6_address == binding.address;
        });
    return nullptr;
}

// A binding by address is passed through unchecked; the socket's address parsing validates its family.
inline std::string
select_interface_address(const std::vector<network_interface> &interfaces,
                         const interface_binding &binding, bool ipv6, std::error_code &ec)
{
    ec.clear();
    if(!binding.index.has_value() && !binding.name.has_value())
        return binding.address;

    const network_interface *nic = find_interface(interfaces, binding);
    if(nic == nullptr)
    {
        ec = std::make_error_code(std::errc::invalid_argument);
        return {};
    }

    const std::string &address = ipv6 ? nic->ipv6_address : nic->ipv4_address;
    if(address.empty())
    {
        ec = std::make_error_code(std::errc::invalid_argument);
        return {};
    }
    return address;
}

inline std::string
resolve_socket_interface_address(const socket_options &opts, bool ipv6, std::error_code &ec)
{
    ec.clear();
    if(!opts.interface_index.has_value() && !opts.interface_name.has_value())
        return opts.interface_address;

    auto interfaces = enumerate_interfaces(ec);
    if(ec)
        return {};
    return select_interface_address(interfaces, extract_interface_binding(opts), ipv6, ec);
}

inline const network_interface *
lowest_index_interface(const std::vector<network_interface> &interfaces, bool ipv6) noexcept
{
    const network_interface *best = nullptr;
    for(const auto &nic : interfaces)
    {
        if(nic.is_loopback || !nic.is_up)
            continue;
        if((ipv6 ? nic.ipv6_address : nic.ipv4_address).empty())
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
        address = ipv6 ? bound->ipv6_address : bound->ipv4_address;
    else if(!binding.address.empty())
    {
        if(address_is_ipv6(binding.address) == ipv6)
            address = binding.address;
    }
    else if(!binding.bound())
    {
        if(const network_interface *nic = lowest_index_interface(interfaces, ipv6))
            address = ipv6 ? nic->ipv6_address : nic->ipv4_address;
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
