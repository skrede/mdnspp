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

// Socket-option interface binding, extracted from a policy's socket options.
// Resolution precedence: index > name > address (see socket_options).
struct interface_binding
{
    std::optional<uint32_t> index{};
    std::optional<std::string> name{};
    std::string address{};

    [[nodiscard]] bool bound() const noexcept
    {
        return index.has_value() || name.has_value() || !address.empty();
    }
};

// Extracts the binding fields from any socket-options type that carries them
// (socket_options and every type derived from it). Policies with unrelated
// socket-options types yield an unbound binding.
template <typename Opts>
[[nodiscard]] interface_binding extract_interface_binding(const Opts &opts)
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

// Family classification of an address string in presentation form: any
// colon-hex address is IPv6, everything else is treated as IPv4.
[[nodiscard]] inline bool address_is_ipv6(std::string_view address) noexcept
{
    return address.find(':') != std::string_view::npos;
}

// Finds the interface a binding designates, honoring the index > name >
// address precedence: when interface_index is set only an index match counts;
// otherwise when interface_name is set only a name match counts; otherwise a
// non-empty interface_address matches the interface owning that address.
// Returns nullptr when the binding is unbound or nothing matches.
[[nodiscard]] inline const network_interface *
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

// Resolves a binding to the interface address the multicast socket should use
// for the given family. interface_index / interface_name are translated to
// the matching interface's address of that family; an unknown index or name,
// or a match without an address of the family, sets
// std::errc::invalid_argument. A binding by address is returned verbatim
// (family validation stays with the socket's address parsing); an unbound
// binding yields the empty string (bind to all interfaces).
[[nodiscard]] inline std::string
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

// Enumerating wrapper used by the socket open paths: translates the binding
// fields of opts into the effective interface address for the socket family.
[[nodiscard]] inline std::string
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

// Fills the unset service_info address fields when info.auto_address is set
// (RFC 6762 §6.2: advertised addresses must be valid on the announcing link).
// Per family, in order:
//   1. The bound interface's address of that family, when the binding
//      designates an interface present in `interfaces` (an interface lacking
//      the family leaves the field unset — no cross-interface fallback).
//   2. The binding address itself, when bound by address only and the address
//      is of that family (covers links absent from `interfaces`).
//   3. Unbound: the address of the non-loopback, running interface with the
//      lowest interface index that has an address of that family.
// Fields already set are never overwritten; a family with no candidate stays
// unset (its records are simply not announced).
inline void resolve_advertised_addresses(const std::vector<network_interface> &interfaces,
                                         const interface_binding &binding, service_info &info)
{
    if(!info.auto_address)
        return;

    const network_interface *bound = find_interface(interfaces, binding);

    auto fallback = [&](bool ipv6) -> const network_interface *
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
    };

    auto fill = [&](std::optional<std::string> &field, bool ipv6)
    {
        if(field.has_value())
            return;
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
            if(const network_interface *nic = fallback(ipv6))
                address = ipv6 ? nic->ipv6_address : nic->ipv4_address;
        }
        if(!address.empty())
            field = std::move(address);
    };

    fill(info.address_ipv4, false);
    fill(info.address_ipv6, true);
}

}

#endif
