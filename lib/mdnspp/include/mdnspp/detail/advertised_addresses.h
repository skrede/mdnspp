#ifndef HPP_GUARD_MDNSPP_DETAIL_ADVERTISED_ADDRESSES_H
#define HPP_GUARD_MDNSPP_DETAIL_ADVERTISED_ADDRESSES_H

#include "mdnspp/detail/ip_address_ops.h"
#include "mdnspp/detail/native_sockaddr.h"
#include "mdnspp/detail/egress_interface.h"
#include "mdnspp/detail/interface_resolve.h"
#include "mdnspp/detail/interface_addresses.h"

#include "mdnspp/endpoint.h"
#include "mdnspp/ip_address.h"
#include "mdnspp/service_info.h"
#include "mdnspp/network_interface.h"

#include <string>
#include <vector>
#include <cstdint>
#include <utility>
#include <optional>
#include <string_view>
#include <system_error>

namespace mdnspp::detail {

struct announcing_link
{
    const network_interface *nic;
    bool ipv6_valid;
};

// An unpinned IPv6 socket joins and sends wherever the kernel routes each packet, so no IPv6 address of the IPv4
// egress interface is known to be valid where it sends.
inline announcing_link select_announcing_link(const std::vector<network_interface> &interfaces,
                                              const interface_binding &binding, uint32_t pinned_index,
                                              const endpoint &group, std::error_code &ec)
{
    ec.clear();
    if(binding.bound())
        return {find_interface(interfaces, binding), true};
    if(pinned_index != 0)
        return {find_interface(interfaces, interface_binding{.index = pinned_index}), true};
    return {find_egress_interface(interfaces, group, ec), !is_ipv6(group.address)};
}

inline bool address_is_ipv6(std::string_view address) noexcept
{
    return address.find(':') != std::string_view::npos;
}

inline std::string first_address_text(const network_interface &nic, bool ipv6)
{
    const ip_network *net = first_address(nic, ipv6 ? address_family::ipv6 : address_family::ipv4);
    return net != nullptr ? format_ip_address(net->address) : std::string{};
}

inline std::string advertised_address(const interface_binding &binding, const announcing_link &link, bool ipv6)
{
    if(link.nic == nullptr && !binding.address.empty())
        return address_is_ipv6(binding.address) == ipv6 ? binding.address : std::string{};
    if(link.nic == nullptr || (ipv6 && !link.ipv6_valid))
        return {};
    return first_address_text(*link.nic, ipv6);
}

// RFC 6762 §6.2: advertised addresses must be valid on the announcing link.
inline void resolve_advertised_addresses(const interface_binding &binding, const announcing_link &link,
                                         service_info &info)
{
    if(!info.auto_address)
        return;

    for(bool ipv6 : {false, true})
    {
        std::optional<std::string> &field = ipv6 ? info.address_ipv6 : info.address_ipv4;
        if(field.has_value())
            continue;
        std::string address = advertised_address(binding, link, ipv6);
        if(!address.empty())
            field = std::move(address);
    }
}

}

#endif
