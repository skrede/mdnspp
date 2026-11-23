#ifndef HPP_GUARD_MDNSPP_GATE_INTERFACES_H
#define HPP_GUARD_MDNSPP_GATE_INTERFACES_H

#include "mdnspp/ip_address.h"
#include "mdnspp/network_interface.h"

#include "mdnspp/detail/ip_address_ops.h"

#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <string_view>
#include <system_error>
#include <initializer_list>

struct interface_snapshot
{
    explicit interface_snapshot(std::vector<mdnspp::network_interface> nics)
        : fail(false)
        , calls(0)
        , interfaces(std::move(nics))
    {
    }

    bool fail;
    std::size_t calls;
    std::vector<mdnspp::network_interface> interfaces;
};

inline mdnspp::ip_network network_of(std::string_view address, uint8_t prefix_length)
{
    return mdnspp::ip_network{*mdnspp::detail::parse_ip_address(address), prefix_length};
}

inline mdnspp::network_interface nic_with(uint32_t index, std::initializer_list<mdnspp::ip_network> addresses)
{
    return mdnspp::network_interface{.name = "nic" + std::to_string(index),
                                     .addresses = addresses,
                                     .index = index,
                                     .is_loopback = false,
                                     .is_up = true};
}

inline auto enumerate_from(interface_snapshot &snapshot)
{
    return [&snapshot](std::error_code &ec)
    {
        ++snapshot.calls;
        if(snapshot.fail)
            ec = std::make_error_code(std::errc::io_error);
        return snapshot.fail ? std::vector<mdnspp::network_interface>{} : snapshot.interfaces;
    };
}

inline std::vector<mdnspp::network_interface> no_interfaces(std::error_code &ec)
{
    ec.clear();
    return {};
}

#endif
