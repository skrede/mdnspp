#ifndef HPP_GUARD_MDNSPP_NETWORK_INTERFACE_H
#define HPP_GUARD_MDNSPP_NETWORK_INTERFACE_H

#include <string>
#include <vector>
#include <cstdint>
#include <utility>
#include <system_error>
#include <unordered_map>

namespace mdnspp {

struct network_interface
{
    std::string name;
    std::string ipv4_address;
    std::string ipv6_address;
    uint32_t index{0};
    bool is_loopback{false};
    bool is_up{false};
};

namespace detail {

using interface_map = std::unordered_map<std::string, network_interface>;

inline void collect_interfaces(interface_map &by_name, std::error_code &ec);

}

inline std::vector<network_interface> enumerate_interfaces(std::error_code &ec)
{
    ec.clear();
    detail::interface_map by_name;
    detail::collect_interfaces(by_name, ec);
    if(ec)
        return {};

    std::vector<network_interface> result_vec;
    result_vec.reserve(by_name.size());
    for(auto &[_, iface] : by_name)
        result_vec.push_back(std::move(iface));

    return result_vec;
}

inline std::vector<network_interface> enumerate_interfaces()
{
    std::error_code ec;
    auto result = enumerate_interfaces(ec);
    if(ec)
        throw std::system_error{ec, "enumerate_interfaces"};
    return result;
}

}

#include "mdnspp/detail/interface_enumeration.h"

#endif
