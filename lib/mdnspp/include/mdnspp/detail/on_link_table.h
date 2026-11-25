#ifndef HPP_GUARD_MDNSPP_DETAIL_ON_LINK_TABLE_H
#define HPP_GUARD_MDNSPP_DETAIL_ON_LINK_TABLE_H

#include "mdnspp/detail/compat.h"
#include "mdnspp/detail/ip_address_ops.h"
#include "mdnspp/detail/interface_addresses.h"

#include "mdnspp/ip_address.h"
#include "mdnspp/network_interface.h"

#include <chrono>
#include <vector>
#include <cstdint>
#include <utility>
#include <optional>
#include <algorithm>
#include <system_error>

namespace mdnspp::detail {

inline bool in_any_prefix(const network_interface &nic, const ip_address &source) noexcept
{
    return std::ranges::any_of(nic.addresses, [&source](const ip_network &net)
    {
        return net.prefix_length != 0 && in_prefix(source, net.address, net.prefix_length);
    });
}

// RFC 6762 section 11 tests the source against the prefixes of the receiving interface. A source equal to one of this
// host's own addresses passes as well: a datagram the host sends itself arrives on loopback, outside its prefix.
template <typename Clock>
class on_link_table
{
public:
    using enumerator = move_only_function<std::vector<network_interface>(std::error_code &)>;

    explicit on_link_table(enumerator enumerate)
        : m_enumerate_cb(std::move(enumerate))
        , m_interfaces()
        , m_refreshed()
    {
    }

    bool on_link(const ip_address &source, uint32_t recv_ifindex, uint32_t bound_ifindex)
    {
        const uint32_t selected = recv_ifindex != 0 ? recv_ifindex : bound_ifindex;
        return matches(source, selected) || (refresh() && matches(source, selected));
    }

private:
    enumerator m_enumerate_cb;
    std::vector<network_interface> m_interfaces;
    std::optional<typename Clock::time_point> m_refreshed;

    bool matches(const ip_address &source, uint32_t selected) const noexcept
    {
        const auto local = [&source](const network_interface &nic) { return contains(nic, source); };
        const auto on_selected = [&source, selected](const network_interface &nic)
        {
            return (selected == 0 || nic.index == selected) && in_any_prefix(nic, source);
        };
        return std::ranges::any_of(m_interfaces, local) || std::ranges::any_of(m_interfaces, on_selected);
    }

    // Only a miss refreshes, and at most once per second, so off-link traffic cannot drive enumeration.
    bool refresh()
    {
        const typename Clock::time_point now = Clock::now();
        if(m_refreshed && now - *m_refreshed < std::chrono::seconds{1})
            return false;
        m_refreshed = now;
        std::error_code ec;
        std::vector<network_interface> fresh = m_enumerate_cb(ec);
        if(ec)
            return false;
        m_interfaces = std::move(fresh);
        return true;
    }
};

}

#endif
