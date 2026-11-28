#ifndef HPP_GUARD_MDNSPP_TESTING_MOCK_RECEIVE_QUEUE_H
#define HPP_GUARD_MDNSPP_TESTING_MOCK_RECEIVE_QUEUE_H

#include "mdnspp/policy.h"
#include "mdnspp/endpoint.h"

#include "mdnspp/detail/compat.h"
#include "mdnspp/detail/ip_address_ops.h"

#include <span>
#include <queue>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <system_error>

namespace mdnspp::testing {

// The defaults describe a datagram multicast to the group from a peer on the group port, so traffic a test does not
// describe looks like ordinary mDNS traffic.
inline recv_metadata default_receive_metadata(const endpoint &group)
{
    return recv_metadata{.sender = endpoint{{}, group.port}, .ttl = uint8_t{255}, .recv_ifindex = 0,
                         .destination = detail::parse_ip_address(group.address)};
}

class mock_receive_queue
{
    struct queued_item
    {
        std::vector<std::byte> packet;
        recv_metadata meta;
    };

public:
    using receive_handler = move_only_function<void(std::error_code, const recv_metadata &, std::span<std::byte>)>;

    mock_receive_queue()
        : m_receive_cb()
        , m_items()
    {
    }

    void push(std::vector<std::byte> packet, recv_metadata meta)
    {
        m_items.push(queued_item{std::move(packet), std::move(meta)});
    }

    void receive(receive_handler handler)
    {
        if(m_items.empty())
        {
            m_receive_cb = std::move(handler);
            return;
        }
        queued_item item = std::move(m_items.front());
        m_items.pop();
        handler(std::error_code{}, item.meta, std::span<std::byte>(item.packet));
    }

    void inject(recv_metadata meta, std::vector<std::byte> packet)
    {
        if(!m_receive_cb)
            return push(std::move(packet), std::move(meta));
        auto handler = std::exchange(m_receive_cb, nullptr);
        handler(std::error_code{}, meta, std::span<std::byte>(packet));
    }

    void inject_error(std::error_code ec)
    {
        if(!m_receive_cb)
            return;
        auto handler = std::exchange(m_receive_cb, nullptr);
        handler(ec, recv_metadata{}, std::span<std::byte>{});
    }

    void cancel() noexcept { m_receive_cb = nullptr; }
    bool has_pending() const noexcept { return m_receive_cb != nullptr; }
    bool empty() const noexcept { return m_items.empty(); }

private:
    receive_handler m_receive_cb;
    std::queue<queued_item> m_items;
};

}

#endif
