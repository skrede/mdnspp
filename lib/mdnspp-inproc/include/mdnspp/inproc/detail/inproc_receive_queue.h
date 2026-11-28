#ifndef HPP_GUARD_MDNSPP_INPROC_DETAIL_INPROC_RECEIVE_QUEUE_H
#define HPP_GUARD_MDNSPP_INPROC_DETAIL_INPROC_RECEIVE_QUEUE_H

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

// In mdnspp::detail rather than mdnspp::inproc::detail: a nested inproc::detail would shadow the
// detail::move_only_function lookups inside mdnspp::inproc.
namespace mdnspp::detail {

inline recv_metadata inproc_metadata(const endpoint &from, const endpoint &to)
{
    return recv_metadata{
        .sender = from, .ttl = uint8_t{255}, .recv_ifindex = 0, .destination = parse_ip_address(to.address)};
}

class inproc_receive_queue
{
    struct queued_packet
    {
        std::vector<std::byte> data;
        recv_metadata meta;
    };

public:
    using receive_handler = move_only_function<void(std::error_code, const recv_metadata &, std::span<std::byte>)>;

    inproc_receive_queue()
        : m_receive_cb()
        , m_buffer()
        , m_queue()
    {
    }

    void receive(receive_handler handler)
    {
        if(m_queue.empty())
        {
            m_receive_cb = std::move(handler);
            return;
        }
        queued_packet pkt = std::move(m_queue.front());
        m_queue.pop();
        handler(std::error_code{}, pkt.meta, std::span<std::byte>(pkt.data));
    }

    void deliver(const recv_metadata &meta, std::span<const std::byte> data)
    {
        if(!m_receive_cb)
        {
            m_queue.push(queued_packet{std::vector<std::byte>(data.begin(), data.end()), meta});
            return;
        }
        m_buffer.assign(data.begin(), data.end());
        auto handler = std::exchange(m_receive_cb, nullptr);
        handler(std::error_code{}, meta, std::span<std::byte>(m_buffer));
    }

    void clear() noexcept
    {
        m_receive_cb = nullptr;
        m_queue = {};
    }

private:
    receive_handler m_receive_cb;
    std::vector<std::byte> m_buffer;
    std::queue<queued_packet> m_queue;
};

}

#endif
