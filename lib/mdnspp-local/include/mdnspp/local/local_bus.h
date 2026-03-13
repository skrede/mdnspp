#ifndef HPP_GUARD_MDNSPP_LOCAL_LOCAL_BUS_H
#define HPP_GUARD_MDNSPP_LOCAL_LOCAL_BUS_H

#include "mdnspp/endpoint.h"
#include "mdnspp/socket_options.h"

#include <span>
#include <deque>
#include <chrono>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <algorithm>

namespace mdnspp::local {

template <typename Clock>
class local_socket;

template <typename Clock = std::chrono::steady_clock>
class local_bus
{
public:
    local_bus() = default;

    local_bus(const local_bus &) = delete;
    local_bus &operator=(const local_bus &) = delete;
    local_bus(local_bus &&) = delete;
    local_bus &operator=(local_bus &&) = delete;

    endpoint register_socket(local_socket<Clock> *sock, const socket_options &opts)
    {
        endpoint assigned{"127.0.0.1", m_next_port++};
        m_sockets.push_back(socket_entry{
            sock,
            assigned,
            opts.multicast_group,
            opts.multicast_loopback == loopback_mode::enabled
        });
        return assigned;
    }

    void deregister_socket(local_socket<Clock> *sock) noexcept
    {
        std::erase_if(m_sockets, [sock](const socket_entry &e) { return e.sock == sock; });
    }

    void enqueue(const endpoint &from, const endpoint &to, std::span<const std::byte> data)
    {
        m_queue.push_back(queued_packet{
            from,
            to,
            std::vector<std::byte>(data.begin(), data.end())
        });
    }

    bool deliver_one()
    {
        if(m_queue.empty())
            return false;

        auto pkt = std::move(m_queue.front());
        m_queue.pop_front();

        bool delivered = false;

        for(auto &entry : m_sockets)
        {
            if(pkt.to == entry.assigned_ep)
            {
                // Unicast: deliver only to matching socket
                entry.sock->deliver(pkt.from, std::span<const std::byte>(pkt.data));
                delivered = true;
                break;
            }
        }

        if(!delivered)
        {
            // Multicast: deliver to all sockets in matching group
            for(auto &entry : m_sockets)
            {
                if(pkt.to != entry.group)
                    continue;

                // Skip sender if loopback is disabled
                if(!entry.loopback && entry.assigned_ep == pkt.from)
                    continue;

                entry.sock->deliver(pkt.from, std::span<const std::byte>(pkt.data));
            }
        }

        return true;
    }

    [[nodiscard]] bool has_pending_packets() const noexcept
    {
        return !m_queue.empty();
    }

private:
    struct queued_packet
    {
        endpoint from;
        endpoint to;
        std::vector<std::byte> data;
    };

    struct socket_entry
    {
        local_socket<Clock> *sock;
        endpoint assigned_ep;
        endpoint group;
        bool loopback;
    };

    std::vector<socket_entry> m_sockets;
    std::deque<queued_packet> m_queue;
    uint16_t m_next_port{10000};
};

}

#endif
