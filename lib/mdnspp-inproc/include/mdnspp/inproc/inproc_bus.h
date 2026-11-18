#ifndef HPP_GUARD_MDNSPP_INPROC_INPROC_BUS_H
#define HPP_GUARD_MDNSPP_INPROC_INPROC_BUS_H

#include "mdnspp/endpoint.h"
#include "mdnspp/socket_options.h"

#include "mdnspp/inproc/inproc_socket_options.h"

#include <span>
#include <deque>
#include <chrono>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <algorithm>

namespace mdnspp::inproc {

template <typename Clock>
class inproc_socket;

template <typename Clock = std::chrono::steady_clock>
class inproc_bus
{
public:
    explicit inproc_bus(uint16_t start_port = 5353)
        : m_port(start_port)
    {
    }

    inproc_bus(const inproc_bus &) = delete;
    inproc_bus &operator=(const inproc_bus &) = delete;
    inproc_bus(inproc_bus &&) = delete;
    inproc_bus &operator=(inproc_bus &&) = delete;

    endpoint register_socket(inproc_socket<Clock> *sock, const inproc_socket_options &opts)
    {
        uint16_t port = opts.port_override.value_or(m_port);
        endpoint assigned{"127.0.0." + std::to_string(m_next_ip++), port};
        m_sockets.push_back(socket_entry{
            sock,
            assigned,
            opts.multicast_group,
            opts.multicast_loopback == loopback_mode::enabled
        });
        return assigned;
    }

    void deregister_socket(inproc_socket<Clock> *sock) noexcept
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
        inproc_socket<Clock> *sock;
        endpoint assigned_ep;
        endpoint group;
        bool loopback;
    };

    std::vector<socket_entry> m_sockets;
    std::deque<queued_packet> m_queue;
    uint16_t m_port{5353};
    uint8_t  m_next_ip{1};
};

}

#endif
