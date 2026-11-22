#ifndef HPP_GUARD_MDNSPP_INPROC_INPROC_BUS_H
#define HPP_GUARD_MDNSPP_INPROC_INPROC_BUS_H

#include "mdnspp/inproc/inproc_socket_options.h"

#include "mdnspp/endpoint.h"
#include "mdnspp/socket_options.h"

#include <span>
#include <deque>
#include <chrono>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <algorithm>
#include <functional>

namespace mdnspp::inproc {

class inproc_receiver
{
public:
    virtual ~inproc_receiver() = default;

    virtual void deliver(const endpoint &from, std::span<const std::byte> data) = 0;
};

template <typename Clock = std::chrono::steady_clock>
class inproc_bus
{
    struct queued_packet
    {
        endpoint from;
        endpoint to;
        std::vector<std::byte> data;
    };

    struct socket_entry
    {
        std::reference_wrapper<inproc_receiver> receiver;
        endpoint assigned_ep;
        endpoint group;
        bool loopback;
    };

public:
    explicit inproc_bus(uint16_t start_port = 5353)
        : m_port(start_port)
        , m_next_ip{1}
        , m_queue()
        , m_sockets()
    {
    }

    inproc_bus(const inproc_bus &) = delete;
    inproc_bus &operator=(const inproc_bus &) = delete;
    inproc_bus(inproc_bus &&) = delete;
    inproc_bus &operator=(inproc_bus &&) = delete;

    endpoint register_socket(inproc_receiver &receiver, const inproc_socket_options &opts)
    {
        uint16_t port = opts.port_override.value_or(m_port);
        endpoint assigned{"127.0.0." + std::to_string(m_next_ip++), port};
        m_sockets.push_back(socket_entry{
            receiver,
            assigned,
            opts.multicast_group,
            opts.multicast_loopback == loopback_mode::enabled
        });
        return assigned;
    }

    void deregister_socket(inproc_receiver &receiver) noexcept
    {
        std::erase_if(m_sockets, [&receiver](const socket_entry &e) { return &e.receiver.get() == &receiver; });
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

        if(!deliver_unicast(pkt))
            deliver_multicast(pkt);

        return true;
    }

    bool has_pending_packets() const noexcept
    {
        return !m_queue.empty();
    }

private:
    uint16_t m_port;
    uint8_t m_next_ip;
    std::deque<queued_packet> m_queue;
    std::vector<socket_entry> m_sockets;

    bool deliver_unicast(const queued_packet &pkt)
    {
        for(auto &entry : m_sockets)
        {
            if(pkt.to == entry.assigned_ep)
            {
                entry.receiver.get().deliver(pkt.from, std::span<const std::byte>(pkt.data));
                return true;
            }
        }
        return false;
    }

    void deliver_multicast(const queued_packet &pkt)
    {
        for(auto &entry : m_sockets)
        {
            if(pkt.to != entry.group)
                continue;
            if(!entry.loopback && entry.assigned_ep == pkt.from)
                continue;
            entry.receiver.get().deliver(pkt.from, std::span<const std::byte>(pkt.data));
        }
    }
};

}

#endif
