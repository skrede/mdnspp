#ifndef HPP_GUARD_MDNSPP_INPROC_INPROC_BUS_H
#define HPP_GUARD_MDNSPP_INPROC_INPROC_BUS_H

#include "mdnspp/inproc/inproc_socket_options.h"

#include "mdnspp/endpoint.h"
#include "mdnspp/socket_options.h"

#include <span>
#include <array>
#include <deque>
#include <chrono>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <charconv>
#include <algorithm>
#include <functional>
#include <system_error>

namespace mdnspp::inproc {

class inproc_receiver
{
public:
    virtual ~inproc_receiver() = default;

    virtual void deliver(const endpoint &from, const endpoint &to, std::span<const std::byte> data) = 0;
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
        uint32_t id;
        endpoint assigned_ep;
        endpoint group;
        bool loopback;
    };

public:
    explicit inproc_bus(uint16_t start_port = 5353)
        : m_port(start_port)
        , m_next_id(1)
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
        std::error_code ec;
        endpoint assigned = register_socket(receiver, opts, ec);
        if(ec)
            throw std::system_error(ec, "mdnspp::inproc::inproc_bus::register_socket");
        return assigned;
    }

    // Registrations take the addresses of 127.0.0.0/8 in order and never reuse one, skipping the network and
    // broadcast addresses, so one bus hands out at most 2^24 - 2 endpoints.
    endpoint register_socket(inproc_receiver &receiver, const inproc_socket_options &opts, std::error_code &ec)
    {
        if(m_next_id > last_address_id)
        {
            ec = std::make_error_code(std::errc::address_not_available);
            return endpoint{};
        }
        ec.clear();
        endpoint assigned{loopback_address(m_next_id), opts.port_override.value_or(m_port)};
        m_sockets.push_back(socket_entry{
            receiver,
            m_next_id++,
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
    static constexpr uint32_t last_address_id = 0xFFFFFE;

    uint16_t m_port;
    uint32_t m_next_id;
    std::deque<queued_packet> m_queue;
    std::vector<socket_entry> m_sockets;

    static std::string loopback_address(uint32_t id)
    {
        std::array<char, 16> text{'1', '2', '7'};
        char *end = text.data() + 3;
        for(uint32_t shift : {16u, 8u, 0u})
        {
            *end++ = '.';
            end = std::to_chars(end, text.data() + text.size(), (id >> shift) & 0xFFu).ptr;
        }
        return std::string(text.data(), end);
    }

    bool deliver_unicast(const queued_packet &pkt)
    {
        for(auto &entry : m_sockets)
        {
            if(pkt.to == entry.assigned_ep)
            {
                entry.receiver.get().deliver(pkt.from, pkt.to, std::span<const std::byte>(pkt.data));
                return true;
            }
        }
        return false;
    }

    static bool takes_multicast(const socket_entry &entry, const queued_packet &pkt)
    {
        return pkt.to == entry.group && (entry.loopback || entry.assigned_ep != pkt.from);
    }

    // A handler may open or close sockets: the packet goes to the sockets registered when its delivery began that are
    // still registered when their turn comes.
    void deliver_multicast(const queued_packet &pkt)
    {
        std::vector<uint32_t> targets;
        for(const socket_entry &entry : m_sockets)
        {
            if(takes_multicast(entry, pkt))
                targets.push_back(entry.id);
        }
        for(uint32_t id : targets)
        {
            auto it = std::ranges::find(m_sockets, id, &socket_entry::id);
            if(it != m_sockets.end())
                it->receiver.get().deliver(pkt.from, pkt.to, std::span<const std::byte>(pkt.data));
        }
    }
};

}

#endif
