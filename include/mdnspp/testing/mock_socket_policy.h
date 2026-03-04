#ifndef HPP_GUARD_MDNSPP_TESTING_MOCK_SOCKET_POLICY_H
#define HPP_GUARD_MDNSPP_TESTING_MOCK_SOCKET_POLICY_H

#include "mdnspp/endpoint.h"
#include <span>
#include <cstddef>
#include <functional>
#include <utility>
#include <vector>
#include <queue>

namespace mdnspp::testing {

struct sent_packet
{
    endpoint dest;
    std::vector<std::byte> data;
};

class MockSocketPolicy
{
public:
    // Enqueue a packet with a specific sender endpoint.
    // The endpoint is delivered to the async_receive handler instead of endpoint{}.
    void enqueue(std::vector<std::byte> packet, endpoint from)
    {
        m_receive_queue.push({std::move(packet), std::move(from)});
    }

    // Enqueue a packet with the default sender (endpoint{}).
    // Backward-compatible: existing code calling enqueue(packet) is unchanged.
    void enqueue(std::vector<std::byte> packet)
    {
        enqueue(std::move(packet), endpoint{});
    }

    void async_receive(std::function<void(std::span<std::byte>, endpoint)> handler)
    {
        if(!m_receive_queue.empty())
        {
            // Copy and pop before calling handler so recursive arm_receive()
            // calls see the queue as already consumed.
            auto [packet, sender] = std::move(m_receive_queue.front());
            m_receive_queue.pop();
            handler(std::span<std::byte>(packet), std::move(sender));
        }
    }

    void send(endpoint dest, std::span<const std::byte> data)
    {
        m_sent_packets.push_back(sent_packet{
            dest,
            std::vector<std::byte>(data.begin(), data.end())
        });
    }

    void close() noexcept
    {
    }

    const std::vector<sent_packet> &sent_packets() const
    {
        return m_sent_packets;
    }

    bool queue_empty() const
    {
        return m_receive_queue.empty();
    }

    void clear_sent()
    {
        m_sent_packets.clear();
    }

private:
    std::queue<std::pair<std::vector<std::byte>, endpoint>> m_receive_queue;
    std::vector<sent_packet> m_sent_packets;
};

}

#endif
