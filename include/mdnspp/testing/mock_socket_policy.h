#ifndef HPP_GUARD_MDNSPP_TESTING_MOCK_SOCKET_POLICY_H
#define HPP_GUARD_MDNSPP_TESTING_MOCK_SOCKET_POLICY_H

#include "mdnspp/endpoint.h"
#include <span>
#include <cstddef>
#include <functional>
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
    void enqueue(std::vector<std::byte> packet)
    {
        m_receive_queue.push(std::move(packet));
    }

    void async_receive(std::function<void(std::span<std::byte>, endpoint)> handler)
    {
        if(!m_receive_queue.empty())
        {
            // Copy and pop before calling handler so recursive arm_receive()
            // calls see the queue as already consumed.
            std::vector<std::byte> packet = std::move(m_receive_queue.front());
            m_receive_queue.pop();
            handler(std::span<std::byte>(packet), endpoint{});
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
    std::queue<std::vector<std::byte>> m_receive_queue;
    std::vector<sent_packet> m_sent_packets;
};

}

#endif
