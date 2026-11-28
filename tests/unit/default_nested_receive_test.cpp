#include "mdnspp/default/default_timer.h"

#include "support/native_udp.h"

#include <catch2/catch_test_macros.hpp>

#include <poll.h>

#include <netinet/in.h>

#include <sys/socket.h>

#include <span>
#include <array>
#include <chrono>
#include <string>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <system_error>

using namespace std::chrono_literals;
using mdnspp::detail::native_socket_t;
using mdnspp::test_support::loopback;
using mdnspp::test_support::udp_socket;
using mdnspp::test_support::bind_loopback;

namespace {

constexpr std::size_t level_count = 3;
constexpr std::array<std::string_view, level_count> payloads{"outer", "nested!", "deepest-level"};

class level_sockets
{
public:
    level_sockets()
        : m_sender_ports{}
        , m_receiver_ports{}
        , m_senders{}
        , m_receivers{}
    {
        for(std::size_t i = 0; i < level_count; ++i)
        {
            m_sender_ports[i] = bind_loopback(m_senders[i].fd());
            m_receiver_ports[i] = bind_loopback(m_receivers[i].fd());
        }
    }

    native_socket_t receiver(std::size_t level) const
    {
        return m_receivers[level].fd();
    }

    uint16_t sender_port(std::size_t level) const
    {
        return m_sender_ports[level];
    }

    void send_and_wait(std::size_t level) const
    {
        const sockaddr_in to = loopback(m_receiver_ports[level]);
        ::sendto(m_senders[level].fd(), payloads[level].data(), payloads[level].size(), 0,
                 reinterpret_cast<const sockaddr *>(&to), sizeof(to));
        pollfd entry{receiver(level), POLLIN, 0};
        ::poll(&entry, 1, 2000);
    }

private:
    std::array<uint16_t, level_count> m_sender_ports;
    std::array<uint16_t, level_count> m_receiver_ports;
    std::array<udp_socket, level_count> m_senders;
    std::array<udp_socket, level_count> m_receivers;
};

struct observation
{
    std::string bytes;
    uint16_t sender_port;
    int32_t calls;
};

using observations = std::array<observation, level_count>;

void arm_levels(mdnspp::default_context &ctx, const level_sockets &net, observations &seen, std::size_t depth)
{
    for(std::size_t level = 0; level < depth; ++level)
    {
        ctx.register_socket(net.receiver(level));
        ctx.arm_receive(net.receiver(level),
                        [&ctx, &net, &seen, level, depth](std::error_code, const mdnspp::recv_metadata &meta,
                                                          std::span<std::byte> data)
                        {
                            ++seen[level].calls;
                            if(level + 1 < depth)
                            {
                                net.send_and_wait(level + 1);
                                ctx.poll_one();
                            }
                            seen[level].bytes.assign(reinterpret_cast<const char *>(data.data()), data.size());
                            seen[level].sender_port = meta.sender.port;
                        });
    }
}

observations run_nested(std::size_t depth, const level_sockets &net)
{
    mdnspp::default_context ctx;
    observations seen{};
    arm_levels(ctx, net, seen, depth);
    net.send_and_wait(0);
    const auto deadline = std::chrono::steady_clock::now() + 2s;
    while(seen[0].calls == 0 && std::chrono::steady_clock::now() < deadline)
        ctx.poll_one();
    return seen;
}

}

TEST_CASE("an outer receive handler keeps its datagram and sender across a nested poll", "[default_context]")
{
    const level_sockets net;
    const observations seen = run_nested(2, net);
    REQUIRE(seen[0].calls == 1);
    REQUIRE(seen[1].calls == 1);
    CHECK(seen[1].bytes == payloads[1]);
    CHECK(seen[0].bytes == payloads[0]);
    CHECK(seen[0].sender_port == net.sender_port(0));
}

TEST_CASE("every receive handler keeps its datagram and sender across two nested polls", "[default_context]")
{
    const level_sockets net;
    const observations seen = run_nested(3, net);
    REQUIRE(seen[0].calls == 1);
    REQUIRE(seen[1].calls == 1);
    REQUIRE(seen[2].calls == 1);
    CHECK(seen[2].bytes == payloads[2]);
    CHECK(seen[1].bytes == payloads[1]);
    CHECK(seen[1].sender_port == net.sender_port(1));
    CHECK(seen[0].bytes == payloads[0]);
    CHECK(seen[0].sender_port == net.sender_port(0));
}
