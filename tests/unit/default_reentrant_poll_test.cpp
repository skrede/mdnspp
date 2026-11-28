#include "mdnspp/default/default_timer.h"

#include "support/native_udp.h"

#include <catch2/catch_test_macros.hpp>

#include <poll.h>

#include <netinet/in.h>

#include <sys/socket.h>

#include <span>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <algorithm>
#include <system_error>

using namespace std::chrono_literals;
using mdnspp::detail::native_socket_t;
using mdnspp::test_support::loopback;
using mdnspp::test_support::udp_socket;
using mdnspp::test_support::bind_loopback;

namespace {

constexpr std::size_t socket_count = 8;

class loopback_sockets
{
public:
    loopback_sockets()
        : m_sender{}
        , m_ports{}
        , m_sockets{}
    {
        for(std::size_t i = 0; i < socket_count; ++i)
            m_ports[i] = bind_loopback(m_sockets[i].fd());
    }

    native_socket_t fd(std::size_t i) const
    {
        return m_sockets[i].fd();
    }

    void send_to(std::size_t i) const
    {
        const sockaddr_in to = loopback(m_ports[i]);
        ::sendto(m_sender.fd(), "x", 1, 0, reinterpret_cast<const sockaddr *>(&to), sizeof(to));
    }

    std::size_t readable(std::size_t first, std::size_t last) const
    {
        std::size_t count = 0;
        for(std::size_t i = first; i < last; ++i)
        {
            pollfd entry{fd(i), POLLIN, 0};
            if(::poll(&entry, 1, 2000) == 1 && (entry.revents & POLLIN) != 0)
                ++count;
        }
        return count;
    }

private:
    udp_socket m_sender;
    std::array<uint16_t, socket_count> m_ports;
    std::array<udp_socket, socket_count> m_sockets;
};

struct reentry_probe
{
    std::array<int32_t, socket_count> calls;
    std::size_t outer_ready;
    std::size_t nested_ready;
};

void arm(mdnspp::default_context &ctx, loopback_sockets &sockets, reentry_probe &probe)
{
    for(std::size_t i = 0; i < socket_count; ++i)
        ctx.register_socket(sockets.fd(i));
    for(std::size_t i = 1; i < socket_count; ++i)
        ctx.arm_receive(sockets.fd(i), [&probe, i](std::error_code, const mdnspp::recv_metadata &, std::span<std::byte>)
        {
            ++probe.calls[i];
        });
    ctx.arm_receive(sockets.fd(0), [&](std::error_code, const mdnspp::recv_metadata &, std::span<std::byte>)
    {
        ++probe.calls[0];
        for(std::size_t i = 2; i < socket_count; ++i)
            sockets.send_to(i);
        probe.nested_ready = sockets.readable(1, socket_count);
        ctx.poll_one();
    });
}

bool each_fired_once(const reentry_probe &probe)
{
    return std::ranges::all_of(probe.calls, [](int32_t calls) { return calls == 1; });
}

}

TEST_CASE("a receive handler that polls its context re-entrantly services every socket once", "[default_context]")
{
    loopback_sockets sockets;
    mdnspp::default_context ctx;
    reentry_probe probe{};
    arm(ctx, sockets, probe);
    sockets.send_to(0);
    sockets.send_to(1);
    probe.outer_ready = sockets.readable(0, 2);
    ctx.poll_one();
    const auto deadline = std::chrono::steady_clock::now() + 2s;
    while(!each_fired_once(probe) && std::chrono::steady_clock::now() < deadline)
        ctx.poll_one();
    // The outer dispatch sizes its ready list for two sockets; seven ready in the nested poll make it reallocate.
    REQUIRE(probe.outer_ready == 2);
    REQUIRE(probe.nested_ready == socket_count - 1);
    REQUIRE(each_fired_once(probe));
}
