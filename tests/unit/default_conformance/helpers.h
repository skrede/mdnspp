#ifndef HPP_GUARD_MDNSPP_DEFAULT_CONFORMANCE_HELPERS_H
#define HPP_GUARD_MDNSPP_DEFAULT_CONFORMANCE_HELPERS_H

#include "support/construct_or_skip.h"

#include "mdnspp/default/default_policy.h"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <string>
#include <thread>
#include <cstdint>

#ifndef _WIN32
#  include <arpa/inet.h>
#  include <fcntl.h>
#  include <netinet/in.h>
#  include <sys/socket.h>
#  include <unistd.h>
#endif

using namespace std::chrono_literals;
using mdnspp::test_support::construct_or_skip;

inline void run_stopped_from_thread(mdnspp::default_context &ctx, std::chrono::milliseconds delay)
{
    std::thread stopper{
        [&ctx, delay]
        {
            std::this_thread::sleep_for(delay);
            ctx.stop();
        }
    };
    ctx.run();
    stopper.join();
}

struct loopback_socket
{
    mdnspp::default_context ctx;
    mdnspp::detail::native_socket_t fd;
    sockaddr_in addr;

    loopback_socket()
        : ctx{}, fd{::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)}, addr{}
    {
        REQUIRE(fd != mdnspp::detail::invalid_socket);
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        REQUIRE(::bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0);
        read_bound_port();
        make_non_blocking();
    }

    ~loopback_socket()
    {
        mdnspp::detail::close_socket(fd);
    }

    loopback_socket(const loopback_socket &) = delete;
    loopback_socket &operator=(const loopback_socket &) = delete;

    bool send_to_self(const std::string &payload)
    {
#ifdef _WIN32
        const int sent = ::sendto(fd, payload.data(), static_cast<int>(payload.size()), 0,
                                  reinterpret_cast<sockaddr *>(&addr), sizeof(addr));
        return sent == static_cast<int>(payload.size());
#else
        const ssize_t sent = ::sendto(fd, payload.data(), payload.size(), 0,
                                      reinterpret_cast<sockaddr *>(&addr), sizeof(addr));
        return sent == static_cast<ssize_t>(payload.size());
#endif
    }

    template <typename Done>
    void poll_until(Done done)
    {
        for(int32_t attempt = 0; attempt < 50 && !done(); ++attempt)
        {
            ctx.poll_one();
            std::this_thread::sleep_for(1ms);
        }
    }

private:
    void read_bound_port()
    {
#ifdef _WIN32
        int len = sizeof(addr);
#else
        socklen_t len = sizeof(addr);
#endif
        REQUIRE(::getsockname(fd, reinterpret_cast<sockaddr *>(&addr), &len) == 0);
    }

    void make_non_blocking()
    {
#ifdef _WIN32
        u_long mode = 1;
        REQUIRE(::ioctlsocket(fd, FIONBIO, &mode) == 0);
#else
        int flags = ::fcntl(fd, F_GETFL, 0);
        REQUIRE(flags >= 0);
        REQUIRE(::fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0);
#endif
    }
};

#endif
