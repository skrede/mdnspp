#include "mdnspp/default/default_timer.h"

#include "support/fd_limit.h"
#include "support/native_udp.h"

#include <catch2/catch_test_macros.hpp>

#include <netinet/in.h>

#include <sys/socket.h>

#include <span>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <system_error>

using namespace std::chrono_literals;
using mdnspp::detail::native_socket_t;
using mdnspp::test_support::loopback;
using mdnspp::test_support::udp_socket;
using mdnspp::test_support::bind_loopback;
using mdnspp::test_support::fd_limit_guard;
using mdnspp::test_support::skip_unless_lowered;
using mdnspp::test_support::skip_under_address_sanitizer;

namespace {

struct completion
{
    int32_t calls;
    std::error_code ec;
};

void arm(mdnspp::default_context &ctx, native_socket_t fd, completion &done)
{
    ctx.register_socket(fd);
    ctx.arm_receive(fd, [&done](std::error_code ec, const mdnspp::recv_metadata &, std::span<std::byte>)
    {
        ++done.calls;
        done.ec = ec;
    });
}

}

TEST_CASE("a descriptor closed behind the registry completes its handler once with bad_file_descriptor", "[default_context]")
{
    mdnspp::default_context ctx;
    udp_socket sock;
    const native_socket_t fd = sock.fd();
    completion done{};
    arm(ctx, fd, done);
    sock.close_behind_registry();
    ctx.poll_one();
    ctx.poll_one();
    ctx.deregister_socket(fd);
    REQUIRE(done.calls == 1);
    REQUIRE(done.ec == std::errc::bad_file_descriptor);
}

#ifdef __linux__

namespace {

uint16_t unused_port()
{
    const udp_socket probe;
    return bind_loopback(probe.fd());
}

// Linux poll() fails with EINVAL once nfds exceeds the soft RLIMIT_NOFILE (poll(2)).
template <typename F>
std::error_code thrown_under_fd_limit(F &&fn)
{
    const fd_limit_guard guard{1};
    skip_unless_lowered(guard);
    try
    {
        fn();
    }
    catch(const std::system_error &e)
    {
        return e.code();
    }
    return std::error_code{};
}

template <typename F>
std::error_code reported_under_fd_limit(F &&fn)
{
    const fd_limit_guard guard{1};
    skip_unless_lowered(guard);
    std::error_code ec;
    fn(ec);
    return ec;
}

}

TEST_CASE("a pending socket error completes the armed handler", "[default_context]")
{
    mdnspp::default_context ctx;
    udp_socket sock;
    sockaddr_in peer = loopback(unused_port());
    REQUIRE(::connect(sock.fd(), reinterpret_cast<sockaddr *>(&peer), sizeof(peer)) == 0);
    REQUIRE(::send(sock.fd(), "x", 1, 0) == 1);
    completion done{};
    arm(ctx, sock.fd(), done);
    const auto deadline = std::chrono::steady_clock::now() + 2s;
    while(done.calls == 0 && std::chrono::steady_clock::now() < deadline)
        ctx.poll_one();
    ctx.deregister_socket(sock.fd());
    REQUIRE(done.calls == 1);
    REQUIRE(done.ec == std::errc::connection_refused);
}

TEST_CASE("a failing poll is reported by both overloads of run and poll_one", "[default_context]")
{
    skip_under_address_sanitizer();
    mdnspp::default_context ctx;
    udp_socket sock;
    completion done{};
    arm(ctx, sock.fd(), done);
    const std::error_code thrown_poll = thrown_under_fd_limit([&] { ctx.poll_one(); });
    const std::error_code thrown_run = thrown_under_fd_limit([&] { ctx.run(); });
    const std::error_code reported_poll = reported_under_fd_limit([&](std::error_code &ec) { ctx.poll_one(ec); });
    const std::error_code reported_run = reported_under_fd_limit([&](std::error_code &ec) { ctx.run(ec); });
    ctx.deregister_socket(sock.fd());
    REQUIRE(thrown_poll == std::errc::invalid_argument);
    REQUIRE(thrown_run == std::errc::invalid_argument);
    REQUIRE(reported_poll == std::errc::invalid_argument);
    REQUIRE(reported_run == std::errc::invalid_argument);
    REQUIRE(done.calls == 0);
}

#endif
