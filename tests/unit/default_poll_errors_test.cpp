#include "mdnspp/default/default_timer.h"

#include <catch2/catch_test_macros.hpp>

#include <fcntl.h>
#include <unistd.h>

#include <netinet/in.h>

#include <sys/socket.h>
#include <sys/resource.h>

#include <span>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <system_error>

using namespace std::chrono_literals;
using mdnspp::detail::native_socket_t;

namespace {

struct completion
{
    int32_t calls;
    std::error_code ec;
};

class udp_socket
{
public:
    udp_socket()
        : m_fd{::socket(AF_INET, SOCK_DGRAM, 0)}
    {
        ::fcntl(m_fd, F_SETFL, ::fcntl(m_fd, F_GETFL) | O_NONBLOCK);
    }

    ~udp_socket()
    {
        if(m_fd >= 0)
            ::close(m_fd);
    }

    udp_socket(const udp_socket &) = delete;
    udp_socket &operator=(const udp_socket &) = delete;

    native_socket_t fd() const
    {
        return m_fd;
    }

    void close_behind_registry()
    {
        ::close(m_fd);
        m_fd = -1;
    }

private:
    native_socket_t m_fd;
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

sockaddr_in loopback(uint16_t port)
{
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return addr;
}

uint16_t unused_port()
{
    udp_socket probe;
    sockaddr_in addr = loopback(0);
    socklen_t len = sizeof(addr);
    ::bind(probe.fd(), reinterpret_cast<sockaddr *>(&addr), len);
    ::getsockname(probe.fd(), reinterpret_cast<sockaddr *>(&addr), &len);
    return ntohs(addr.sin_port);
}

class fd_limit_guard
{
public:
    explicit fd_limit_guard(rlim_t soft)
        : m_saved{}
    {
        ::getrlimit(RLIMIT_NOFILE, &m_saved);
        rlimit lowered = m_saved;
        lowered.rlim_cur = soft;
        ::setrlimit(RLIMIT_NOFILE, &lowered);
    }

    ~fd_limit_guard()
    {
        ::setrlimit(RLIMIT_NOFILE, &m_saved);
    }

    fd_limit_guard(const fd_limit_guard &) = delete;
    fd_limit_guard &operator=(const fd_limit_guard &) = delete;

private:
    rlimit m_saved;
};

// Linux poll() fails with EINVAL once nfds exceeds the soft RLIMIT_NOFILE (poll(2)).
template <typename F>
std::error_code thrown_under_fd_limit(F &&fn)
{
    const fd_limit_guard guard{1};
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
