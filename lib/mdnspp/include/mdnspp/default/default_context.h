#ifndef HPP_GUARD_MDNSPP_DEFAULT_CONTEXT_H
#define HPP_GUARD_MDNSPP_DEFAULT_CONTEXT_H

// DefaultContext — standalone poll-based event loop for NativePolicy.
// No ASIO includes. POSIX/Linux primary, Windows via #ifdef guards.
//
// NOTE: compute_next_timeout_ms() and fire_expired_timers() are declared here
// but defined in native_timer.h (after DefaultTimer is fully defined), because
// they dereference DefaultTimer*. Include native_timer.h to get the full
// implementation — that header includes this one first.

#include "mdnspp/endpoint.h"

#include "mdnspp/detail/platform.h"

#include <span>
#include <array>
#include <atomic>
#include <chrono>
#include <vector>
#include <cstddef>
#include <functional>
#include <system_error>

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <arpa/inet.h>
#  include <fcntl.h>
#  include <netinet/in.h>
#  include <poll.h>
#  include <sys/socket.h>
#  include <unistd.h>
#  ifdef __linux__
#    include <sys/eventfd.h>
#  endif
#endif

namespace mdnspp {
namespace detail {

#ifdef _WIN32
using native_socket_t = SOCKET;
inline constexpr native_socket_t invalid_socket = INVALID_SOCKET;

inline void close_socket(native_socket_t fd) noexcept
{
    ::closesocket(fd);
}

inline int poll_sockets(pollfd *fds, unsigned long nfds, int timeout_ms)
{
    return ::WSAPoll(fds, nfds, timeout_ms);
}
#else
using native_socket_t = int;
inline constexpr native_socket_t invalid_socket = -1;

inline void close_socket(native_socket_t fd) noexcept
{
    ::close(fd);
}

inline int poll_sockets(pollfd *fds, nfds_t nfds, int timeout_ms)
{
    return ::poll(fds, nfds, timeout_ms);
}
#endif

}

class DefaultTimer;

// ---------------------------------------------------------------------------
// winsock_guard — RAII Winsock initializer. No-op on POSIX.
// ---------------------------------------------------------------------------
class winsock_guard
{
public:
    winsock_guard()
    {
#ifdef _WIN32
        WSADATA data{};
        if(const int rc = ::WSAStartup(MAKEWORD(2, 2), &data); rc != 0)
            throw std::system_error(rc, std::system_category(), "WSAStartup failed");
#endif
    }

    ~winsock_guard()
    {
#ifdef _WIN32
        ::WSACleanup();
#endif
    }

    winsock_guard(const winsock_guard &) = delete;
    winsock_guard &operator=(const winsock_guard &) = delete;
    winsock_guard(winsock_guard &&) = delete;
    winsock_guard &operator=(winsock_guard &&) = delete;
};

// ---------------------------------------------------------------------------
// DefaultContext — the event loop executor
// ---------------------------------------------------------------------------
class DefaultContext
{
public:
    /// Constructor — creates the stop-wakeup fd.
    /// Throws std::system_error on platform failure.
    DefaultContext()
    {
        create_wakeup_fd();
    }

    ~DefaultContext()
    {
        close_wakeup_fd();
    }

    DefaultContext(const DefaultContext &) = delete;
    DefaultContext &operator=(const DefaultContext &) = delete;
    DefaultContext(DefaultContext &&) = delete;
    DefaultContext &operator=(DefaultContext &&) = delete;

    /// Block until stop() is called, processing I/O and expired timers.
    void run()
    {
        m_stopped.store(false, std::memory_order_relaxed);
        while(!m_stopped.load(std::memory_order_acquire))
        {
            const auto now = std::chrono::steady_clock::now();
            const int timeout = compute_next_timeout_ms(now);
            const int rc = do_poll(timeout);

            if(rc < 0)
            {
#ifndef _WIN32
                if(errno == EINTR)
                    continue; // EINTR — retry
#endif
                break;
            }

            if(wakeup_readable())
            {
                drain_wakeup_fd();
                break;
            }

            if(data_readable())
                dispatch_receive();

            fire_expired_timers();
        }
    }

    void poll_one()
    {
        const int rc = do_poll(0);
        if(rc < 0)
            return;

        if(wakeup_readable())
        {
            drain_wakeup_fd();
            return;
        }

        if(data_readable())
        {
            dispatch_receive();
            return;
        }

        fire_expired_timers();
    }

    /// Signal the event loop to stop. Thread-safe and idempotent.
    void stop()
    {
        m_stopped.store(true, std::memory_order_release);
        write_wakeup_fd();
    }

    /// Reset the stopped flag so run() can be called again after stop().
    void restart()
    {
        m_stopped.store(false, std::memory_order_relaxed);
        drain_wakeup_fd();
    }

    // -----------------------------------------------------------------------
    // Internal interface — called by NativeSocket / DefaultTimer
    // -----------------------------------------------------------------------

    void register_socket(detail::native_socket_t fd)
    {
        m_socket_fd = fd;
    }

    void deregister_socket()
    {
        m_socket_fd = detail::invalid_socket;
    }

    /// Register a callback invoked when data is available on the socket fd.
    void register_receive(std::function<void(std::span<std::byte>, endpoint)> handler)
    {
        m_receive_handler = std::move(handler);
    }

    void register_timer(DefaultTimer *t)
    {
        if(std::find(m_timers.begin(), m_timers.end(), t) == m_timers.end())
            m_timers.push_back(t);
    }

    void deregister_timer(DefaultTimer *t)
    {
        std::erase(m_timers, t);
    }

    // -----------------------------------------------------------------------
    // Private helpers (declared here; timer-dependent ones defined in
    // native_timer.h after DefaultTimer is fully defined)
    // -----------------------------------------------------------------------
    int compute_next_timeout_ms(std::chrono::steady_clock::time_point now) const;
    void fire_expired_timers();

private:
    // winsock_guard MUST be the first member — initialised before any sockets.
    winsock_guard m_wsa{};
    std::atomic<bool> m_stopped{false};
    detail::native_socket_t m_socket_fd{detail::invalid_socket};
    std::function<void(std::span<std::byte>, endpoint)> m_receive_handler;
    std::vector<DefaultTimer*> m_timers;
    std::array<std::byte, 4096> m_recv_buf{};
    sockaddr_in m_sender_addr{};

    // Stop-wakeup mechanism — platform-specific members.
#if defined(__linux__)
    int m_wakeup_fd{-1};
#elif defined(_WIN32)
    detail::native_socket_t m_wakeup_recv{detail::invalid_socket};
    detail::native_socket_t m_wakeup_send{detail::invalid_socket};
#else
    int m_pipe[2]{-1, -1};
#endif

    // Per-poll-call result flags.
    bool m_wakeup_ready{false};
    bool m_data_ready{false};

    // ------------------------------------------------------------------
    // Platform-specific wakeup fd lifecycle
    // ------------------------------------------------------------------
    void create_wakeup_fd()
    {
#if defined(__linux__)
        m_wakeup_fd = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        if(m_wakeup_fd < 0)
            throw std::system_error(errno, std::generic_category(), "eventfd");

#elif defined(_WIN32)
        m_wakeup_recv = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if(m_wakeup_recv == INVALID_SOCKET)
            throw std::system_error(::WSAGetLastError(), std::system_category(), "socket(wakeup_recv)");

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;

        if(::bind(m_wakeup_recv, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR)
        {
            ::closesocket(m_wakeup_recv);
            throw std::system_error(::WSAGetLastError(), std::system_category(), "bind(wakeup_recv)");
        }

        int len = sizeof(addr);
        if(::getsockname(m_wakeup_recv, reinterpret_cast<sockaddr*>(&addr), &len) == SOCKET_ERROR)
        {
            ::closesocket(m_wakeup_recv);
            throw std::system_error(::WSAGetLastError(), std::system_category(), "getsockname");
        }

        m_wakeup_send = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if(m_wakeup_send == INVALID_SOCKET)
        {
            ::closesocket(m_wakeup_recv);
            throw std::system_error(::WSAGetLastError(), std::system_category(), "socket(wakeup_send)");
        }

        if(::connect(m_wakeup_send, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR)
        {
            ::closesocket(m_wakeup_recv);
            ::closesocket(m_wakeup_send);
            throw std::system_error(::WSAGetLastError(), std::system_category(), "connect(wakeup_send)");
        }

#else
        // Other POSIX: self-pipe
        if(::pipe(m_pipe) != 0)
            throw std::system_error(errno, std::generic_category(), "pipe");

        for(const int fd : m_pipe)
        {
            const int flags = ::fcntl(fd, F_GETFL, 0);
            if(flags < 0 || ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
            {
                ::close(m_pipe[0]);
                ::close(m_pipe[1]);
                throw std::system_error(errno, std::generic_category(), "fcntl(O_NONBLOCK)");
            }
        }
#endif
    }

    void close_wakeup_fd() noexcept
    {
#if defined(__linux__)
        if(m_wakeup_fd >= 0)
        {
            ::close(m_wakeup_fd);
            m_wakeup_fd = -1;
        }
#elif defined(_WIN32)
        if(m_wakeup_recv != INVALID_SOCKET)
            ::closesocket(m_wakeup_recv);
        if(m_wakeup_send != INVALID_SOCKET)
            ::closesocket(m_wakeup_send);
        m_wakeup_recv = INVALID_SOCKET;
        m_wakeup_send = INVALID_SOCKET;
#else
        for(int &fd : m_pipe)
        {
            if(fd >= 0)
            {
                ::close(fd);
                fd = -1;
            }
        }
#endif
    }

    void write_wakeup_fd() noexcept
    {
#if defined(__linux__)
        const uint64_t one = 1;
        (void)::write(m_wakeup_fd, &one, sizeof(one));
#elif defined(_WIN32)
        const char byte = 1;
        (void)::send(m_wakeup_send, &byte, 1, 0);
#else
        const char byte = 1;
        (void)::write(m_pipe[1], &byte, 1);
#endif
    }

    void drain_wakeup_fd() noexcept
    {
#if defined(__linux__)
        uint64_t val{};
        (void)::read(m_wakeup_fd, &val, sizeof(val));
#elif defined(_WIN32)
        char buf[64];
        while(::recv(m_wakeup_recv, buf, sizeof(buf), 0) > 0)
        {
        }
#else
        char buf[64];
        while(::read(m_pipe[0], buf, sizeof(buf)) > 0)
        {
        }
#endif
    }

#if defined(__linux__)
    [[nodiscard]] int wakeup_poll_fd() const noexcept { return m_wakeup_fd; }
#elif defined(_WIN32)
    [[nodiscard]] detail::native_socket_t wakeup_poll_fd() const noexcept { return m_wakeup_recv; }
#else
    [[nodiscard]] int wakeup_poll_fd() const noexcept { return m_pipe[0]; }
#endif

    /// Build pollfd array, invoke poll, cache readability flags.
    int do_poll(int timeout_ms)
    {
        m_wakeup_ready = false;
        m_data_ready = false;

        const bool has_socket = (m_socket_fd != detail::invalid_socket);

        pollfd fds[2]{};
        fds[0].fd = static_cast<int>(wakeup_poll_fd());
        fds[0].events = POLLIN;

        if(has_socket)
        {
            fds[1].fd = static_cast<int>(m_socket_fd);
            fds[1].events = POLLIN;
        }

        const nfds_t nfds = has_socket ? 2u : 1u;
        const int rc = detail::poll_sockets(fds, nfds, timeout_ms);

        if(rc > 0)
        {
            m_wakeup_ready = (fds[0].revents & POLLIN) != 0;
            m_data_ready = has_socket && ((fds[1].revents & POLLIN) != 0);
        }

        return rc;
    }

    [[nodiscard]] bool wakeup_readable() const noexcept { return m_wakeup_ready; }
    [[nodiscard]] bool data_readable() const noexcept { return m_data_ready; }

    void dispatch_receive()
    {
        if(!m_receive_handler)
            return;

#ifdef _WIN32
        int sender_len = sizeof(m_sender_addr);
        const int bytes = ::recvfrom(
            m_socket_fd,
            reinterpret_cast<char*>(m_recv_buf.data()),
            static_cast<int>(m_recv_buf.size()),
            0,
            reinterpret_cast<sockaddr*>(&m_sender_addr),
            &sender_len);

        if(bytes == SOCKET_ERROR)
            return; // WSAEWOULDBLOCK or other — ignore silently
#else
        socklen_t sender_len = sizeof(m_sender_addr);
        const ssize_t bytes = ::recvfrom(
            m_socket_fd,
            m_recv_buf.data(),
            m_recv_buf.size(),
            0,
            reinterpret_cast<sockaddr*>(&m_sender_addr),
            &sender_len);

        if(bytes < 0)
            return; // EAGAIN/EWOULDBLOCK or other — ignore silently
#endif

        char addr_str[INET_ADDRSTRLEN]{};
        ::inet_ntop(AF_INET, &m_sender_addr.sin_addr, addr_str, sizeof(addr_str));

        endpoint ep{
            .address = addr_str,
            .port    = ::ntohs(m_sender_addr.sin_port),
        };

        m_receive_handler(
            std::span<std::byte>{m_recv_buf.data(), static_cast<std::size_t>(bytes)},
            ep);
    }
};

}

#endif
