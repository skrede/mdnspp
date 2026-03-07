#ifndef HPP_GUARD_MDNSPP_DEFAULT_SOCKET_H
#define HPP_GUARD_MDNSPP_DEFAULT_SOCKET_H

// DefaultSocket — raw UDP multicast socket satisfying SocketLike.
// No ASIO includes. POSIX/Linux primary, Windows via #ifdef guards.
//
// Joins the mDNS multicast group 224.0.0.251:5353 on construction.
// Registers with DefaultContext for poll-based dispatch.

#include "mdnspp/policy.h"
#include "mdnspp/socket_options.h"

#include "mdnspp/default/default_context.h"

#include <span>
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
#  include <sys/socket.h>
#  include <unistd.h>
#endif

namespace mdnspp {

class DefaultSocket
{
public:
    // Throwing constructor.
    /// Opens a UDP socket, sets options, binds to :5353, joins 224.0.0.251,
    /// and registers with the context for poll dispatch.
    explicit DefaultSocket(DefaultContext &ctx)
        : m_ctx{ctx}
    {
        open_and_configure();
    }

    // Non-throwing constructor.
    explicit DefaultSocket(DefaultContext &ctx, std::error_code &ec)
        : m_ctx{ctx}
    {
        open_and_configure(ec);
    }

    // Throwing constructor with socket_options.
    explicit DefaultSocket(DefaultContext &ctx, const socket_options &opts)
        : m_ctx{ctx}
    {
        open_and_configure(opts);
    }

    // Non-throwing constructor with socket_options.
    explicit DefaultSocket(DefaultContext &ctx, const socket_options &opts, std::error_code &ec)
        : m_ctx{ctx}
    {
        open_and_configure(opts, ec);
    }

    ~DefaultSocket()
    {
        close();
    }

    DefaultSocket(const DefaultSocket &) = delete;
    DefaultSocket &operator=(const DefaultSocket &) = delete;
    DefaultSocket(DefaultSocket &&) = delete;
    DefaultSocket &operator=(DefaultSocket &&) = delete;

    /// Register this socket and its receive handler with DefaultContext.
    /// Called by recv_loop when it wants to arm the next receive.
    void async_receive(std::function<void(const endpoint &, std::span<std::byte>)> handler)
    {
        m_receive_handler = std::move(handler);
        m_ctx.register_socket(m_fd, m_receive_handler);
    }

    /// Synchronous sendto(). mDNS sends are tiny and infrequent.
    void send(const endpoint &dest, std::span<const std::byte> data)
    {
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(dest.port);
#ifdef _WIN32
        addr.sin_addr.s_addr = ::inet_addr(dest.address.c_str());
#else
        ::inet_pton(AF_INET, dest.address.c_str(), &addr.sin_addr);
#endif

#ifdef _WIN32
        (void)::sendto(
            m_fd,
            reinterpret_cast<const char*>(data.data()),
            static_cast<int>(data.size()),
            0,
            reinterpret_cast<const sockaddr*>(&addr),
            static_cast<int>(sizeof(addr)));
#else
        (void)::sendto(
            m_fd,
            data.data(),
            data.size(),
            0,
            reinterpret_cast<const sockaddr*>(&addr),
            static_cast<socklen_t>(sizeof(addr)));
#endif
    }

    /// Close the socket and deregister from the context. Idempotent.
    void close()
    {
        if(m_fd != detail::invalid_socket)
        {
            m_ctx.deregister_socket(m_fd);
            detail::close_socket(m_fd);
            m_fd = detail::invalid_socket;
        }
    }

private:
    DefaultContext &m_ctx;
    detail::native_socket_t m_fd{detail::invalid_socket};
    std::function<void(const endpoint &, std::span<std::byte>)> m_receive_handler;

    /// Throwing
    void open_and_configure()
    {
        // 1. Create UDP socket
        m_fd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if(m_fd == detail::invalid_socket)
        {
#ifdef _WIN32
            throw std::system_error(::WSAGetLastError(), std::system_category(), "socket");
#else
            throw std::system_error(errno, std::generic_category(), "socket");
#endif
        }

        // 2. SO_REUSEADDR
        {
            const int opt = 1;
#ifdef _WIN32
            if(::setsockopt(m_fd, SOL_SOCKET, SO_REUSEADDR,
                            reinterpret_cast<const char*>(&opt), sizeof(opt)) == SOCKET_ERROR)
            {
                detail::close_socket(m_fd);
                m_fd = detail::invalid_socket;
                throw std::system_error(::WSAGetLastError(), std::system_category(), "setsockopt(SO_REUSEADDR)");
            }
#else
            if(::setsockopt(m_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
            {
                detail::close_socket(m_fd);
                m_fd = detail::invalid_socket;
                throw std::system_error(errno, std::generic_category(), "setsockopt(SO_REUSEADDR)");
            }
#endif
        }

        // 3. SO_REUSEPORT (optional — warn on failure, do not throw)
#if defined(SO_REUSEPORT)
        {
            const int opt = 1;
            if(::setsockopt(m_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0)
            {
                // Non-fatal — log a warning but continue
                // (stderr is acceptable here; library callers can suppress)
            }
        }
#endif

        // 4. Non-blocking
        set_nonblocking_or_throw();

        // 5. Bind to INADDR_ANY:5353
        {
            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_ANY);
            addr.sin_port = htons(5353);

#ifdef _WIN32
            if(::bind(m_fd, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR)
            {
                detail::close_socket(m_fd);
                m_fd = detail::invalid_socket;
                throw std::system_error(::WSAGetLastError(), std::system_category(), "bind");
            }
#else
            if(::bind(m_fd, reinterpret_cast<const sockaddr*>(&addr),
                      static_cast<socklen_t>(sizeof(addr))) < 0)
            {
                detail::close_socket(m_fd);
                m_fd = detail::invalid_socket;
                throw std::system_error(errno, std::generic_category(), "bind");
            }
#endif
        }

        // 6. Join multicast group 224.0.0.251 on INADDR_ANY
        join_multicast_or_throw();
    }

    /// Non-throwing — sets ec and returns early on failure.
    void open_and_configure(std::error_code &ec)
    {
        ec.clear();

        // 1. Create UDP socket
        m_fd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if(m_fd == detail::invalid_socket)
        {
#ifdef _WIN32
            ec = std::error_code(::WSAGetLastError(), std::system_category());
#else
            ec = std::error_code(errno, std::generic_category());
#endif
            return;
        }

        // 2. SO_REUSEADDR
        {
            const int opt = 1;
#ifdef _WIN32
            if(::setsockopt(m_fd, SOL_SOCKET, SO_REUSEADDR,
                            reinterpret_cast<const char*>(&opt), sizeof(opt)) == SOCKET_ERROR)
            {
                ec = std::error_code(::WSAGetLastError(), std::system_category());
                detail::close_socket(m_fd);
                m_fd = detail::invalid_socket;
                return;
            }
#else
            if(::setsockopt(m_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
            {
                ec = std::error_code(errno, std::generic_category());
                detail::close_socket(m_fd);
                m_fd = detail::invalid_socket;
                return;
            }
#endif
        }

        // 3. SO_REUSEPORT (optional — warn on failure, do not set ec)
#if defined(SO_REUSEPORT)
        {
            const int opt = 1;
            (void)::setsockopt(m_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
        }
#endif

        // 4. Non-blocking
        if(!set_nonblocking(ec))
        {
            detail::close_socket(m_fd);
            m_fd = detail::invalid_socket;
            return;
        }

        // 5. Bind to INADDR_ANY:5353
        {
            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_ANY);
            addr.sin_port = htons(5353);

#ifdef _WIN32
            if(::bind(m_fd, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR)
            {
                ec = std::error_code(::WSAGetLastError(), std::system_category());
                detail::close_socket(m_fd);
                m_fd = detail::invalid_socket;
                return;
            }
#else
            if(::bind(m_fd, reinterpret_cast<const sockaddr*>(&addr),
                      static_cast<socklen_t>(sizeof(addr))) < 0)
            {
                ec = std::error_code(errno, std::generic_category());
                detail::close_socket(m_fd);
                m_fd = detail::invalid_socket;
                return;
            }
#endif
        }

        // 6. Join multicast group 224.0.0.251
        join_multicast(ec);
        if(ec)
        {
            detail::close_socket(m_fd);
            m_fd = detail::invalid_socket;
        }
    }

    /// throwing
    void set_nonblocking_or_throw()
    {
#ifdef _WIN32
        u_long mode = 1;
        if(::ioctlsocket(m_fd, FIONBIO, &mode) == SOCKET_ERROR)
        {
            detail::close_socket(m_fd);
            m_fd = detail::invalid_socket;
            throw std::system_error(::WSAGetLastError(), std::system_category(), "ioctlsocket(FIONBIO)");
        }
#else
        const int flags = ::fcntl(m_fd, F_GETFL, 0);
        if(flags < 0 || ::fcntl(m_fd, F_SETFL, flags | O_NONBLOCK) < 0)
        {
            detail::close_socket(m_fd);
            m_fd = detail::invalid_socket;
            throw std::system_error(errno, std::generic_category(), "fcntl(F_SETFL, O_NONBLOCK)");
        }
#endif
    }

    /// non-throwing
    bool set_nonblocking(std::error_code &ec)
    {
#ifdef _WIN32
        u_long mode = 1;
        if(::ioctlsocket(m_fd, FIONBIO, &mode) == SOCKET_ERROR)
        {
            ec = std::error_code(::WSAGetLastError(), std::system_category());
            return false;
        }
#else
        const int flags = ::fcntl(m_fd, F_GETFL, 0);
        if(flags < 0 || ::fcntl(m_fd, F_SETFL, flags | O_NONBLOCK) < 0)
        {
            ec = std::error_code(errno, std::generic_category());
            return false;
        }
#endif
        return true;
    }

    /// throwing
    void join_multicast_or_throw()
    {
        ip_mreq mreq{};
        mreq.imr_multiaddr.s_addr = ::inet_addr("224.0.0.251");
        mreq.imr_interface.s_addr = htonl(INADDR_ANY);

#ifdef _WIN32
        if(::setsockopt(m_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                        reinterpret_cast<const char*>(&mreq), sizeof(mreq)) == SOCKET_ERROR)
        {
            detail::close_socket(m_fd);
            m_fd = detail::invalid_socket;
            throw std::system_error(::WSAGetLastError(), std::system_category(), "setsockopt(IP_ADD_MEMBERSHIP)");
        }
#else
        if(::setsockopt(m_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0)
        {
            detail::close_socket(m_fd);
            m_fd = detail::invalid_socket;
            throw std::system_error(errno, std::generic_category(), "setsockopt(IP_ADD_MEMBERSHIP)");
        }
#endif
    }

    /// non-throwing
    void join_multicast(std::error_code &ec)
    {
        ip_mreq mreq{};
        mreq.imr_multiaddr.s_addr = ::inet_addr("224.0.0.251");
        mreq.imr_interface.s_addr = htonl(INADDR_ANY);

#ifdef _WIN32
        if(::setsockopt(m_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                        reinterpret_cast<const char*>(&mreq), sizeof(mreq)) == SOCKET_ERROR)
        {
            ec = std::error_code(::WSAGetLastError(), std::system_category());
        }
#else
        if(::setsockopt(m_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0)
            ec = std::error_code(errno, std::generic_category());
#endif
    }

    /// Throwing — interface-aware multicast configuration via socket_options.
    void open_and_configure(const socket_options &opts)
    {
        // 1. Create UDP socket
        m_fd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if(m_fd == detail::invalid_socket)
        {
#ifdef _WIN32
            throw std::system_error(::WSAGetLastError(), std::system_category(), "socket");
#else
            throw std::system_error(errno, std::generic_category(), "socket");
#endif
        }

        // 2. SO_REUSEADDR
        {
            const int opt = 1;
#ifdef _WIN32
            if(::setsockopt(m_fd, SOL_SOCKET, SO_REUSEADDR,
                            reinterpret_cast<const char*>(&opt), sizeof(opt)) == SOCKET_ERROR)
            {
                detail::close_socket(m_fd);
                m_fd = detail::invalid_socket;
                throw std::system_error(::WSAGetLastError(), std::system_category(), "setsockopt(SO_REUSEADDR)");
            }
#else
            if(::setsockopt(m_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
            {
                detail::close_socket(m_fd);
                m_fd = detail::invalid_socket;
                throw std::system_error(errno, std::generic_category(), "setsockopt(SO_REUSEADDR)");
            }
#endif
        }

        // 3. SO_REUSEPORT (optional — warn on failure, do not throw)
#if defined(SO_REUSEPORT)
        {
            const int opt = 1;
            if(::setsockopt(m_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0)
            {
            }
        }
#endif

        // 4. Non-blocking
        set_nonblocking_or_throw();

        // 5. Bind to INADDR_ANY:5353
        {
            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_ANY);
            addr.sin_port = htons(5353);

#ifdef _WIN32
            if(::bind(m_fd, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR)
            {
                detail::close_socket(m_fd);
                m_fd = detail::invalid_socket;
                throw std::system_error(::WSAGetLastError(), std::system_category(), "bind");
            }
#else
            if(::bind(m_fd, reinterpret_cast<const sockaddr*>(&addr),
                      static_cast<socklen_t>(sizeof(addr))) < 0)
            {
                detail::close_socket(m_fd);
                m_fd = detail::invalid_socket;
                throw std::system_error(errno, std::generic_category(), "bind");
            }
#endif
        }

        // 6. Compute interface address (single variable for both IF and MEMBERSHIP — CMPL-03)
        in_addr iface_addr{};
        if(opts.interface_address.empty())
            iface_addr.s_addr = htonl(INADDR_ANY);
        else if(::inet_pton(AF_INET, opts.interface_address.c_str(), &iface_addr) != 1)
        {
            detail::close_socket(m_fd);
            m_fd = detail::invalid_socket;
            throw std::system_error(std::make_error_code(std::errc::invalid_argument),
                                    "invalid interface address: " + opts.interface_address);
        }

        // 7. IP_MULTICAST_IF (outgoing multicast interface)
        if(!opts.interface_address.empty())
        {
#ifdef _WIN32
            if(::setsockopt(m_fd, IPPROTO_IP, IP_MULTICAST_IF,
                            reinterpret_cast<const char*>(&iface_addr), sizeof(iface_addr)) == SOCKET_ERROR)
            {
                detail::close_socket(m_fd);
                m_fd = detail::invalid_socket;
                throw std::system_error(::WSAGetLastError(), std::system_category(), "setsockopt(IP_MULTICAST_IF)");
            }
#else
            if(::setsockopt(m_fd, IPPROTO_IP, IP_MULTICAST_IF, &iface_addr, sizeof(iface_addr)) < 0)
            {
                detail::close_socket(m_fd);
                m_fd = detail::invalid_socket;
                throw std::system_error(errno, std::generic_category(), "setsockopt(IP_MULTICAST_IF)");
            }
#endif
        }

        // 8. IP_ADD_MEMBERSHIP (same iface_addr — no split-brain)
        {
            ip_mreq mreq{};
            mreq.imr_multiaddr.s_addr = ::inet_addr("224.0.0.251");
            mreq.imr_interface = iface_addr;

#ifdef _WIN32
            if(::setsockopt(m_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                            reinterpret_cast<const char*>(&mreq), sizeof(mreq)) == SOCKET_ERROR)
            {
                detail::close_socket(m_fd);
                m_fd = detail::invalid_socket;
                throw std::system_error(::WSAGetLastError(), std::system_category(), "setsockopt(IP_ADD_MEMBERSHIP)");
            }
#else
            if(::setsockopt(m_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0)
            {
                detail::close_socket(m_fd);
                m_fd = detail::invalid_socket;
                throw std::system_error(errno, std::generic_category(), "setsockopt(IP_ADD_MEMBERSHIP)");
            }
#endif
        }

        // 9. IP_MULTICAST_TTL (default 255 per RFC 6762 Section 11)
        {
            const int ttl_val = static_cast<int>(opts.multicast_ttl.value_or(255));
#ifdef _WIN32
            if(::setsockopt(m_fd, IPPROTO_IP, IP_MULTICAST_TTL,
                            reinterpret_cast<const char*>(&ttl_val), sizeof(ttl_val)) == SOCKET_ERROR)
            {
                detail::close_socket(m_fd);
                m_fd = detail::invalid_socket;
                throw std::system_error(::WSAGetLastError(), std::system_category(), "setsockopt(IP_MULTICAST_TTL)");
            }
#else
            if(::setsockopt(m_fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl_val, sizeof(ttl_val)) < 0)
            {
                detail::close_socket(m_fd);
                m_fd = detail::invalid_socket;
                throw std::system_error(errno, std::generic_category(), "setsockopt(IP_MULTICAST_TTL)");
            }
#endif
        }

        // 10. IP_MULTICAST_LOOP (if specified)
        if(opts.multicast_loopback.has_value())
        {
            const int val = (opts.multicast_loopback.value() == loopback_mode::enabled) ? 1 : 0;
#ifdef _WIN32
            if(::setsockopt(m_fd, IPPROTO_IP, IP_MULTICAST_LOOP,
                            reinterpret_cast<const char*>(&val), sizeof(val)) == SOCKET_ERROR)
            {
                detail::close_socket(m_fd);
                m_fd = detail::invalid_socket;
                throw std::system_error(::WSAGetLastError(), std::system_category(), "setsockopt(IP_MULTICAST_LOOP)");
            }
#else
            if(::setsockopt(m_fd, IPPROTO_IP, IP_MULTICAST_LOOP, &val, sizeof(val)) < 0)
            {
                detail::close_socket(m_fd);
                m_fd = detail::invalid_socket;
                throw std::system_error(errno, std::generic_category(), "setsockopt(IP_MULTICAST_LOOP)");
            }
#endif
        }
    }

    /// Non-throwing — interface-aware multicast configuration via socket_options.
    void open_and_configure(const socket_options &opts, std::error_code &ec)
    {
        ec.clear();

        // 1. Create UDP socket
        m_fd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if(m_fd == detail::invalid_socket)
        {
#ifdef _WIN32
            ec = std::error_code(::WSAGetLastError(), std::system_category());
#else
            ec = std::error_code(errno, std::generic_category());
#endif
            return;
        }

        // 2. SO_REUSEADDR
        {
            const int opt = 1;
#ifdef _WIN32
            if(::setsockopt(m_fd, SOL_SOCKET, SO_REUSEADDR,
                            reinterpret_cast<const char*>(&opt), sizeof(opt)) == SOCKET_ERROR)
            {
                ec = std::error_code(::WSAGetLastError(), std::system_category());
                detail::close_socket(m_fd);
                m_fd = detail::invalid_socket;
                return;
            }
#else
            if(::setsockopt(m_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
            {
                ec = std::error_code(errno, std::generic_category());
                detail::close_socket(m_fd);
                m_fd = detail::invalid_socket;
                return;
            }
#endif
        }

        // 3. SO_REUSEPORT (optional — warn on failure, do not set ec)
#if defined(SO_REUSEPORT)
        {
            const int opt = 1;
            (void)::setsockopt(m_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
        }
#endif

        // 4. Non-blocking
        if(!set_nonblocking(ec))
        {
            detail::close_socket(m_fd);
            m_fd = detail::invalid_socket;
            return;
        }

        // 5. Bind to INADDR_ANY:5353
        {
            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_ANY);
            addr.sin_port = htons(5353);

#ifdef _WIN32
            if(::bind(m_fd, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR)
            {
                ec = std::error_code(::WSAGetLastError(), std::system_category());
                detail::close_socket(m_fd);
                m_fd = detail::invalid_socket;
                return;
            }
#else
            if(::bind(m_fd, reinterpret_cast<const sockaddr*>(&addr),
                      static_cast<socklen_t>(sizeof(addr))) < 0)
            {
                ec = std::error_code(errno, std::generic_category());
                detail::close_socket(m_fd);
                m_fd = detail::invalid_socket;
                return;
            }
#endif
        }

        // 6. Compute interface address (single variable for both IF and MEMBERSHIP — CMPL-03)
        in_addr iface_addr{};
        if(opts.interface_address.empty())
            iface_addr.s_addr = htonl(INADDR_ANY);
        else if(::inet_pton(AF_INET, opts.interface_address.c_str(), &iface_addr) != 1)
        {
            ec = std::make_error_code(std::errc::invalid_argument);
            detail::close_socket(m_fd);
            m_fd = detail::invalid_socket;
            return;
        }

        // 7. IP_MULTICAST_IF (outgoing multicast interface)
        if(!opts.interface_address.empty())
        {
#ifdef _WIN32
            if(::setsockopt(m_fd, IPPROTO_IP, IP_MULTICAST_IF,
                            reinterpret_cast<const char*>(&iface_addr), sizeof(iface_addr)) == SOCKET_ERROR)
            {
                ec = std::error_code(::WSAGetLastError(), std::system_category());
                detail::close_socket(m_fd);
                m_fd = detail::invalid_socket;
                return;
            }
#else
            if(::setsockopt(m_fd, IPPROTO_IP, IP_MULTICAST_IF, &iface_addr, sizeof(iface_addr)) < 0)
            {
                ec = std::error_code(errno, std::generic_category());
                detail::close_socket(m_fd);
                m_fd = detail::invalid_socket;
                return;
            }
#endif
        }

        // 8. IP_ADD_MEMBERSHIP (same iface_addr — no split-brain)
        {
            ip_mreq mreq{};
            mreq.imr_multiaddr.s_addr = ::inet_addr("224.0.0.251");
            mreq.imr_interface = iface_addr;

#ifdef _WIN32
            if(::setsockopt(m_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                            reinterpret_cast<const char*>(&mreq), sizeof(mreq)) == SOCKET_ERROR)
            {
                ec = std::error_code(::WSAGetLastError(), std::system_category());
                detail::close_socket(m_fd);
                m_fd = detail::invalid_socket;
                return;
            }
#else
            if(::setsockopt(m_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0)
            {
                ec = std::error_code(errno, std::generic_category());
                detail::close_socket(m_fd);
                m_fd = detail::invalid_socket;
                return;
            }
#endif
        }

        // 9. IP_MULTICAST_TTL (default 255 per RFC 6762 Section 11)
        {
            const int ttl_val = static_cast<int>(opts.multicast_ttl.value_or(255));
#ifdef _WIN32
            if(::setsockopt(m_fd, IPPROTO_IP, IP_MULTICAST_TTL,
                            reinterpret_cast<const char*>(&ttl_val), sizeof(ttl_val)) == SOCKET_ERROR)
            {
                ec = std::error_code(::WSAGetLastError(), std::system_category());
                detail::close_socket(m_fd);
                m_fd = detail::invalid_socket;
                return;
            }
#else
            if(::setsockopt(m_fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl_val, sizeof(ttl_val)) < 0)
            {
                ec = std::error_code(errno, std::generic_category());
                detail::close_socket(m_fd);
                m_fd = detail::invalid_socket;
                return;
            }
#endif
        }

        // 10. IP_MULTICAST_LOOP (if specified)
        if(opts.multicast_loopback.has_value())
        {
            const int val = (opts.multicast_loopback.value() == loopback_mode::enabled) ? 1 : 0;
#ifdef _WIN32
            if(::setsockopt(m_fd, IPPROTO_IP, IP_MULTICAST_LOOP,
                            reinterpret_cast<const char*>(&val), sizeof(val)) == SOCKET_ERROR)
            {
                ec = std::error_code(::WSAGetLastError(), std::system_category());
                detail::close_socket(m_fd);
                m_fd = detail::invalid_socket;
                return;
            }
#else
            if(::setsockopt(m_fd, IPPROTO_IP, IP_MULTICAST_LOOP, &val, sizeof(val)) < 0)
            {
                ec = std::error_code(errno, std::generic_category());
                detail::close_socket(m_fd);
                m_fd = detail::invalid_socket;
                return;
            }
#endif
        }
    }
};

static_assert(mdnspp::SocketLike<mdnspp::DefaultSocket>, "DefaultSocket must satisfy SocketLike — check async_receive/send/close signatures");

}

#endif
