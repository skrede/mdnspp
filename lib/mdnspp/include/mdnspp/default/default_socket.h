#ifndef HPP_GUARD_MDNSPP_DEFAULT_SOCKET_H
#define HPP_GUARD_MDNSPP_DEFAULT_SOCKET_H

// DefaultSocket — raw UDP multicast socket satisfying SocketLike.
// No ASIO includes. POSIX/Linux primary, Windows via #ifdef guards.
//
// Joins the multicast group from socket_options (default 224.0.0.251:5353) on construction.
// Registers with DefaultContext for poll-based dispatch.

#include "mdnspp/policy.h"
#include "mdnspp/socket_options.h"

#include "mdnspp/detail/validate_multicast.h"
#include "mdnspp/default/default_context.h"

#include <span>
#include <memory>
#include <string>
#include <cstddef>
#include <cstring>
#include <functional>
#include <system_error>

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <iphlpapi.h>
#else
#  include <net/if.h>
#  include <ifaddrs.h>
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
    /// Opens a UDP socket, sets options, binds to the default mDNS port,
    /// joins the default multicast group, and registers with the context for poll dispatch.
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
        sockaddr_storage ss{};
        socklen_t sa_len{};

        if(is_ipv6(dest.address))
        {
            auto &addr6 = *reinterpret_cast<sockaddr_in6 *>(&ss);
            addr6.sin6_family = AF_INET6;
            addr6.sin6_port = htons(dest.port);
            ::inet_pton(AF_INET6, dest.address.c_str(), &addr6.sin6_addr);
            sa_len = sizeof(sockaddr_in6);
        }
        else
        {
            auto &addr4 = *reinterpret_cast<sockaddr_in *>(&ss);
            addr4.sin_family = AF_INET;
            addr4.sin_port = htons(dest.port);
            ::inet_pton(AF_INET, dest.address.c_str(), &addr4.sin_addr);
            sa_len = sizeof(sockaddr_in);
        }

#ifdef _WIN32
        (void)::sendto(
            m_fd,
            reinterpret_cast<const char*>(data.data()),
            static_cast<int>(data.size()),
            0,
            reinterpret_cast<const sockaddr*>(&ss),
            static_cast<int>(sa_len));
#else
        (void)::sendto(
            m_fd,
            data.data(),
            data.size(),
            0,
            reinterpret_cast<const sockaddr*>(&ss),
            sa_len);
#endif
    }

    /// Synchronous sendto() -- non-throwing, reports errors via ec.
    void send(const endpoint &dest, std::span<const std::byte> data, std::error_code &ec)
    {
        sockaddr_storage ss{};
        socklen_t sa_len{};

        if(is_ipv6(dest.address))
        {
            auto &addr6 = *reinterpret_cast<sockaddr_in6 *>(&ss);
            addr6.sin6_family = AF_INET6;
            addr6.sin6_port = htons(dest.port);
            ::inet_pton(AF_INET6, dest.address.c_str(), &addr6.sin6_addr);
            sa_len = sizeof(sockaddr_in6);
        }
        else
        {
            auto &addr4 = *reinterpret_cast<sockaddr_in *>(&ss);
            addr4.sin_family = AF_INET;
            addr4.sin_port = htons(dest.port);
            ::inet_pton(AF_INET, dest.address.c_str(), &addr4.sin_addr);
            sa_len = sizeof(sockaddr_in);
        }

#ifdef _WIN32
        auto result = ::sendto(
            m_fd,
            reinterpret_cast<const char*>(data.data()),
            static_cast<int>(data.size()),
            0,
            reinterpret_cast<const sockaddr*>(&ss),
            static_cast<int>(sa_len));
        if(result == SOCKET_ERROR)
            ec = std::error_code(::WSAGetLastError(), std::system_category());
        else
            ec.clear();
#else
        auto result = ::sendto(
            m_fd,
            data.data(),
            data.size(),
            0,
            reinterpret_cast<const sockaddr*>(&ss),
            sa_len);
        if(result < 0)
            ec = std::error_code(errno, std::system_category());
        else
            ec.clear();
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

    static bool is_ipv6(const std::string &addr)
    {
        in6_addr tmp{};
        return ::inet_pton(AF_INET6, addr.c_str(), &tmp) == 1;
    }

    static unsigned int resolve_ipv6_interface_index([[maybe_unused]] const std::string &addr)
    {
        if(addr.empty())
            return 0;
#ifdef _WIN32
        ULONG buf_size = 15000;
        std::unique_ptr<std::byte[]> buffer;
        ULONG result = ERROR_BUFFER_OVERFLOW;

        for(int attempts = 0; attempts < 3 && result == ERROR_BUFFER_OVERFLOW; ++attempts)
        {
            buffer = std::make_unique<std::byte[]>(buf_size);
            result = GetAdaptersAddresses(AF_UNSPEC, 0, nullptr,
                                          reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.get()), &buf_size);
        }

        if(result != NO_ERROR)
            return 0;

        for(auto *adapter = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.get());
            adapter != nullptr; adapter = adapter->Next)
        {
            for(auto *ua = adapter->FirstUnicastAddress; ua != nullptr; ua = ua->Next)
            {
                auto *sa = ua->Address.lpSockaddr;
                char buf[INET6_ADDRSTRLEN]{};

                if(sa->sa_family == AF_INET)
                {
                    auto *sin = reinterpret_cast<const sockaddr_in *>(sa);
                    if(inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf)) && addr == buf)
                        return adapter->Ipv6IfIndex ? adapter->Ipv6IfIndex : adapter->IfIndex;
                }
                else if(sa->sa_family == AF_INET6)
                {
                    auto *sin6 = reinterpret_cast<const sockaddr_in6 *>(sa);
                    if(inet_ntop(AF_INET6, &sin6->sin6_addr, buf, sizeof(buf)) && addr == buf)
                        return adapter->Ipv6IfIndex ? adapter->Ipv6IfIndex : adapter->IfIndex;
                }
            }
        }
        return 0;
#else
        ifaddrs *addrs{};
        if(::getifaddrs(&addrs) != 0)
            return 0;

        unsigned int idx{};
        in6_addr target{};
        ::inet_pton(AF_INET6, addr.c_str(), &target);

        for(auto *ifa = addrs; ifa; ifa = ifa->ifa_next)
        {
            if(!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET6)
                continue;
            auto &sa6 = *reinterpret_cast<sockaddr_in6 *>(ifa->ifa_addr);
            if(std::memcmp(&sa6.sin6_addr, &target, sizeof(in6_addr)) == 0)
            {
                idx = ::if_nametoindex(ifa->ifa_name);
                break;
            }
        }

        ::freeifaddrs(addrs);
        return idx;
#endif
    }

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

        // 5. Bind to INADDR_ANY:5353 (default mDNS)
        {
            socket_options default_opts;
            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_ANY);
            addr.sin_port = htons(default_opts.multicast_group.port);

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

        // 6. Join default multicast group on INADDR_ANY
        {
            socket_options default_opts;
            join_multicast_or_throw(default_opts.multicast_group.address);
        }
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

        // 5. Bind to INADDR_ANY with default port
        {
            socket_options default_opts;
            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_ANY);
            addr.sin_port = htons(default_opts.multicast_group.port);

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

        // 6. Join default multicast group
        {
            socket_options default_opts;
            join_multicast(default_opts.multicast_group.address, ec);
        }
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
    void join_multicast_or_throw(const std::string &group_address)
    {
        ip_mreq mreq{};
        ::inet_pton(AF_INET, group_address.c_str(), &mreq.imr_multiaddr);
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
    void join_multicast(const std::string &group_address, std::error_code &ec)
    {
        ip_mreq mreq{};
        ::inet_pton(AF_INET, group_address.c_str(), &mreq.imr_multiaddr);
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

    /// Throwing -- interface-aware multicast configuration via socket_options.
    void open_and_configure(const socket_options &opts)
    {
        // 0. Validate multicast group address
        detail::validate_multicast_address(opts.multicast_group.address);

        const bool v6 = is_ipv6(opts.multicast_group.address);
        const int family = v6 ? AF_INET6 : AF_INET;

        // 1. Create UDP socket
        m_fd = ::socket(family, SOCK_DGRAM, IPPROTO_UDP);
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

        // 3. SO_REUSEPORT (optional -- warn on failure, do not throw)
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

        if(v6)
        {
            // 5v6. Bind to in6addr_any with configured port
            {
                sockaddr_in6 addr6{};
                addr6.sin6_family = AF_INET6;
                addr6.sin6_addr = in6addr_any;
                addr6.sin6_port = htons(opts.multicast_group.port);

#ifdef _WIN32
                if(::bind(m_fd, reinterpret_cast<const sockaddr*>(&addr6), sizeof(addr6)) == SOCKET_ERROR)
                {
                    detail::close_socket(m_fd);
                    m_fd = detail::invalid_socket;
                    throw std::system_error(::WSAGetLastError(), std::system_category(), "bind");
                }
#else
                if(::bind(m_fd, reinterpret_cast<const sockaddr*>(&addr6),
                          static_cast<socklen_t>(sizeof(addr6))) < 0)
                {
                    detail::close_socket(m_fd);
                    m_fd = detail::invalid_socket;
                    throw std::system_error(errno, std::generic_category(), "bind");
                }
#endif
            }

            // 6v6. Resolve interface index for IPv6
            unsigned int iface_idx = resolve_ipv6_interface_index(opts.interface_address);

            // 7v6. IPV6_MULTICAST_IF (outgoing multicast interface)
            if(!opts.interface_address.empty())
            {
#ifdef _WIN32
                if(::setsockopt(m_fd, IPPROTO_IPV6, IPV6_MULTICAST_IF,
                                reinterpret_cast<const char*>(&iface_idx), sizeof(iface_idx)) == SOCKET_ERROR)
                {
                    detail::close_socket(m_fd);
                    m_fd = detail::invalid_socket;
                    throw std::system_error(::WSAGetLastError(), std::system_category(), "setsockopt(IPV6_MULTICAST_IF)");
                }
#else
                if(::setsockopt(m_fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &iface_idx, sizeof(iface_idx)) < 0)
                {
                    detail::close_socket(m_fd);
                    m_fd = detail::invalid_socket;
                    throw std::system_error(errno, std::generic_category(), "setsockopt(IPV6_MULTICAST_IF)");
                }
#endif
            }

            // 8v6. IPV6_JOIN_GROUP
            {
                ipv6_mreq mreq6{};
                ::inet_pton(AF_INET6, opts.multicast_group.address.c_str(), &mreq6.ipv6mr_multiaddr);
                mreq6.ipv6mr_interface = iface_idx;

#ifdef _WIN32
                if(::setsockopt(m_fd, IPPROTO_IPV6, IPV6_JOIN_GROUP,
                                reinterpret_cast<const char*>(&mreq6), sizeof(mreq6)) == SOCKET_ERROR)
                {
                    detail::close_socket(m_fd);
                    m_fd = detail::invalid_socket;
                    throw std::system_error(::WSAGetLastError(), std::system_category(), "setsockopt(IPV6_JOIN_GROUP)");
                }
#else
                if(::setsockopt(m_fd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq6, sizeof(mreq6)) < 0)
                {
                    detail::close_socket(m_fd);
                    m_fd = detail::invalid_socket;
                    throw std::system_error(errno, std::generic_category(), "setsockopt(IPV6_JOIN_GROUP)");
                }
#endif
            }

            // 9v6. IPV6_MULTICAST_HOPS (default 255 per RFC 6762 Section 11)
            {
                const int hops_val = static_cast<int>(opts.multicast_ttl.value_or(255));
#ifdef _WIN32
                if(::setsockopt(m_fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
                                reinterpret_cast<const char*>(&hops_val), sizeof(hops_val)) == SOCKET_ERROR)
                {
                    detail::close_socket(m_fd);
                    m_fd = detail::invalid_socket;
                    throw std::system_error(::WSAGetLastError(), std::system_category(), "setsockopt(IPV6_MULTICAST_HOPS)");
                }
#else
                if(::setsockopt(m_fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops_val, sizeof(hops_val)) < 0)
                {
                    detail::close_socket(m_fd);
                    m_fd = detail::invalid_socket;
                    throw std::system_error(errno, std::generic_category(), "setsockopt(IPV6_MULTICAST_HOPS)");
                }
#endif
            }

            // 10v6. IPV6_MULTICAST_LOOP
            {
                const int val = (opts.multicast_loopback == loopback_mode::enabled) ? 1 : 0;
#ifdef _WIN32
                if(::setsockopt(m_fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
                                reinterpret_cast<const char*>(&val), sizeof(val)) == SOCKET_ERROR)
                {
                    detail::close_socket(m_fd);
                    m_fd = detail::invalid_socket;
                    throw std::system_error(::WSAGetLastError(), std::system_category(), "setsockopt(IPV6_MULTICAST_LOOP)");
                }
#else
                if(::setsockopt(m_fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &val, sizeof(val)) < 0)
                {
                    detail::close_socket(m_fd);
                    m_fd = detail::invalid_socket;
                    throw std::system_error(errno, std::generic_category(), "setsockopt(IPV6_MULTICAST_LOOP)");
                }
#endif
            }
        }
        else
        {
            // 5. Bind to INADDR_ANY with configured port
            {
                sockaddr_in addr{};
                addr.sin_family = AF_INET;
                addr.sin_addr.s_addr = htonl(INADDR_ANY);
                addr.sin_port = htons(opts.multicast_group.port);

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

            // 6. Compute interface address (single variable for both IF and MEMBERSHIP)
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

            // 8. IP_ADD_MEMBERSHIP (same iface_addr -- no split-brain)
            {
                ip_mreq mreq{};
                ::inet_pton(AF_INET, opts.multicast_group.address.c_str(), &mreq.imr_multiaddr);
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

            // 10. IP_MULTICAST_LOOP
            {
                const int val = (opts.multicast_loopback == loopback_mode::enabled) ? 1 : 0;
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
    }

    /// Non-throwing -- interface-aware multicast configuration via socket_options.
    void open_and_configure(const socket_options &opts, std::error_code &ec)
    {
        ec.clear();

        // 0. Validate multicast group address
        detail::validate_multicast_address(opts.multicast_group.address, ec);
        if(ec) return;

        const bool v6 = is_ipv6(opts.multicast_group.address);
        const int family = v6 ? AF_INET6 : AF_INET;

        // 1. Create UDP socket
        m_fd = ::socket(family, SOCK_DGRAM, IPPROTO_UDP);
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

        // 3. SO_REUSEPORT (optional -- warn on failure, do not set ec)
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

        if(v6)
        {
            // 5v6. Bind to in6addr_any with configured port
            {
                sockaddr_in6 addr6{};
                addr6.sin6_family = AF_INET6;
                addr6.sin6_addr = in6addr_any;
                addr6.sin6_port = htons(opts.multicast_group.port);

#ifdef _WIN32
                if(::bind(m_fd, reinterpret_cast<const sockaddr*>(&addr6), sizeof(addr6)) == SOCKET_ERROR)
                {
                    ec = std::error_code(::WSAGetLastError(), std::system_category());
                    detail::close_socket(m_fd);
                    m_fd = detail::invalid_socket;
                    return;
                }
#else
                if(::bind(m_fd, reinterpret_cast<const sockaddr*>(&addr6),
                          static_cast<socklen_t>(sizeof(addr6))) < 0)
                {
                    ec = std::error_code(errno, std::generic_category());
                    detail::close_socket(m_fd);
                    m_fd = detail::invalid_socket;
                    return;
                }
#endif
            }

            // 6v6. Resolve interface index for IPv6
            unsigned int iface_idx = resolve_ipv6_interface_index(opts.interface_address);

            // 7v6. IPV6_MULTICAST_IF (outgoing multicast interface)
            if(!opts.interface_address.empty())
            {
#ifdef _WIN32
                if(::setsockopt(m_fd, IPPROTO_IPV6, IPV6_MULTICAST_IF,
                                reinterpret_cast<const char*>(&iface_idx), sizeof(iface_idx)) == SOCKET_ERROR)
                {
                    ec = std::error_code(::WSAGetLastError(), std::system_category());
                    detail::close_socket(m_fd);
                    m_fd = detail::invalid_socket;
                    return;
                }
#else
                if(::setsockopt(m_fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &iface_idx, sizeof(iface_idx)) < 0)
                {
                    ec = std::error_code(errno, std::generic_category());
                    detail::close_socket(m_fd);
                    m_fd = detail::invalid_socket;
                    return;
                }
#endif
            }

            // 8v6. IPV6_JOIN_GROUP
            {
                ipv6_mreq mreq6{};
                ::inet_pton(AF_INET6, opts.multicast_group.address.c_str(), &mreq6.ipv6mr_multiaddr);
                mreq6.ipv6mr_interface = iface_idx;

#ifdef _WIN32
                if(::setsockopt(m_fd, IPPROTO_IPV6, IPV6_JOIN_GROUP,
                                reinterpret_cast<const char*>(&mreq6), sizeof(mreq6)) == SOCKET_ERROR)
                {
                    ec = std::error_code(::WSAGetLastError(), std::system_category());
                    detail::close_socket(m_fd);
                    m_fd = detail::invalid_socket;
                    return;
                }
#else
                if(::setsockopt(m_fd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq6, sizeof(mreq6)) < 0)
                {
                    ec = std::error_code(errno, std::generic_category());
                    detail::close_socket(m_fd);
                    m_fd = detail::invalid_socket;
                    return;
                }
#endif
            }

            // 9v6. IPV6_MULTICAST_HOPS (default 255 per RFC 6762 Section 11)
            {
                const int hops_val = static_cast<int>(opts.multicast_ttl.value_or(255));
#ifdef _WIN32
                if(::setsockopt(m_fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
                                reinterpret_cast<const char*>(&hops_val), sizeof(hops_val)) == SOCKET_ERROR)
                {
                    ec = std::error_code(::WSAGetLastError(), std::system_category());
                    detail::close_socket(m_fd);
                    m_fd = detail::invalid_socket;
                    return;
                }
#else
                if(::setsockopt(m_fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops_val, sizeof(hops_val)) < 0)
                {
                    ec = std::error_code(errno, std::generic_category());
                    detail::close_socket(m_fd);
                    m_fd = detail::invalid_socket;
                    return;
                }
#endif
            }

            // 10v6. IPV6_MULTICAST_LOOP
            {
                const int val = (opts.multicast_loopback == loopback_mode::enabled) ? 1 : 0;
#ifdef _WIN32
                if(::setsockopt(m_fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
                                reinterpret_cast<const char*>(&val), sizeof(val)) == SOCKET_ERROR)
                {
                    ec = std::error_code(::WSAGetLastError(), std::system_category());
                    detail::close_socket(m_fd);
                    m_fd = detail::invalid_socket;
                    return;
                }
#else
                if(::setsockopt(m_fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &val, sizeof(val)) < 0)
                {
                    ec = std::error_code(errno, std::generic_category());
                    detail::close_socket(m_fd);
                    m_fd = detail::invalid_socket;
                    return;
                }
#endif
            }
        }
        else
        {
            // 5. Bind to INADDR_ANY with configured port
            {
                sockaddr_in addr{};
                addr.sin_family = AF_INET;
                addr.sin_addr.s_addr = htonl(INADDR_ANY);
                addr.sin_port = htons(opts.multicast_group.port);

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

            // 6. Compute interface address (single variable for both IF and MEMBERSHIP)
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

            // 8. IP_ADD_MEMBERSHIP (same iface_addr -- no split-brain)
            {
                ip_mreq mreq{};
                ::inet_pton(AF_INET, opts.multicast_group.address.c_str(), &mreq.imr_multiaddr);
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

            // 10. IP_MULTICAST_LOOP
            {
                const int val = (opts.multicast_loopback == loopback_mode::enabled) ? 1 : 0;
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
    }
};

static_assert(mdnspp::SocketLike<mdnspp::DefaultSocket>, "DefaultSocket must satisfy SocketLike — check async_receive/send/close signatures");

}

#endif
