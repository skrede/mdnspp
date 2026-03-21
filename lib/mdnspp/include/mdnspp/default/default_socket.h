#ifndef HPP_GUARD_MDNSPP_DEFAULT_SOCKET_H
#define HPP_GUARD_MDNSPP_DEFAULT_SOCKET_H

// DefaultSocket — raw UDP multicast socket satisfying SocketLike.
// No ASIO includes. POSIX/Linux primary, Windows via #ifdef guards.
//
// Joins the multicast group from socket_options (default 224.0.0.251:5353) on construction.
// Registers with DefaultContext for poll-based dispatch.

#include "mdnspp/policy.h"
#include "mdnspp/socket_options.h"

#include "mdnspp/detail/compat.h"
#include "mdnspp/detail/validate_multicast.h"
#include "mdnspp/default/default_context.h"

#include <span>
#include <memory>
#include <string>
#include <cstddef>
#include <cstring>
#include <system_error>

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <iphlpapi.h>
#  include <mswsock.h>
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
    explicit DefaultSocket(DefaultContext &ctx)
        : m_ctx{ctx}
    {
        open_and_configure(socket_options{});
    }

    // Non-throwing constructor.
    explicit DefaultSocket(DefaultContext &ctx, std::error_code &ec)
        : m_ctx{ctx}
    {
        open_and_configure(socket_options{}, ec);
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
    void async_receive(detail::move_only_function<void(const recv_metadata &, std::span<std::byte>)> handler)
    {
        m_receive_handler = std::move(handler);
        m_ctx.register_socket(m_fd,
            [this](const recv_metadata &meta, std::span<std::byte> data)
            {
                m_receive_handler(meta, data);
            }
#ifdef _WIN32
            , m_fn_wsarecvmsg
#endif
            );
    }

    /// Return the underlying native socket descriptor.
    [[nodiscard]] auto native_handle() const noexcept { return m_fd; }

    /// Synchronous sendto().
    void send(const endpoint &dest, std::span<const std::byte> data)
    {
        auto [ss, sa_len] = build_sockaddr(dest);
#ifdef _WIN32
        (void)::sendto(m_fd, reinterpret_cast<const char*>(data.data()),
                        static_cast<int>(data.size()), 0,
                        reinterpret_cast<const sockaddr*>(&ss), static_cast<int>(sa_len));
#else
        (void)::sendto(m_fd, data.data(), data.size(), 0,
                        reinterpret_cast<const sockaddr*>(&ss), sa_len);
#endif
    }

    /// Synchronous sendto() -- non-throwing, reports errors via ec.
    void send(const endpoint &dest, std::span<const std::byte> data, std::error_code &ec)
    {
        auto [ss, sa_len] = build_sockaddr(dest);
#ifdef _WIN32
        auto result = ::sendto(m_fd, reinterpret_cast<const char*>(data.data()),
                               static_cast<int>(data.size()), 0,
                               reinterpret_cast<const sockaddr*>(&ss), static_cast<int>(sa_len));
        if(result == SOCKET_ERROR)
            ec = std::error_code(::WSAGetLastError(), std::system_category());
        else
            ec.clear();
#else
        auto result = ::sendto(m_fd, data.data(), data.size(), 0,
                               reinterpret_cast<const sockaddr*>(&ss), sa_len);
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
    detail::move_only_function<void(const recv_metadata &, std::span<std::byte>)> m_receive_handler;
#ifdef _WIN32
    LPFN_WSARECVMSG m_fn_wsarecvmsg{nullptr};
#endif

    // -------------------------------------------------------------------------
    // Address helpers
    // -------------------------------------------------------------------------

    static bool is_ipv6(const std::string &addr)
    {
        in6_addr tmp{};
        return ::inet_pton(AF_INET6, addr.c_str(), &tmp) == 1;
    }

    struct sockaddr_result
    {
        sockaddr_storage ss{};
        socklen_t len{};
    };

    static sockaddr_result build_sockaddr(const endpoint &dest)
    {
        sockaddr_result r;
        if(is_ipv6(dest.address))
        {
            auto &addr6 = *reinterpret_cast<sockaddr_in6 *>(&r.ss);
            addr6.sin6_family = AF_INET6;
            addr6.sin6_port = htons(dest.port);
            ::inet_pton(AF_INET6, dest.address.c_str(), &addr6.sin6_addr);
            r.len = sizeof(sockaddr_in6);
        }
        else
        {
            auto &addr4 = *reinterpret_cast<sockaddr_in *>(&r.ss);
            addr4.sin_family = AF_INET;
            addr4.sin_port = htons(dest.port);
            ::inet_pton(AF_INET, dest.address.c_str(), &addr4.sin_addr);
            r.len = sizeof(sockaddr_in);
        }
        return r;
    }

    static unsigned int resolve_ipv6_interface_index([[maybe_unused]] const std::string &addr)
    {
        if(addr.empty())
            return 0;
#ifdef _WIN32
        ULONG buf_size = 15000;
        std::unique_ptr<std::byte[]> buffer;
        ULONG result = ERROR_BUFFER_OVERFLOW;

        for(int32_t attempts = 0; attempts < 3 && result == ERROR_BUFFER_OVERFLOW; ++attempts)
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

    // -------------------------------------------------------------------------
    // Platform setsockopt helpers -- eliminate #ifdef duplication
    // -------------------------------------------------------------------------

    void cleanup_on_error()
    {
        detail::close_socket(m_fd);
        m_fd = detail::invalid_socket;
    }

    // Returns true on success. On failure, sets ec and cleans up m_fd.
    bool set_sock_opt(int32_t level, int32_t optname, const void *optval,
                      socklen_t optlen, std::error_code &ec)
    {
#ifdef _WIN32
        if(::setsockopt(m_fd, level, optname,
                        reinterpret_cast<const char*>(optval), optlen) == SOCKET_ERROR)
        {
            ec = std::error_code(::WSAGetLastError(), std::system_category());
            cleanup_on_error();
            return false;
        }
#else
        if(::setsockopt(m_fd, level, optname, optval, optlen) < 0)
        {
            ec = std::error_code(errno, std::generic_category());
            cleanup_on_error();
            return false;
        }
#endif
        return true;
    }

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
        const int32_t flags = ::fcntl(m_fd, F_GETFL, 0);
        if(flags < 0 || ::fcntl(m_fd, F_SETFL, flags | O_NONBLOCK) < 0)
        {
            ec = std::error_code(errno, std::generic_category());
            return false;
        }
#endif
        return true;
    }

    // -------------------------------------------------------------------------
    // Socket configuration -- single implementation using error_code
    // -------------------------------------------------------------------------

    // Non-throwing -- the throwing overload wraps this.
    void open_and_configure(const socket_options &opts, std::error_code &ec)
    {
        ec.clear();

        detail::validate_multicast_address(opts.multicast_group.address, ec);
        if(ec) return;

        const bool v6 = is_ipv6(opts.multicast_group.address);
        const int32_t family = v6 ? AF_INET6 : AF_INET;

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

        const int32_t one = 1;
        if(!set_sock_opt(SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one), ec))
            return;

#if defined(SO_REUSEPORT)
        (void)::setsockopt(m_fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
#endif

        if(!set_nonblocking(ec))
        {
            cleanup_on_error();
            return;
        }

        if(v6)
            configure_ipv6(opts, ec);
        else
            configure_ipv4(opts, ec);

        if(ec)
            return;

#ifdef _WIN32
        {
            GUID guid = WSAID_WSARECVMSG;
            DWORD bytes_returned = 0;
            if(::WSAIoctl(m_fd,
                          SIO_GET_EXTENSION_FUNCTION_POINTER,
                          &guid, sizeof(guid),
                          &m_fn_wsarecvmsg, sizeof(m_fn_wsarecvmsg),
                          &bytes_returned, nullptr, nullptr) == SOCKET_ERROR)
            {
                m_fn_wsarecvmsg = nullptr;
            }
        }
#endif
    }

    // Throwing -- delegates to the ec overload.
    void open_and_configure(const socket_options &opts)
    {
        std::error_code ec;
        open_and_configure(opts, ec);
        if(ec)
            throw std::system_error(ec, "DefaultSocket::open_and_configure");
    }

    // -------------------------------------------------------------------------
    // IPv4 configuration
    // -------------------------------------------------------------------------

    void configure_ipv4(const socket_options &opts, std::error_code &ec)
    {
        // Bind
        {
            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_ANY);
            addr.sin_port = htons(opts.multicast_group.port);

            if(!bind_socket(reinterpret_cast<const sockaddr*>(&addr),
                            static_cast<socklen_t>(sizeof(addr)), ec))
                return;
        }

        // Interface address
        in_addr iface_addr{};
        if(opts.interface_address.empty())
            iface_addr.s_addr = htonl(INADDR_ANY);
        else if(::inet_pton(AF_INET, opts.interface_address.c_str(), &iface_addr) != 1)
        {
            ec = std::make_error_code(std::errc::invalid_argument);
            cleanup_on_error();
            return;
        }

        // IP_MULTICAST_IF
        if(!opts.interface_address.empty())
        {
            if(!set_sock_opt(IPPROTO_IP, IP_MULTICAST_IF, &iface_addr,
                             sizeof(iface_addr), ec))
                return;
        }

        // IP_ADD_MEMBERSHIP
        {
            ip_mreq mreq{};
            ::inet_pton(AF_INET, opts.multicast_group.address.c_str(), &mreq.imr_multiaddr);
            mreq.imr_interface = iface_addr;
            if(!set_sock_opt(IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq,
                             sizeof(mreq), ec))
                return;
        }

        // IP_MULTICAST_TTL
        {
            const int32_t ttl_val = static_cast<int32_t>(opts.multicast_ttl.value_or(255));
            if(!set_sock_opt(IPPROTO_IP, IP_MULTICAST_TTL, &ttl_val,
                             sizeof(ttl_val), ec))
                return;
        }

        // IP_MULTICAST_LOOP
        {
            const int32_t val = (opts.multicast_loopback == loopback_mode::enabled) ? 1 : 0;
            if(!set_sock_opt(IPPROTO_IP, IP_MULTICAST_LOOP, &val,
                             sizeof(val), ec))
                return;
        }

#ifdef IP_RECVTTL
        {
            const int32_t opt = 1;
#ifdef _WIN32
            (void)::setsockopt(m_fd, IPPROTO_IP, IP_RECVTTL,
                               reinterpret_cast<const char*>(&opt), sizeof(opt));
#else
            (void)::setsockopt(m_fd, IPPROTO_IP, IP_RECVTTL, &opt, sizeof(opt));
#endif
        }
#endif

#if defined(IP_PKTINFO)
        {
            const int32_t opt = 1;
#ifdef _WIN32
            (void)::setsockopt(m_fd, IPPROTO_IP, IP_PKTINFO,
                               reinterpret_cast<const char*>(&opt), sizeof(opt));
#else
            (void)::setsockopt(m_fd, IPPROTO_IP, IP_PKTINFO, &opt, sizeof(opt));
#endif
        }
#elif defined(__APPLE__) && defined(IP_RECVIF)
        {
            const int32_t opt = 1;
            (void)::setsockopt(m_fd, IPPROTO_IP, IP_RECVIF, &opt, sizeof(opt));
        }
#endif
    }

    // -------------------------------------------------------------------------
    // IPv6 configuration
    // -------------------------------------------------------------------------

    void configure_ipv6(const socket_options &opts, std::error_code &ec)
    {
        // Bind
        {
            sockaddr_in6 addr6{};
            addr6.sin6_family = AF_INET6;
            addr6.sin6_addr = in6addr_any;
            addr6.sin6_port = htons(opts.multicast_group.port);

            if(!bind_socket(reinterpret_cast<const sockaddr*>(&addr6),
                            static_cast<socklen_t>(sizeof(addr6)), ec))
                return;
        }

        unsigned int iface_idx = resolve_ipv6_interface_index(opts.interface_address);

        // IPV6_MULTICAST_IF
        if(!opts.interface_address.empty())
        {
            if(!set_sock_opt(IPPROTO_IPV6, IPV6_MULTICAST_IF, &iface_idx,
                             sizeof(iface_idx), ec))
                return;
        }

        // IPV6_JOIN_GROUP
        {
            ipv6_mreq mreq6{};
            ::inet_pton(AF_INET6, opts.multicast_group.address.c_str(), &mreq6.ipv6mr_multiaddr);
            mreq6.ipv6mr_interface = iface_idx;
            if(!set_sock_opt(IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq6,
                             sizeof(mreq6), ec))
                return;
        }

        // IPV6_MULTICAST_HOPS
        {
            const int32_t hops_val = static_cast<int32_t>(opts.multicast_ttl.value_or(255));
            if(!set_sock_opt(IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops_val,
                             sizeof(hops_val), ec))
                return;
        }

        // IPV6_MULTICAST_LOOP
        {
            const int32_t val = (opts.multicast_loopback == loopback_mode::enabled) ? 1 : 0;
            if(!set_sock_opt(IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &val,
                             sizeof(val), ec))
                return;
        }

#ifdef IPV6_RECVHOPLIMIT
        {
            const int32_t opt = 1;
#ifdef _WIN32
            (void)::setsockopt(m_fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT,
                               reinterpret_cast<const char*>(&opt), sizeof(opt));
#else
            (void)::setsockopt(m_fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &opt, sizeof(opt));
#endif
        }
#endif

#ifdef IPV6_RECVPKTINFO
        {
            const int32_t opt = 1;
#ifdef _WIN32
            (void)::setsockopt(m_fd, IPPROTO_IPV6, IPV6_RECVPKTINFO,
                               reinterpret_cast<const char*>(&opt), sizeof(opt));
#else
            (void)::setsockopt(m_fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &opt, sizeof(opt));
#endif
        }
#endif
    }

    // -------------------------------------------------------------------------
    // Bind helper
    // -------------------------------------------------------------------------

    bool bind_socket(const sockaddr *addr, socklen_t addrlen, std::error_code &ec)
    {
#ifdef _WIN32
        if(::bind(m_fd, addr, static_cast<int>(addrlen)) == SOCKET_ERROR)
        {
            ec = std::error_code(::WSAGetLastError(), std::system_category());
            cleanup_on_error();
            return false;
        }
#else
        if(::bind(m_fd, addr, addrlen) < 0)
        {
            ec = std::error_code(errno, std::generic_category());
            cleanup_on_error();
            return false;
        }
#endif
        return true;
    }
};

static_assert(mdnspp::SocketLike<mdnspp::DefaultSocket>, "DefaultSocket must satisfy SocketLike — check async_receive/send/close signatures");

}

#endif
