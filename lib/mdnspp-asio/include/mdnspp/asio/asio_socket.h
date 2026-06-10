#ifndef HPP_GUARD_MDNSPP_ASIO_ASIO_SOCKET_H
#define HPP_GUARD_MDNSPP_ASIO_ASIO_SOCKET_H

#include "mdnspp/policy.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/socket_options.h"

#include "mdnspp/detail/compat.h"
#include "mdnspp/detail/validate_multicast.h"

#include <asio.hpp>

#ifdef _WIN32
#include <mswsock.h>
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <cstring>
#  ifdef __APPLE__
#    include <net/if_dl.h>
#  endif
#endif

#include <span>
#include <array>
#include <vector>
#include <optional>
#include <system_error>

namespace mdnspp {

class asio_socket
{
public:
    explicit asio_socket(asio::io_context &io)
        : asio_socket(io, socket_options{})
    {}

    explicit asio_socket(asio::io_context &io, std::error_code &ec)
        : asio_socket(io, socket_options{}, ec)
    {}

    // Throwing constructor with socket_options.
    explicit asio_socket(asio::io_context &io, const socket_options &opts)
        : m_socket(io)
    {
        detail::validate_multicast_address(opts.multicast_group.address);
        const auto multicast_addr = asio::ip::make_address(opts.multicast_group.address);

        if(multicast_addr.is_v6())
        {
            m_socket.open(asio::ip::udp::v6());
            m_socket.non_blocking(true);
            configure_ttl_extraction(true);
            m_socket.set_option(asio::ip::udp::socket::reuse_address(true));
            apply_reuse_port();
            m_socket.bind(asio::ip::udp::endpoint(asio::ip::address_v6::any(), opts.multicast_group.port));

            if(!opts.interface_address.empty())
            {
                auto iface_v6 = asio::ip::make_address_v6(opts.interface_address);
                m_socket.set_option(asio::ip::multicast::outbound_interface(
                    static_cast<unsigned int>(iface_v6.scope_id())));
                m_socket.set_option(asio::ip::multicast::join_group(multicast_addr));
            }
            else
            {
                m_socket.set_option(asio::ip::multicast::join_group(multicast_addr));
            }
        }
        else
        {
            m_socket.open(asio::ip::udp::v4());
            m_socket.non_blocking(true);
            configure_ttl_extraction(false);
            m_socket.set_option(asio::ip::udp::socket::reuse_address(true));
            apply_reuse_port();
            m_socket.bind(asio::ip::udp::endpoint(asio::ip::address_v4::any(), opts.multicast_group.port));

            if(!opts.interface_address.empty())
            {
                auto iface_addr = asio::ip::make_address_v4(opts.interface_address);
                m_socket.set_option(asio::ip::multicast::outbound_interface(iface_addr));
                m_socket.set_option(asio::ip::multicast::join_group(multicast_addr.to_v4(), iface_addr));
            }
            else
            {
                m_socket.set_option(asio::ip::multicast::join_group(multicast_addr));
            }
        }

        m_socket.set_option(asio::ip::multicast::hops(opts.multicast_ttl.value_or(255)));

        m_socket.set_option(asio::ip::multicast::enable_loopback(
            opts.multicast_loopback == loopback_mode::enabled));

        m_buffer.resize(detail::max_udp_payload);
    }

    // Non-throwing constructor with socket_options.
    explicit asio_socket(asio::io_context &io, const socket_options &opts, std::error_code &ec)
        : m_socket(io)
    {
        detail::validate_multicast_address(opts.multicast_group.address, ec);
        if(ec) return;
        const auto multicast_addr = asio::ip::make_address(opts.multicast_group.address, ec);
        if(ec) return;

        if(multicast_addr.is_v6())
        {
            m_socket.open(asio::ip::udp::v6(), ec);
            if(ec) return;
            m_socket.non_blocking(true, ec);
            if(ec) return;
            configure_ttl_extraction(true);
            m_socket.set_option(asio::ip::udp::socket::reuse_address(true), ec);
            if(ec) return;
            apply_reuse_port();
            m_socket.bind(asio::ip::udp::endpoint(asio::ip::address_v6::any(), opts.multicast_group.port), ec);
            if(ec) return;

            if(!opts.interface_address.empty())
            {
                auto iface_v6 = asio::ip::make_address_v6(opts.interface_address, ec);
                if(ec) return;
                m_socket.set_option(asio::ip::multicast::outbound_interface(
                    static_cast<unsigned int>(iface_v6.scope_id())), ec);
                if(ec) return;
                m_socket.set_option(asio::ip::multicast::join_group(multicast_addr), ec);
                if(ec) return;
            }
            else
            {
                m_socket.set_option(asio::ip::multicast::join_group(multicast_addr), ec);
                if(ec) return;
            }
        }
        else
        {
            m_socket.open(asio::ip::udp::v4(), ec);
            if(ec) return;
            m_socket.non_blocking(true, ec);
            if(ec) return;
            configure_ttl_extraction(false);
            m_socket.set_option(asio::ip::udp::socket::reuse_address(true), ec);
            if(ec) return;
            apply_reuse_port();
            m_socket.bind(asio::ip::udp::endpoint(asio::ip::address_v4::any(), opts.multicast_group.port), ec);
            if(ec) return;

            if(!opts.interface_address.empty())
            {
                auto iface_addr = asio::ip::make_address_v4(opts.interface_address, ec);
                if(ec) return;
                m_socket.set_option(asio::ip::multicast::outbound_interface(iface_addr), ec);
                if(ec) return;
                m_socket.set_option(asio::ip::multicast::join_group(multicast_addr.to_v4(), iface_addr), ec);
                if(ec) return;
            }
            else
            {
                m_socket.set_option(asio::ip::multicast::join_group(multicast_addr), ec);
                if(ec) return;
            }
        }

        m_socket.set_option(asio::ip::multicast::hops(opts.multicast_ttl.value_or(255)), ec);
        if(ec) return;

        m_socket.set_option(asio::ip::multicast::enable_loopback(
            opts.multicast_loopback == loopback_mode::enabled), ec);
        if(ec) return;

        m_buffer.resize(detail::max_udp_payload);
    }

    void async_receive(move_only_function<void(std::error_code, const mdnspp::recv_metadata &, std::span<std::byte>)> handler)
    {
        m_socket.async_wait(
            asio::ip::udp::socket::wait_read,
            [this, handler = std::move(handler)](std::error_code ec) mutable
            {
                if(ec)
                {
                    handler(ec, mdnspp::recv_metadata{}, std::span<std::byte>{});
                    return;
                }

#ifndef _WIN32
                sockaddr_storage sender_addr{};
                iovec iov{};
                iov.iov_base = m_buffer.data();
                iov.iov_len  = m_buffer.size();

                alignas(cmsghdr) std::array<std::byte, 64> ctrl_buf{};

                msghdr msg{};
                msg.msg_name    = &sender_addr;
                msg.msg_namelen = sizeof(sender_addr);
                msg.msg_iov     = &iov;
                msg.msg_iovlen  = 1;
                msg.msg_control    = ctrl_buf.data();
                msg.msg_controllen = ctrl_buf.size();

                const ssize_t n = ::recvmsg(m_socket.native_handle(), &msg, 0);
                if(n < 0)
                {
                    if(errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                    {
                        async_receive(std::move(handler)); // spurious readiness — re-arm
                        return;
                    }
                    handler(std::error_code(errno, std::generic_category()),
                            mdnspp::recv_metadata{}, std::span<std::byte>{});
                    return;
                }
#ifdef MSG_TRUNC
                if(msg.msg_flags & MSG_TRUNC) // truncated datagram — drop and re-arm
                {
                    async_receive(std::move(handler));
                    return;
                }
#endif

                std::optional<uint8_t> ttl;
                uint32_t recv_ifindex = 0;
                for(cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg))
                {
                    if(cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TTL)
                    {
                        int ttl_val{};
                        std::memcpy(&ttl_val, CMSG_DATA(cmsg), sizeof(ttl_val));
                        ttl = static_cast<uint8_t>(ttl_val);
                    }
#ifdef IPV6_HOPLIMIT
                    else if(cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_HOPLIMIT)
                    {
                        int ttl_val{};
                        std::memcpy(&ttl_val, CMSG_DATA(cmsg), sizeof(ttl_val));
                        ttl = static_cast<uint8_t>(ttl_val);
                    }
#endif
#if defined(IP_PKTINFO)
                    else if(cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO)
                    {
                        in_pktinfo pktinfo{};
                        std::memcpy(&pktinfo, CMSG_DATA(cmsg), sizeof(pktinfo));
                        recv_ifindex = static_cast<uint32_t>(pktinfo.ipi_ifindex);
                    }
#elif defined(__APPLE__) && defined(IP_RECVIF)
                    else if(cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_RECVIF)
                    {
                        sockaddr_dl sdl{};
                        std::memcpy(&sdl, CMSG_DATA(cmsg),
                                    (std::min)(sizeof(sdl),
                                               static_cast<std::size_t>(cmsg->cmsg_len) -
                                               sizeof(cmsghdr)));
                        recv_ifindex = static_cast<uint32_t>(sdl.sdl_index);
                    }
#endif
#ifdef IPV6_PKTINFO
                    else if(cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO)
                    {
                        in6_pktinfo pktinfo6{};
                        std::memcpy(&pktinfo6, CMSG_DATA(cmsg), sizeof(pktinfo6));
                        recv_ifindex = static_cast<uint32_t>(pktinfo6.ipi6_ifindex);
                    }
#endif
                }

                char addr_str[INET6_ADDRSTRLEN]{};
                uint16_t port{};
                if(sender_addr.ss_family == AF_INET6)
                {
                    const auto *sa6 = reinterpret_cast<const sockaddr_in6 *>(&sender_addr);
                    ::inet_ntop(AF_INET6, &sa6->sin6_addr, addr_str, sizeof(addr_str));
                    port = ntohs(sa6->sin6_port);
                }
                else
                {
                    const auto *sa4 = reinterpret_cast<const sockaddr_in *>(&sender_addr);
                    ::inet_ntop(AF_INET, &sa4->sin_addr, addr_str, sizeof(addr_str));
                    port = ntohs(sa4->sin_port);
                }

                mdnspp::endpoint ep{addr_str, port};
                mdnspp::recv_metadata meta{ep, ttl, recv_ifindex};
                handler(std::error_code{}, meta, std::span<std::byte>(m_buffer.data(), static_cast<std::size_t>(n)));

#else // _WIN32
                if(m_fn_wsarecvmsg)
                {
                    sockaddr_storage sender_addr{};
                    WSABUF data_buf{};
                    data_buf.len = static_cast<ULONG>(m_buffer.size());
                    data_buf.buf = reinterpret_cast<char *>(m_buffer.data());

                    alignas(WSACMSGHDR) std::array<std::byte, 64> ctrl_buf{};

                    WSAMSG wmsg{};
                    wmsg.name       = reinterpret_cast<LPSOCKADDR>(&sender_addr);
                    wmsg.namelen    = sizeof(sender_addr);
                    wmsg.lpBuffers  = &data_buf;
                    wmsg.dwBufferCount = 1;
                    wmsg.Control.buf = reinterpret_cast<char *>(ctrl_buf.data());
                    wmsg.Control.len = static_cast<ULONG>(ctrl_buf.size());
                    wmsg.dwFlags    = 0;

                    DWORD received = 0;
                    if(m_fn_wsarecvmsg(m_socket.native_handle(), &wmsg, &received, nullptr, nullptr) == SOCKET_ERROR)
                    {
                        const int err = ::WSAGetLastError();
                        if(err == WSAEWOULDBLOCK || err == WSAEMSGSIZE) // spurious readiness / truncated datagram
                        {
                            async_receive(std::move(handler));
                            return;
                        }
                        handler(std::error_code(err, std::system_category()),
                                mdnspp::recv_metadata{}, std::span<std::byte>{});
                        return;
                    }
                    if(wmsg.dwFlags & MSG_PARTIAL) // truncated datagram — drop and re-arm
                    {
                        async_receive(std::move(handler));
                        return;
                    }

                    std::optional<uint8_t> ttl;
                    uint32_t recv_ifindex = 0;
                    for(WSACMSGHDR *cmsg = WSA_CMSG_FIRSTHDR(&wmsg); cmsg; cmsg = WSA_CMSG_NXTHDR(&wmsg, cmsg))
                    {
                        if(cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TTL)
                        {
                            int ttl_val{};
                            std::memcpy(&ttl_val, WSA_CMSG_DATA(cmsg), sizeof(ttl_val));
                            ttl = static_cast<uint8_t>(ttl_val);
                        }
#ifdef IPV6_HOPLIMIT
                        else if(cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_HOPLIMIT)
                        {
                            int ttl_val{};
                            std::memcpy(&ttl_val, WSA_CMSG_DATA(cmsg), sizeof(ttl_val));
                            ttl = static_cast<uint8_t>(ttl_val);
                        }
#endif
#ifdef IP_PKTINFO
                        else if(cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO)
                        {
                            IN_PKTINFO pktinfo{};
                            std::memcpy(&pktinfo, WSA_CMSG_DATA(cmsg), sizeof(pktinfo));
                            recv_ifindex = static_cast<uint32_t>(pktinfo.ipi_ifindex);
                        }
#endif
#ifdef IPV6_PKTINFO
                        else if(cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO)
                        {
                            IN6_PKTINFO pktinfo6{};
                            std::memcpy(&pktinfo6, WSA_CMSG_DATA(cmsg), sizeof(pktinfo6));
                            recv_ifindex = static_cast<uint32_t>(pktinfo6.ipi6_ifindex);
                        }
#endif
                    }

                    char addr_str[INET6_ADDRSTRLEN]{};
                    uint16_t port{};
                    if(sender_addr.ss_family == AF_INET6)
                    {
                        const auto *sa6 = reinterpret_cast<const sockaddr_in6 *>(&sender_addr);
                        ::inet_ntop(AF_INET6, &sa6->sin6_addr, addr_str, sizeof(addr_str));
                        port = ntohs(sa6->sin6_port);
                    }
                    else
                    {
                        const auto *sa4 = reinterpret_cast<const sockaddr_in *>(&sender_addr);
                        ::inet_ntop(AF_INET, &sa4->sin_addr, addr_str, sizeof(addr_str));
                        port = ntohs(sa4->sin_port);
                    }

                    mdnspp::endpoint ep{addr_str, port};
                    mdnspp::recv_metadata meta{ep, ttl, recv_ifindex};
                    handler(std::error_code{}, meta, std::span<std::byte>(m_buffer.data(), static_cast<std::size_t>(received)));
                }
                else
                {
                    // Fallback: WSARecvMsg not available -- use recvfrom, TTL stays nullopt.
                    sockaddr_storage sender_addr{};
                    int namelen = sizeof(sender_addr);
                    const int n = ::recvfrom(m_socket.native_handle(),
                                             reinterpret_cast<char *>(m_buffer.data()),
                                             static_cast<int>(m_buffer.size()),
                                             0,
                                             reinterpret_cast<sockaddr *>(&sender_addr),
                                             &namelen);
                    if(n == SOCKET_ERROR)
                    {
                        const int err = ::WSAGetLastError();
                        if(err == WSAEWOULDBLOCK || err == WSAEMSGSIZE) // spurious readiness / truncated datagram
                        {
                            async_receive(std::move(handler));
                            return;
                        }
                        handler(std::error_code(err, std::system_category()),
                                mdnspp::recv_metadata{}, std::span<std::byte>{});
                        return;
                    }

                    char addr_str[INET6_ADDRSTRLEN]{};
                    uint16_t port{};
                    if(sender_addr.ss_family == AF_INET6)
                    {
                        const auto *sa6 = reinterpret_cast<const sockaddr_in6 *>(&sender_addr);
                        ::inet_ntop(AF_INET6, &sa6->sin6_addr, addr_str, sizeof(addr_str));
                        port = ntohs(sa6->sin6_port);
                    }
                    else
                    {
                        const auto *sa4 = reinterpret_cast<const sockaddr_in *>(&sender_addr);
                        ::inet_ntop(AF_INET, &sa4->sin_addr, addr_str, sizeof(addr_str));
                        port = ntohs(sa4->sin_port);
                    }

                    mdnspp::endpoint ep{addr_str, port};
                    mdnspp::recv_metadata meta{ep, std::nullopt};
                    handler(std::error_code{}, meta, std::span<std::byte>(m_buffer.data(), static_cast<std::size_t>(n)));
                }
#endif
            });
    }

    void send(const mdnspp::endpoint &dest, std::span<const std::byte> data)
    {
        std::error_code ec;
        asio::ip::udp::endpoint ep(asio::ip::make_address(dest.address, ec), dest.port);
        if(!ec)
            m_socket.send_to(asio::buffer(data.data(), data.size()), ep, 0, ec);
    }

    void send(const mdnspp::endpoint &dest, std::span<const std::byte> data, std::error_code &ec)
    {
        asio::ip::udp::endpoint ep(asio::ip::make_address(dest.address, ec), dest.port);
        if(!ec)
            m_socket.send_to(asio::buffer(data.data(), data.size()), ep, 0, ec);
    }

    void close()
    {
        if(m_socket.is_open())
        {
            std::error_code ec;
            m_socket.cancel(ec);
            m_socket.close(ec);
        }
    }

    auto native_handle() { return m_socket.native_handle(); }

private:
    // Apply SO_REUSEPORT in addition to asio's reuse_address (SO_REUSEADDR),
    // mirroring default_socket which sets both. For co-located same-port
    // multicast sockets (e.g. an announcing server and a browsing monitor in
    // one process, both bound to :5353), SO_REUSEPORT is the portable option
    // for guaranteeing inbound multicast fan-out to every joined socket across
    // kernels. Must be set before bind(). No-op where SO_REUSEPORT is absent.
    void apply_reuse_port()
    {
#if !defined(_WIN32) && defined(SO_REUSEPORT)
        const int one = 1;
        (void)::setsockopt(m_socket.native_handle(), SOL_SOCKET, SO_REUSEPORT,
                           reinterpret_cast<const char *>(&one), sizeof(one));
#endif
    }

    void configure_ttl_extraction(bool is_v6)
    {
#ifdef _WIN32
        {
            GUID guid = WSAID_WSARECVMSG;
            DWORD bytes_returned = 0;
            if(::WSAIoctl(m_socket.native_handle(),
                          SIO_GET_EXTENSION_FUNCTION_POINTER,
                          &guid, sizeof(guid),
                          &m_fn_wsarecvmsg, sizeof(m_fn_wsarecvmsg),
                          &bytes_returned, nullptr, nullptr) == SOCKET_ERROR)
            {
                m_fn_wsarecvmsg = nullptr;
            }
        }
        if(is_v6)
        {
#ifdef IPV6_RECVHOPLIMIT
            const int opt = 1;
            (void)::setsockopt(m_socket.native_handle(),
                               IPPROTO_IPV6, IPV6_RECVHOPLIMIT,
                               reinterpret_cast<const char *>(&opt), sizeof(opt));
#endif
#ifdef IPV6_RECVPKTINFO
            const int opt6pkt = 1;
            (void)::setsockopt(m_socket.native_handle(),
                               IPPROTO_IPV6, IPV6_RECVPKTINFO,
                               reinterpret_cast<const char *>(&opt6pkt), sizeof(opt6pkt));
#endif
        }
        else
        {
#ifdef IP_RECVTTL
            const int opt = 1;
            (void)::setsockopt(m_socket.native_handle(),
                               IPPROTO_IP, IP_RECVTTL,
                               reinterpret_cast<const char *>(&opt), sizeof(opt));
#endif
#ifdef IP_PKTINFO
            const int optpkt = 1;
            (void)::setsockopt(m_socket.native_handle(),
                               IPPROTO_IP, IP_PKTINFO,
                               reinterpret_cast<const char *>(&optpkt), sizeof(optpkt));
#endif
        }
#else
        if(is_v6)
        {
#ifdef IPV6_RECVHOPLIMIT
            const int opt = 1;
            (void)::setsockopt(m_socket.native_handle(),
                               IPPROTO_IPV6, IPV6_RECVHOPLIMIT,
                               &opt, sizeof(opt));
#endif
#ifdef IPV6_RECVPKTINFO
            const int opt6pkt = 1;
            (void)::setsockopt(m_socket.native_handle(),
                               IPPROTO_IPV6, IPV6_RECVPKTINFO,
                               &opt6pkt, sizeof(opt6pkt));
#endif
        }
        else
        {
#ifdef IP_RECVTTL
            const int opt = 1;
            (void)::setsockopt(m_socket.native_handle(),
                               IPPROTO_IP, IP_RECVTTL,
                               &opt, sizeof(opt));
#endif
#if defined(IP_PKTINFO)
            const int optpkt = 1;
            (void)::setsockopt(m_socket.native_handle(),
                               IPPROTO_IP, IP_PKTINFO,
                               &optpkt, sizeof(optpkt));
#elif defined(__APPLE__) && defined(IP_RECVIF)
            const int optrecvif = 1;
            (void)::setsockopt(m_socket.native_handle(),
                               IPPROTO_IP, IP_RECVIF,
                               &optrecvif, sizeof(optrecvif));
#endif
        }
#endif
    }

    asio::ip::udp::socket m_socket;
    std::vector<std::byte> m_buffer;
#ifdef _WIN32
    LPFN_WSARECVMSG m_fn_wsarecvmsg{nullptr};
#endif
};

}

static_assert(mdnspp::socket_like<mdnspp::asio_socket>, "asio_socket must satisfy socket_like — check async_receive/send/close signatures"
);

#endif
