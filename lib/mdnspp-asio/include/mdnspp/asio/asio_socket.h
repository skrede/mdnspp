#ifndef HPP_GUARD_MDNSPP_ASIO_ASIO_SOCKET_H
#define HPP_GUARD_MDNSPP_ASIO_ASIO_SOCKET_H

#include "mdnspp/policy.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/socket_options.h"

#include "mdnspp/detail/compat.h"
#include "mdnspp/detail/interface_resolve.h"
#include "mdnspp/detail/validate_multicast.h"
#include "mdnspp/detail/recv_datagram.h"

#include <asio.hpp>

#ifdef _WIN32
#include <mswsock.h>
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#include <span>
#include <string>
#include <vector>
#include <system_error>

namespace mdnspp {

class asio_socket
{
public:
    /// Executor of the underlying socket (asio convention).
    using executor_type = asio::ip::udp::socket::executor_type;

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

        // Translate interface_index / interface_name to the interface address
        // of the socket family; precedence index > name > address. An unknown
        // index or name fails with std::errc::invalid_argument.
        std::string iface_address;
        {
            std::error_code resolve_ec;
            iface_address = detail::resolve_socket_interface_address(
                opts, multicast_addr.is_v6(), resolve_ec);
            if(resolve_ec)
                throw std::system_error(resolve_ec, "asio_socket interface resolution");
        }

        if(multicast_addr.is_v6())
        {
            m_socket.open(asio::ip::udp::v6());
            m_socket.non_blocking(true);
            configure_ttl_extraction(true);
            m_socket.set_option(asio::ip::udp::socket::reuse_address(true));
            apply_reuse_port();
            m_socket.bind(asio::ip::udp::endpoint(asio::ip::address_v6::any(), opts.multicast_group.port));

            if(!iface_address.empty())
            {
                auto iface_v6 = asio::ip::make_address_v6(iface_address);
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

            if(!iface_address.empty())
            {
                auto iface_addr = asio::ip::make_address_v4(iface_address);
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

        const std::string iface_address = detail::resolve_socket_interface_address(
            opts, multicast_addr.is_v6(), ec);
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

            if(!iface_address.empty())
            {
                auto iface_v6 = asio::ip::make_address_v6(iface_address, ec);
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

            if(!iface_address.empty())
            {
                auto iface_addr = asio::ip::make_address_v4(iface_address, ec);
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

                const detail::datagram_result result = read_datagram();
                if(result.would_block || result.truncated)
                {
                    async_receive(std::move(handler));
                    return;
                }
                if(result.ec)
                {
                    handler(result.ec, mdnspp::recv_metadata{}, std::span<std::byte>{});
                    return;
                }
                handler(std::error_code{}, result.meta,
                        std::span<std::byte>(m_buffer.data(), result.size));
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

    /// Returns the I/O executor the socket was constructed with. Used by the
    /// async_* adapter initiations so that tokens which construct internal
    /// state on the operation's executor (e.g. asio::cancel_after's timer)
    /// resolve to the peer's io_context. The const_cast is required because
    /// asio::basic_socket::get_executor() is non-const; the call is
    /// logically const (it only reads the stored executor).
    executor_type get_executor() const noexcept
    {
        return const_cast<asio::ip::udp::socket &>(m_socket).get_executor();
    }

private:
    detail::datagram_result read_datagram()
    {
#ifdef _WIN32
        return detail::recv_datagram(m_socket.native_handle(), m_buffer, m_fn_wsarecvmsg);
#else
        return detail::recv_datagram(m_socket.native_handle(), m_buffer);
#endif
    }

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
