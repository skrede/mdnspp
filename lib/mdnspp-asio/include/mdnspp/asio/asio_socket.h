#ifndef HPP_GUARD_MDNSPP_ASIO_SOCKET_H
#define HPP_GUARD_MDNSPP_ASIO_SOCKET_H

#include <mdnspp/policy.h>
#include <mdnspp/endpoint.h>
#include <mdnspp/socket_options.h>
#include <mdnspp/detail/validate_multicast.h>

#include <asio.hpp>

#include <span>
#include <vector>
#include <functional>
#include <system_error>

namespace mdnspp {

class AsioSocket
{
public:
    explicit AsioSocket(asio::io_context &io)
        : m_socket(io)
        , m_sender_endpoint{}
    {
        socket_options default_opts;
        const auto multicast_addr = asio::ip::make_address(default_opts.multicast_group.address);

        m_socket.open(asio::ip::udp::v4());
        m_socket.set_option(asio::ip::udp::socket::reuse_address(true));
        m_socket.bind(asio::ip::udp::endpoint(asio::ip::address_v4::any(), default_opts.multicast_group.port));
        m_socket.set_option(asio::ip::multicast::join_group(multicast_addr));
        m_buffer.resize(4096);
    }

    explicit AsioSocket(asio::io_context &io, std::error_code &ec)
        : m_socket(io)
        , m_sender_endpoint{}
    {
        socket_options default_opts;
        const auto multicast_addr = asio::ip::make_address(default_opts.multicast_group.address, ec);
        if(ec) return;

        m_socket.open(asio::ip::udp::v4(), ec);
        if(ec) return;
        m_socket.set_option(asio::ip::udp::socket::reuse_address(true), ec);
        if(ec) return;
        m_socket.bind(asio::ip::udp::endpoint(asio::ip::address_v4::any(), default_opts.multicast_group.port), ec);
        if(ec) return;
        m_socket.set_option(asio::ip::multicast::join_group(multicast_addr), ec);
        if(ec) return;
        m_buffer.resize(4096);
    }

    // Throwing constructor with socket_options.
    explicit AsioSocket(asio::io_context &io, const socket_options &opts)
        : m_socket(io)
        , m_sender_endpoint{}
    {
        detail::validate_multicast_address(opts.multicast_group.address);
        const auto multicast_addr = asio::ip::make_address(opts.multicast_group.address);

        if(multicast_addr.is_v6())
        {
            m_socket.open(asio::ip::udp::v6());
            m_socket.set_option(asio::ip::udp::socket::reuse_address(true));
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
            m_socket.set_option(asio::ip::udp::socket::reuse_address(true));
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

        m_buffer.resize(4096);
    }

    // Non-throwing constructor with socket_options.
    explicit AsioSocket(asio::io_context &io, const socket_options &opts, std::error_code &ec)
        : m_socket(io)
        , m_sender_endpoint{}
    {
        detail::validate_multicast_address(opts.multicast_group.address, ec);
        if(ec) return;
        const auto multicast_addr = asio::ip::make_address(opts.multicast_group.address, ec);
        if(ec) return;

        if(multicast_addr.is_v6())
        {
            m_socket.open(asio::ip::udp::v6(), ec);
            if(ec) return;
            m_socket.set_option(asio::ip::udp::socket::reuse_address(true), ec);
            if(ec) return;
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
            m_socket.set_option(asio::ip::udp::socket::reuse_address(true), ec);
            if(ec) return;
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

        m_buffer.resize(4096);
    }

    void async_receive(std::function<void(const mdnspp::endpoint &, std::span<std::byte>)> handler)
    {
        m_socket.async_receive_from(
            asio::buffer(m_buffer),
            m_sender_endpoint,
            [this, handler = std::move(handler)](std::error_code ec, std::size_t bytes)
            {
                if(!ec)
                {
                    mdnspp::endpoint ep{
                        m_sender_endpoint.address().to_string(),
                        m_sender_endpoint.port()
                    };
                    handler(ep, std::span<std::byte>(m_buffer.data(), bytes));
                }
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

private:
    asio::ip::udp::socket m_socket;
    asio::ip::udp::endpoint m_sender_endpoint;
    std::vector<std::byte> m_buffer;
};

}

static_assert(mdnspp::SocketLike<mdnspp::AsioSocket>, "AsioSocket must satisfy SocketLike — check async_receive/send/close signatures"
);

#endif
