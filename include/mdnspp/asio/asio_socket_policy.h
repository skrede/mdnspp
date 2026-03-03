#pragma once
#include <asio.hpp>
#include "mdnspp/socket_policy.h"
#include "mdnspp/endpoint.h"
#include <span>
#include <functional>
#include <vector>
#include <system_error>

namespace mdnspp::asio_policy {

class AsioSocketPolicy
{
public:
    explicit AsioSocketPolicy(asio::io_context &io)
        : m_socket(io)
        , m_sender_endpoint{}
    {
        const auto multicast_addr = asio::ip::make_address("224.0.0.251");
        const uint16_t mdns_port = 5353;

        m_socket.open(asio::ip::udp::v4());
        m_socket.set_option(asio::ip::udp::socket::reuse_address(true));
        // Bind to INADDR_ANY — not to multicast address (Linux/macOS pattern; Windows-only pattern would break Linux)
        m_socket.bind(asio::ip::udp::endpoint(asio::ip::address_v4::any(), mdns_port));
        m_socket.set_option(asio::ip::multicast::join_group(multicast_addr));
        m_buffer.resize(4096);
    }

    void async_receive(std::function<void(std::span<std::byte>, mdnspp::endpoint)> handler)
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
                    handler(std::span<std::byte>(m_buffer.data(), bytes), ep);
                }
            });
    }

    void send(mdnspp::endpoint dest, std::span<const std::byte> data)
    {
        asio::ip::udp::endpoint ep(
            asio::ip::make_address(dest.address), dest.port);
        m_socket.send_to(asio::buffer(data.data(), data.size()), ep);
    }

    void close()
    {
        if(m_socket.is_open())
        {
            std::error_code ec;
            m_socket.cancel(ec);
            m_socket.close(ec);
            // NOTE: For cross-thread safety, close() should be called from
            // the io_context thread or via asio::post(m_socket.get_executor(), ...).
            // Full strand wiring is deferred to Phase 5 (BEHAV-03).
        }
    }

private:
    asio::ip::udp::socket m_socket;
    asio::ip::udp::endpoint m_sender_endpoint;
    std::vector<std::byte> m_buffer;
};

} // namespace mdnspp::asio_policy

static_assert(
    mdnspp::SocketPolicy<mdnspp::asio_policy::AsioSocketPolicy>,
    "AsioSocketPolicy must satisfy SocketPolicy — check async_receive/send/close signatures"
);
