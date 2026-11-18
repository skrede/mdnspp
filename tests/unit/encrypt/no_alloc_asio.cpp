#if defined(MDNSPP_HAS_ASIO)

#include "helpers.h"

#include "support/skip_or_fail.h"
#include "support/alloc_counter.h"

#include "mdnspp/asio/asio_socket.h"

#include <asio.hpp>

#include <catch2/catch_test_macros.hpp>

#include <span>
#include <array>
#include <memory>
#include <cstddef>
#include <cstdint>
#include <system_error>

namespace {

constexpr int window_cycles = 50;

using backend_socket = mdnspp::encrypt::encrypted_socket<mdnspp::asio_socket>;

void drain(asio::io_context &io, const uint64_t &delivered, uint64_t target)
{
    for(int i = 0; i < 16 && delivered < target; ++i)
    {
        io.restart();
        io.poll();
    }
}

class plain_rig
{
public:
    plain_rig()
        : m_io{}
        , m_receiver(m_io, asio::ip::udp::endpoint(asio::ip::address_v4::loopback(), 0))
        , m_sender(m_io, asio::ip::udp::v4())
        , m_dest(asio::ip::address_v4::loopback(), m_receiver.local_endpoint().port())
        , m_token(std::make_shared<char>())
        , m_buffer{}
        , m_from{}
        , m_delivered(0)
    {
        arm();
    }

    void cycle(std::span<const std::byte> datagram)
    {
        m_sender.send_to(asio::buffer(datagram.data(), datagram.size()), m_dest);
        drain(m_io, m_delivered, m_delivered + 1);
    }

    uint64_t delivered() const noexcept { return m_delivered; }

private:
    asio::io_context m_io;
    asio::ip::udp::socket m_receiver;
    asio::ip::udp::socket m_sender;
    asio::ip::udp::endpoint m_dest;
    std::shared_ptr<char> m_token;
    std::array<std::byte, 2048> m_buffer;
    asio::ip::udp::endpoint m_from;
    uint64_t m_delivered;

    void arm()
    {
        std::array<std::byte, 64> pad{};
        m_receiver.async_wait(asio::ip::udp::socket::wait_read,
            [this, token = std::weak_ptr<char>(m_token), pad](std::error_code ec) mutable
            {
                if(token.expired() || ec)
                    return;
                m_receiver.receive_from(asio::buffer(m_buffer), m_from);
                ++m_delivered;
                arm();
            });
    }
};

class encrypted_rig
{
public:
    encrypted_rig()
        : m_io{}
        , m_receiver_ec{}
        , m_sender_ec{}
        , m_receiver(m_io, group_opts(2), m_receiver_ec)
        , m_sender(m_io, group_opts(1), m_sender_ec)
        , m_dest{"127.0.0.1", m_receiver_ec ? uint16_t{0} : port_of(m_receiver.inner())}
        , m_delivered(0)
    {
        if(const std::error_code ec = m_receiver_ec ? m_receiver_ec : m_sender_ec)
            mdnspp::test_support::skip_or_fail("asio_socket construction failed: " + ec.message());
        arm();
    }

    void cycle(std::span<const std::byte> plaintext)
    {
        m_sender.send(m_dest, plaintext);
        drain(m_io, m_delivered, m_delivered + 1);
    }

    uint64_t delivered() const noexcept { return m_delivered; }

private:
    asio::io_context m_io;
    std::error_code m_receiver_ec;
    std::error_code m_sender_ec;
    backend_socket m_receiver;
    backend_socket m_sender;
    mdnspp::endpoint m_dest;
    uint64_t m_delivered;

    static mdnspp::encrypt::encrypt_socket_options group_opts(uint32_t sender_id)
    {
        auto opts = make_test_opts(std::byte{0x42}, sender_id);
        opts.multicast_group = mdnspp::endpoint{"224.0.0.251", 0};
        return opts;
    }

    static uint16_t port_of(mdnspp::asio_socket &sock)
    {
        sockaddr_in addr{};
        socklen_t len = sizeof(addr);
        ::getsockname(sock.native_handle(), reinterpret_cast<sockaddr *>(&addr), &len);
        return ntohs(addr.sin_port);
    }

    void arm()
    {
        m_receiver.async_receive([this](std::error_code, const mdnspp::recv_metadata &, std::span<std::byte>)
        {
            ++m_delivered;
            arm();
        });
    }
};

template <typename Rig>
uint64_t allocations_over_window(Rig &rig, std::span<const std::byte> payload)
{
    rig.cycle(payload);
    mdnspp::test_support::reset_allocation_count();
    for(int i = 0; i < window_cycles; ++i)
        rig.cycle(payload);
    return mdnspp::test_support::allocation_count();
}

}

TEST_CASE("encrypted send and deliver over the asio socket allocates no more than a plain asio receive loop",
          "[encrypted_socket][alloc][asio_socket]")
{
    const plain_bytes plaintext(200, std::byte{0x5A});
    plain_rig plain;
    const uint64_t baseline = allocations_over_window(plain, plaintext);
    encrypted_rig encrypted;
    const uint64_t measured = allocations_over_window(encrypted, plaintext);
    CHECK(plain.delivered() == window_cycles + 1);
    CHECK(encrypted.delivered() == window_cycles + 1);
    INFO("baseline allocations " << baseline << ", encrypted allocations " << measured);
    REQUIRE(measured <= baseline);
}

#endif
