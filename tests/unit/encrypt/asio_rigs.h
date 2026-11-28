#ifndef HPP_GUARD_MDNSPP_ENCRYPT_ASIO_RIGS_H
#define HPP_GUARD_MDNSPP_ENCRYPT_ASIO_RIGS_H

#if defined(MDNSPP_HAS_ASIO)

#include "helpers.h"

#include "support/skip_or_fail.h"

#include "mdnspp/asio/asio_socket.h"

#include <asio.hpp>

#include <span>
#include <array>
#include <chrono>
#include <memory>
#include <cstddef>
#include <cstdint>
#include <system_error>

struct loopback_family
{
    asio::ip::udp protocol;
    asio::ip::address loopback;
    const char *group;
    const char *dest;
};

inline loopback_family ipv4_loopback()
{
    return {asio::ip::udp::v4(), asio::ip::address_v4::loopback(), "224.0.0.251", "127.0.0.1"};
}

inline loopback_family ipv6_loopback()
{
    return {asio::ip::udp::v6(), asio::ip::address_v6::loopback(), "ff02::fb", "::1"};
}

inline uint16_t bound_port(mdnspp::asio_socket &sock)
{
    sockaddr_storage addr{};
    socklen_t len = sizeof(addr);
    ::getsockname(sock.native_handle(), reinterpret_cast<sockaddr *>(&addr), &len);
    if(addr.ss_family == AF_INET6)
        return ntohs(reinterpret_cast<const sockaddr_in6 &>(addr).sin6_port);
    return ntohs(reinterpret_cast<const sockaddr_in &>(addr).sin_port);
}

// Windows asio reports UDP readiness from a background select thread, so a zero-timeout poll can
// return before the completion of a datagram that already arrived is queued; wait for it instead.
inline void drain(asio::io_context &io, const uint64_t &delivered, uint64_t target)
{
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    io.restart();
    while(delivered < target && io.run_one_until(deadline) != 0)
        continue;
}

class plain_rig
{
public:
    explicit plain_rig(const loopback_family &family)
        : m_io{}
        , m_receiver(m_io)
        , m_sender(m_io)
        , m_dest{}
        , m_token(std::make_shared<char>())
        , m_buffer{}
        , m_from{}
        , m_delivered(0)
    {
        std::error_code ec;
        open(family, ec);
        if(ec)
            mdnspp::test_support::skip_or_fail("plain asio socket construction failed: " + ec.message());
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

    void open(const loopback_family &family, std::error_code &ec)
    {
        m_receiver.open(family.protocol, ec);
        if(!ec)
            m_receiver.bind(asio::ip::udp::endpoint(family.loopback, 0), ec);
        if(!ec)
            m_sender.open(family.protocol, ec);
        if(!ec)
            m_dest = asio::ip::udp::endpoint(family.loopback, m_receiver.local_endpoint(ec).port());
    }

    void arm()
    {
        std::array<std::byte, 64> pad{};
        m_receiver.async_wait(asio::ip::udp::socket::wait_read,
            [this, token = std::weak_ptr<char>(m_token), pad](std::error_code ec) mutable
            {
                static_cast<void>(pad);
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
    explicit encrypted_rig(const loopback_family &family)
        : m_io{}
        , m_receiver_ec{}
        , m_sender_ec{}
        , m_receiver(m_io, group_opts(family, 2), m_receiver_ec)
        , m_sender(m_io, group_opts(family, 1), m_sender_ec)
        , m_dest{family.dest, m_receiver_ec ? uint16_t{0} : bound_port(m_receiver.inner())}
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
    using backend_socket = mdnspp::encrypt::encrypted_socket<mdnspp::asio_socket>;

    asio::io_context m_io;
    std::error_code m_receiver_ec;
    std::error_code m_sender_ec;
    backend_socket m_receiver;
    backend_socket m_sender;
    mdnspp::endpoint m_dest;
    uint64_t m_delivered;

    static mdnspp::encrypt::encrypt_socket_options group_opts(const loopback_family &family, uint32_t sender_id)
    {
        auto opts = make_test_opts(std::byte{0x42}, sender_id);
        opts.multicast_group = mdnspp::endpoint{family.group, 0};
        // Darwin rejects an IPv6 link-local group join with interface index 0 when it has no IPv6 route to the group.
        if(family.protocol == asio::ip::udp::v6())
            opts.interface_address = family.dest;
        return opts;
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

#endif

#endif
