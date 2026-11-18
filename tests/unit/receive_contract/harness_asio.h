#ifndef HPP_GUARD_MDNSPP_RECEIVE_CONTRACT_HARNESS_ASIO_H
#define HPP_GUARD_MDNSPP_RECEIVE_CONTRACT_HARNESS_ASIO_H

#include "receive_contract/harness.h"

#include "support/skip_or_fail.h"

#include "mdnspp/socket_options.h"

#include "mdnspp/asio/asio_socket.h"

#include <asio.hpp>

#include <span>
#include <chrono>
#include <cstdint>
#include <system_error>

namespace mdnspp::test_support {

inline socket_options asio_ephemeral_group_options()
{
    return socket_options{.multicast_group = endpoint{"224.0.0.251", 0}};
}

template <>
struct harness<asio_socket>
{
    using ledger_type = arm_ledger<asio_socket>;

    harness()
        : m_io{}
        , m_socket_ec{}
        , m_sender{m_io, asio::ip::udp::v4()}
        , m_socket{m_io, asio_ephemeral_group_options(), m_socket_ec}
        , m_port{m_socket_ec ? uint16_t{0} : bound_port(m_socket.inner().native_handle())}
    {
        if(m_socket_ec)
            skip_or_fail("asio_socket construction failed: " + m_socket_ec.message());
    }

    ledger_type &socket() noexcept { return m_socket; }

    ledger_type &ledger() noexcept { return m_socket; }

    void inject(std::span<const std::byte> bytes)
    {
        const asio::ip::udp::endpoint target{asio::ip::address_v4::loopback(), m_port};
        m_sender.send_to(asio::buffer(bytes.data(), bytes.size()), target);
    }

    // Windows asio reports UDP readiness from a background select thread, so a zero-timeout poll can
    // return before the completion of a datagram that already arrived is queued; run until idle instead.
    void pump()
    {
        m_io.restart();
        while(m_io.run_one_for(settle_time) != 0)
            continue;
        REQUIRE(m_socket.consistent());
    }

private:
    static constexpr std::chrono::milliseconds settle_time{100};

    static uint16_t bound_port(asio::ip::udp::socket::native_handle_type fd)
    {
        sockaddr_in addr{};
        socklen_t len = sizeof(addr);
        ::getsockname(fd, reinterpret_cast<sockaddr *>(&addr), &len);
        return ntohs(addr.sin_port);
    }

    asio::io_context m_io;
    std::error_code m_socket_ec;
    asio::ip::udp::socket m_sender;
    ledger_type m_socket;
    uint16_t m_port;
};

}

#endif
