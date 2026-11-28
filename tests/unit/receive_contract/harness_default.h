#ifndef HPP_GUARD_MDNSPP_RECEIVE_CONTRACT_HARNESS_DEFAULT_H
#define HPP_GUARD_MDNSPP_RECEIVE_CONTRACT_HARNESS_DEFAULT_H

#include "receive_contract/harness.h"

#include "support/skip_or_fail.h"

#include "mdnspp/socket_options.h"

#include "mdnspp/detail/native_socket.h"

#include "mdnspp/default/default_timer.h"
#include "mdnspp/default/default_socket.h"
#include "mdnspp/default/default_context.h"

#include <span>
#include <cstdint>
#include <system_error>

namespace mdnspp::test_support {

inline uint16_t bound_port(detail::native_socket_t fd)
{
    sockaddr_in addr{};
    socklen_t len = sizeof(addr);
    ::getsockname(fd, reinterpret_cast<sockaddr *>(&addr), &len);
    return ntohs(addr.sin_port);
}

inline socket_options ephemeral_group_options()
{
    return socket_options{.multicast_group = endpoint{"224.0.0.251", 0}};
}

template <>
struct harness<default_socket>
{
    using ledger_type = arm_ledger<default_socket>;

    harness()
        : m_ctx{}
        , m_socket_ec{}
        , m_peer_ec{}
        , m_socket{m_ctx, ephemeral_group_options(), m_socket_ec}
        , m_peer{m_ctx, ephemeral_group_options(), m_peer_ec}
        , m_port{m_socket_ec ? uint16_t{0} : bound_port(m_socket.inner().native_handle())}
    {
        if(const std::error_code ec = m_socket_ec ? m_socket_ec : m_peer_ec)
            skip_or_fail("default_socket construction failed: " + ec.message());
    }

    ledger_type &socket() noexcept { return m_socket; }

    ledger_type &ledger() noexcept { return m_socket; }

    void inject(std::span<const std::byte> bytes)
    {
        m_peer.send(endpoint{"127.0.0.1", m_port}, bytes);
    }

    void pump()
    {
        for(uint32_t i = 0; i < pump_polls; ++i)
            m_ctx.poll_one();
        REQUIRE(m_socket.consistent());
    }

private:
    static constexpr uint32_t pump_polls = 8;

    default_context m_ctx;
    std::error_code m_socket_ec;
    std::error_code m_peer_ec;
    ledger_type m_socket;
    default_socket m_peer;
    uint16_t m_port;
};

}

#endif
