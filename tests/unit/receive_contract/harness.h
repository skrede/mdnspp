#ifndef HPP_GUARD_MDNSPP_RECEIVE_CONTRACT_HARNESS_H
#define HPP_GUARD_MDNSPP_RECEIVE_CONTRACT_HARNESS_H

#include "support/arm_ledger.h"

#include "mdnspp/policy.h"
#include "mdnspp/endpoint.h"

#include "mdnspp/testing/mock_policy.h"

#include "mdnspp/inproc/inproc_bus.h"
#include "mdnspp/inproc/inproc_timer.h"
#include "mdnspp/inproc/inproc_socket.h"
#include "mdnspp/inproc/inproc_executor.h"

#include <catch2/catch_test_macros.hpp>

#include <span>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <system_error>

namespace mdnspp::test_support {

struct received
{
    std::error_code ec;
    std::vector<std::byte> bytes;
    endpoint sender;
};

using received_list = std::vector<received>;

enum class after_receive : uint8_t
{
    none,
    rearm,
    close_then_rearm
};

template <typename Socket>
void arm_recording(Socket &sock, received_list &out, after_receive next)
{
    sock.async_receive([&sock, &out, next](std::error_code ec, const recv_metadata &meta, std::span<std::byte> data)
    {
        out.push_back(received{ec, {data.begin(), data.end()}, meta.sender});
        if(next == after_receive::close_then_rearm)
            sock.close();
        if(next != after_receive::none)
            arm_recording(sock, out, next);
    });
}

inline std::vector<std::byte> payload(uint8_t seed, std::size_t size = 4)
{
    std::vector<std::byte> bytes(size);
    for(std::size_t i = 0; i < size; ++i)
        bytes[i] = static_cast<std::byte>(seed + i);
    return bytes;
}

template <typename Harness>
void deliver(Harness &h, std::span<const std::byte> bytes)
{
    h.inject(bytes);
    h.pump();
}

template <typename Socket>
struct harness;

template <>
struct harness<testing::mock_socket>
{
    using ledger_type = arm_ledger<testing::mock_socket>;

    harness()
        : m_ex{}
        , m_socket{m_ex}
    {
    }

    ledger_type &socket() noexcept { return m_socket; }

    ledger_type &ledger() noexcept { return m_socket; }

    void inject(std::span<const std::byte> bytes)
    {
        m_socket.inner().inject_receive(endpoint{"192.0.2.1", 5353}, {bytes.begin(), bytes.end()});
    }

    void pump()
    {
        REQUIRE(m_socket.consistent());
    }

private:
    testing::mock_executor m_ex;
    ledger_type m_socket;
};

template <typename Clock>
struct harness<inproc::inproc_socket<Clock>>
{
    using ledger_type = arm_ledger<inproc::inproc_socket<Clock>>;

    harness()
        : m_bus{}
        , m_ex{m_bus}
        , m_socket{m_ex}
        , m_peer{m_ex}
    {
    }

    ledger_type &socket() noexcept { return m_socket; }

    ledger_type &ledger() noexcept { return m_socket; }

    void inject(std::span<const std::byte> bytes)
    {
        m_peer.send(m_socket.inner().assigned_endpoint(), bytes);
    }

    void pump()
    {
        m_ex.drain();
        REQUIRE(m_socket.consistent());
    }

private:
    inproc::inproc_bus<Clock> m_bus;
    inproc::inproc_executor<Clock> m_ex;
    ledger_type m_socket;
    inproc::inproc_socket<Clock> m_peer;
};

}

#endif
