#ifndef HPP_GUARD_MDNSPP_SUPPORT_ARM_LEDGER_H
#define HPP_GUARD_MDNSPP_SUPPORT_ARM_LEDGER_H

#include "mdnspp/policy.h"
#include "mdnspp/endpoint.h"

#include "mdnspp/testing/mock_policy.h"

#include <span>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <concepts>
#include <system_error>

namespace mdnspp::test_support {

template <socket_like Inner>
class arm_ledger
{
public:
    template <typename... Args>
        requires std::constructible_from<Inner, Args...>
    explicit arm_ledger(Args &&...args)
        : m_inner(std::forward<Args>(args)...)
        , m_arms{0}
        , m_completions{0}
        , m_after_close{0}
        , m_closed{false}
    {
    }

    arm_ledger(const arm_ledger &) = delete;
    arm_ledger &operator=(const arm_ledger &) = delete;

    void async_receive(move_only_function<void(std::error_code, const recv_metadata &, std::span<std::byte>)> handler)
    {
        ++m_arms;
        m_inner.async_receive([this, handler = std::move(handler)](std::error_code ec, const recv_metadata &meta, std::span<std::byte> data) mutable
        {
            ++m_completions;
            if(m_closed)
                ++m_after_close;
            handler(ec, meta, data);
        });
    }

    void send(const endpoint &dest, std::span<const std::byte> data)
    {
        m_inner.send(dest, data);
    }

    void send(const endpoint &dest, std::span<const std::byte> data, std::error_code &ec)
    {
        m_inner.send(dest, data, ec);
    }

    void close()
    {
        m_closed = true;
        m_inner.close();
    }

    Inner &inner() noexcept { return m_inner; }

    uint32_t arms() const noexcept { return m_arms; }

    uint32_t completions() const noexcept { return m_completions; }

    uint32_t completions_after_close() const noexcept { return m_after_close; }

    bool closed() const noexcept { return m_closed; }

    bool consistent() const noexcept { return m_completions <= m_arms && m_after_close == 0; }

private:
    Inner m_inner;
    uint32_t m_arms;
    uint32_t m_completions;
    uint32_t m_after_close;
    bool m_closed;
};

static_assert(socket_like<arm_ledger<testing::mock_socket>>, "arm_ledger must itself be a socket_like");

}

#endif
