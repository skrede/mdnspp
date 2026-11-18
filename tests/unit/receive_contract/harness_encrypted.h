#ifndef HPP_GUARD_MDNSPP_RECEIVE_CONTRACT_HARNESS_ENCRYPTED_H
#define HPP_GUARD_MDNSPP_RECEIVE_CONTRACT_HARNESS_ENCRYPTED_H

#include "receive_contract/harness.h"

#include "support/arm_ledger.h"
#include "support/socket_ref.h"

#include "mdnspp/encrypt/secure_key.h"
#include "mdnspp/encrypt/encrypted_socket.h"
#include "mdnspp/encrypt/encrypt_socket_options.h"

#include "mdnspp/testing/mock_policy.h"

#include <span>
#include <array>
#include <cstddef>
#include <cstdint>

namespace mdnspp::test_support {

template <typename Inner>
struct encrypted_over
{
};

inline encrypt::encrypt_socket_options shared_key_options(uint32_t sender_id)
{
    std::array<std::byte, 32> key;
    key.fill(std::byte{0x42});
    encrypt::encrypt_socket_options opts;
    opts.encrypt.psk = encrypt::secure_key(key);
    opts.encrypt.sender_id = sender_id;
    return opts;
}

template <typename Inner>
struct harness<encrypted_over<Inner>>
{
    using inner_harness = harness<Inner>;
    using inner_ledger = typename inner_harness::ledger_type;
    using ledger_type = arm_ledger<encrypt::encrypted_socket<socket_ref<inner_ledger>>>;

    harness()
        : m_inner{}
        , m_sender_ex{}
        , m_sender{m_sender_ex, shared_key_options(1)}
        , m_socket{m_inner.ledger(), shared_key_options(2)}
    {
    }

    ledger_type &socket() noexcept { return m_socket; }

    ledger_type &ledger() noexcept { return m_socket; }

    void inject(std::span<const std::byte> bytes)
    {
        m_sender.send(endpoint{}, bytes);
        m_inner.inject(m_sender.inner().sent_packets().back().data);
    }

    void pump()
    {
        m_inner.pump();
        REQUIRE(m_socket.consistent());
        const inner_ledger &below = m_inner.ledger();
        if(below.closed())
            return;
        const bool outer_armed = m_socket.arms() > m_socket.completions();
        REQUIRE(below.arms() - below.completions() == (outer_armed ? 1u : 0u));
    }

private:
    inner_harness m_inner;
    testing::mock_executor m_sender_ex;
    encrypt::encrypted_socket<testing::mock_socket> m_sender;
    ledger_type m_socket;
};

}

#endif
