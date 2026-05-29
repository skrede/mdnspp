#include "mdnspp/encrypt/encrypted_policy.h"
#include "mdnspp/encrypt/encrypt_socket_options.h"

#include "mdnspp/testing/mock_policy.h"
#include "mdnspp/default/default_policy.h"
#include "mdnspp/inproc/inproc_policy.h"

#ifdef MDNSPP_HAS_ASIO
#include "mdnspp/asio/asio_policy.h"
#endif

#include <catch2/catch_test_macros.hpp>

#include <type_traits>

// ---------------------------------------------------------------------------
// PLCY-01: encrypted_policy satisfies Policy concept
// ---------------------------------------------------------------------------

static_assert(mdnspp::Policy<mdnspp::encrypted_policy<mdnspp::testing::MockPolicy>>,
    "PLCY-01: encrypted_policy<MockPolicy> must satisfy Policy");

// PLCY-01/02: composition with DefaultPolicy
static_assert(mdnspp::Policy<mdnspp::encrypted_policy<mdnspp::DefaultPolicy>>,
    "PLCY-01/02: encrypted_policy<DefaultPolicy> must satisfy Policy");

// PLCY-02: composition with InProcPolicy
static_assert(mdnspp::Policy<mdnspp::encrypted_policy<mdnspp::InProcPolicy>>,
    "PLCY-02: encrypted_policy<InProcPolicy> must satisfy Policy");

// PLCY-02/D-10: composition with AsioPolicy (conditional on asio availability)
#ifdef MDNSPP_HAS_ASIO
static_assert(mdnspp::Policy<mdnspp::encrypted_policy<mdnspp::AsioPolicy>>,
    "D-10: encrypted_policy<AsioPolicy> must satisfy Policy");
#endif

// ---------------------------------------------------------------------------
// PLCY-03: type pass-through static_asserts
// ---------------------------------------------------------------------------

// PLCY-03: timer_type passes through to inner
static_assert(std::is_same_v<
    mdnspp::encrypted_policy<mdnspp::testing::MockPolicy>::timer_type,
    mdnspp::testing::MockTimer>,
    "PLCY-03: timer_type must be Inner::timer_type");

// PLCY-03: executor_type passes through to inner
static_assert(std::is_same_v<
    mdnspp::encrypted_policy<mdnspp::testing::MockPolicy>::executor_type,
    mdnspp::testing::mock_executor &>,
    "PLCY-03: executor_type must be Inner::executor_type");

// D-09: socket_options_type resolves to encrypt_socket_options
static_assert(std::is_same_v<
    mdnspp::policy_socket_options_t<mdnspp::encrypted_policy<mdnspp::testing::MockPolicy>>,
    mdnspp::encrypt_socket_options>,
    "D-09: policy_socket_options_t must resolve to encrypt_socket_options");

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

namespace {

mdnspp::encrypt_socket_options make_test_opts(std::byte fill = std::byte{0x42},
                                               uint32_t sender_id = 1)
{
    mdnspp::encrypt_socket_options opts;
    std::array<std::byte, 32> key_bytes;
    key_bytes.fill(fill);
    opts.encrypt.psk = mdnspp::secure_key(key_bytes);
    opts.encrypt.sender_id = sender_id;
    opts.encrypt.accept_cleartext = false;
    opts.encrypt.detection = mdnspp::cleartext_detection::magic_byte;
    return opts;
}

} // namespace

// ---------------------------------------------------------------------------
// PLCY-03: post delegates to inner policy
// ---------------------------------------------------------------------------

TEST_CASE("PLCY-03: post delegates to inner policy", "[encrypted_policy][post]")
{
    mdnspp::testing::mock_executor ex;

    bool flag = false;
    mdnspp::encrypted_policy<mdnspp::testing::MockPolicy>::post(ex,
        [&flag]{ flag = true; });

    CHECK(ex.m_posted.size() == 1);
    ex.drain_posted();
    CHECK(flag);
}

// ---------------------------------------------------------------------------
// PLCY-02: encrypted_policy<MockPolicy> socket round-trip
// ---------------------------------------------------------------------------

TEST_CASE("PLCY-02: encrypted_policy<MockPolicy> socket round-trip", "[encrypted_policy][integration]")
{
    using P = mdnspp::encrypted_policy<mdnspp::testing::MockPolicy>;

    mdnspp::testing::mock_executor ex;
    auto send_opts = make_test_opts(std::byte{0x42}, 1);
    auto recv_opts = make_test_opts(std::byte{0x42}, 2);

    P::socket_type sender(ex, send_opts);
    P::socket_type receiver(ex, recv_opts);

    std::vector<std::byte> plaintext{std::byte{0x11}, std::byte{0x22}, std::byte{0x33}};
    sender.send(mdnspp::endpoint{}, std::span<const std::byte>(plaintext));

    REQUIRE(sender.inner().sent_packets().size() == 1);
    auto encrypted_pkt = sender.inner().sent_packets()[0].data;
    receiver.inner().enqueue(encrypted_pkt);

    bool handler_called = false;
    std::vector<std::byte> received;
    receiver.async_receive(
        [&](const mdnspp::recv_metadata &, std::span<std::byte> data)
        {
            handler_called = true;
            received.assign(data.begin(), data.end());
        });

    CHECK(handler_called);
    CHECK(received == plaintext);
}
