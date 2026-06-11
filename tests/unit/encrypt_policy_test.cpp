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
// PLCY-01: encrypted_policy satisfies policy_like concept
// ---------------------------------------------------------------------------

static_assert(mdnspp::policy_like<mdnspp::encrypt::encrypted_policy<mdnspp::testing::mock_policy>>,
    "PLCY-01: encrypted_policy<mock_policy> must satisfy policy_like");

// PLCY-01/02: composition with default_policy
static_assert(mdnspp::policy_like<mdnspp::encrypt::encrypted_policy<mdnspp::default_policy>>,
    "PLCY-01/02: encrypted_policy<default_policy> must satisfy policy_like");

// PLCY-02: composition with inproc_policy
static_assert(mdnspp::policy_like<mdnspp::encrypt::encrypted_policy<mdnspp::inproc_policy>>,
    "PLCY-02: encrypted_policy<inproc_policy> must satisfy policy_like");

// PLCY-02/D-10: composition with asio_policy (conditional on asio availability)
#ifdef MDNSPP_HAS_ASIO
static_assert(mdnspp::policy_like<mdnspp::encrypt::encrypted_policy<mdnspp::asio_policy>>,
    "D-10: encrypted_policy<asio_policy> must satisfy policy_like");
#endif

// ---------------------------------------------------------------------------
// PLCY-03: type pass-through static_asserts
// ---------------------------------------------------------------------------

// PLCY-03: timer_type passes through to inner
static_assert(std::is_same_v<
    mdnspp::encrypt::encrypted_policy<mdnspp::testing::mock_policy>::timer_type,
    mdnspp::testing::mock_timer>,
    "PLCY-03: timer_type must be Inner::timer_type");

// PLCY-03: executor_type passes through to inner
static_assert(std::is_same_v<
    mdnspp::encrypt::encrypted_policy<mdnspp::testing::mock_policy>::executor_type,
    mdnspp::testing::mock_executor &>,
    "PLCY-03: executor_type must be Inner::executor_type");

// D-09: socket_options_type resolves to encrypt_socket_options
static_assert(std::is_same_v<
    mdnspp::policy_socket_options_t<mdnspp::encrypt::encrypted_policy<mdnspp::testing::mock_policy>>,
    mdnspp::encrypt::encrypt_socket_options>,
    "D-09: policy_socket_options_t must resolve to encrypt_socket_options");

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

namespace {

mdnspp::encrypt::encrypt_socket_options make_test_opts(std::byte fill = std::byte{0x42},
                                               uint32_t sender_id = 1)
{
    mdnspp::encrypt::encrypt_socket_options opts;
    std::array<std::byte, 32> key_bytes;
    key_bytes.fill(fill);
    opts.encrypt.psk = mdnspp::encrypt::secure_key(key_bytes);
    opts.encrypt.sender_id = sender_id;
    opts.encrypt.accept_cleartext = false;
    opts.encrypt.detection = mdnspp::encrypt::cleartext_detection::magic_byte;
    return opts;
}

}

// ---------------------------------------------------------------------------
// PLCY-03: post delegates to inner policy
// ---------------------------------------------------------------------------

TEST_CASE("PLCY-03: post delegates to inner policy", "[encrypted_policy][post]")
{
    mdnspp::testing::mock_executor ex;

    bool flag = false;
    mdnspp::encrypt::encrypted_policy<mdnspp::testing::mock_policy>::post(ex,
        [&flag]{ flag = true; });

    CHECK(ex.m_posted.size() == 1);
    ex.drain_posted();
    CHECK(flag);
}

// ---------------------------------------------------------------------------
// PLCY-02: encrypted_policy<mock_policy> socket round-trip
// ---------------------------------------------------------------------------

TEST_CASE("PLCY-02: encrypted_policy<mock_policy> socket round-trip", "[encrypted_policy][integration]")
{
    using P = mdnspp::encrypt::encrypted_policy<mdnspp::testing::mock_policy>;

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
        [&](std::error_code, const mdnspp::recv_metadata &, std::span<std::byte> data)
        {
            handler_called = true;
            received.assign(data.begin(), data.end());
        });

    CHECK(handler_called);
    CHECK(received == plaintext);
}
