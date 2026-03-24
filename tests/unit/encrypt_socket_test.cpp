#include "mdnspp/encrypt/encrypted_socket.h"
#include "mdnspp/encrypt/encrypt_socket_options.h"
#include "mdnspp/encrypt/packet_header.h"
#include "mdnspp/encrypt/aead.h"

#include "mdnspp/testing/mock_policy.h"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstddef>
#include <vector>

// SOCK-01: encrypted_socket<MockSocket> must satisfy SocketLike
static_assert(mdnspp::SocketLike<mdnspp::encrypted_socket<mdnspp::testing::MockSocket>>,
    "SOCK-01: encrypted_socket<MockSocket> must satisfy SocketLike");

namespace {

mdnspp::encrypt_socket_options make_test_opts(
    std::byte fill = std::byte{0x42},
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
// SOCK-02: send encrypts plaintext and forwards to inner socket
// ---------------------------------------------------------------------------

TEST_CASE("SOCK-02: send encrypts plaintext and forwards to inner socket", "[encrypted_socket][send]")
{
    mdnspp::testing::mock_executor ex;
    auto opts = make_test_opts();
    mdnspp::encrypted_socket<mdnspp::testing::MockSocket> sock(ex, opts);

    std::vector<std::byte> plaintext{std::byte{0xDE}, std::byte{0xAD}};
    sock.send(mdnspp::endpoint{}, std::span<const std::byte>(plaintext));

    CHECK(sock.inner().sent_packets().size() == 1);
    const auto &pkt = sock.inner().sent_packets()[0].data;
    CHECK(pkt.size() == plaintext.size() + mdnspp::encrypted_overhead);
    CHECK(pkt[0] == std::byte{0x4D});
    CHECK(pkt[1] == std::byte{0x43});
}

// ---------------------------------------------------------------------------
// SOCK-02: send increments sequence counter
// ---------------------------------------------------------------------------

TEST_CASE("SOCK-02: send increments sequence counter", "[encrypted_socket][sequence]")
{
    mdnspp::testing::mock_executor ex;
    auto opts = make_test_opts();
    mdnspp::encrypted_socket<mdnspp::testing::MockSocket> sock(ex, opts);

    std::vector<std::byte> plaintext{std::byte{0xAB}};
    sock.send(mdnspp::endpoint{}, std::span<const std::byte>(plaintext));
    sock.send(mdnspp::endpoint{}, std::span<const std::byte>(plaintext));
    sock.send(mdnspp::endpoint{}, std::span<const std::byte>(plaintext));

    REQUIRE(sock.inner().sent_packets().size() == 3);

    for (std::size_t i = 0; i < 3; ++i)
    {
        const auto &pkt = sock.inner().sent_packets()[i].data;
        auto hdr = mdnspp::deserialize_header(pkt.data());
        CHECK(hdr.sequence == i + 1);
    }
}

// ---------------------------------------------------------------------------
// SOCK-03: async_receive decrypts valid packet and calls handler
// ---------------------------------------------------------------------------

TEST_CASE("SOCK-03: async_receive decrypts valid packet and calls handler", "[encrypted_socket][receive]")
{
    mdnspp::testing::mock_executor ex;
    auto send_opts = make_test_opts(std::byte{0x42}, 1);
    auto recv_opts = make_test_opts(std::byte{0x42}, 2);

    mdnspp::encrypted_socket<mdnspp::testing::MockSocket> sender(ex, send_opts);
    mdnspp::encrypted_socket<mdnspp::testing::MockSocket> receiver(ex, recv_opts);

    std::vector<std::byte> plaintext{std::byte{0x01}, std::byte{0x02}, std::byte{0x03}};
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

// ---------------------------------------------------------------------------
// SOCK-04: recv_metadata forwarded unchanged
// ---------------------------------------------------------------------------

TEST_CASE("SOCK-04: recv_metadata forwarded unchanged", "[encrypted_socket][metadata]")
{
    mdnspp::testing::mock_executor ex;
    auto send_opts = make_test_opts(std::byte{0x42}, 1);
    auto recv_opts = make_test_opts(std::byte{0x42}, 2);

    mdnspp::encrypted_socket<mdnspp::testing::MockSocket> sender(ex, send_opts);
    mdnspp::encrypted_socket<mdnspp::testing::MockSocket> receiver(ex, recv_opts);

    std::vector<std::byte> plaintext{std::byte{0xFF}};
    sender.send(mdnspp::endpoint{}, std::span<const std::byte>(plaintext));

    auto encrypted_pkt = sender.inner().sent_packets()[0].data;
    receiver.inner().enqueue(encrypted_pkt,
                             mdnspp::endpoint{"1.2.3.4", 5353},
                             std::optional<uint8_t>{uint8_t{128}});

    mdnspp::recv_metadata captured_meta;
    receiver.async_receive(
        [&](const mdnspp::recv_metadata &meta, std::span<std::byte>)
        {
            captured_meta = meta;
        });

    CHECK(captured_meta.ttl == std::optional<uint8_t>{uint8_t{128}});
    CHECK(captured_meta.sender.address == "1.2.3.4");
}

// ---------------------------------------------------------------------------
// SOCK-05: cleartext handling with magic_byte detection
// ---------------------------------------------------------------------------

TEST_CASE("SOCK-05: cleartext handling with magic_byte detection", "[encrypted_socket][cleartext]")
{
    std::vector<std::byte> cleartext_pkt{
        std::byte{0x00}, std::byte{0x01}, std::byte{0x02}, std::byte{0x03}};

    SECTION("accept_cleartext=true passes cleartext through")
    {
        mdnspp::testing::mock_executor ex;
        auto opts = make_test_opts();
        opts.encrypt.accept_cleartext = true;
        opts.encrypt.detection = mdnspp::cleartext_detection::magic_byte;

        mdnspp::encrypted_socket<mdnspp::testing::MockSocket> sock(ex, opts);
        sock.inner().enqueue(cleartext_pkt);

        bool handler_called = false;
        sock.async_receive(
            [&](const mdnspp::recv_metadata &, std::span<std::byte>)
            {
                handler_called = true;
            });

        CHECK(handler_called);
    }

    SECTION("accept_cleartext=false drops cleartext")
    {
        mdnspp::testing::mock_executor ex;
        auto opts = make_test_opts();
        opts.encrypt.accept_cleartext = false;
        opts.encrypt.detection = mdnspp::cleartext_detection::magic_byte;

        mdnspp::encrypted_socket<mdnspp::testing::MockSocket> sock(ex, opts);
        sock.inner().enqueue(cleartext_pkt);

        bool handler_called = false;
        sock.async_receive(
            [&](const mdnspp::recv_metadata &, std::span<std::byte>)
            {
                handler_called = true;
            });

        CHECK_FALSE(handler_called);
    }
}

// ---------------------------------------------------------------------------
// SOCK-05: cleartext_detection::reject_all drops all non-encrypted
// ---------------------------------------------------------------------------

TEST_CASE("SOCK-05: cleartext_detection::reject_all drops all non-encrypted",
    "[encrypted_socket][cleartext][reject_all]")
{
    mdnspp::testing::mock_executor ex;
    auto opts = make_test_opts();
    opts.encrypt.accept_cleartext = true;  // even with accept_cleartext=true, reject_all wins
    opts.encrypt.detection = mdnspp::cleartext_detection::reject_all;

    mdnspp::encrypted_socket<mdnspp::testing::MockSocket> sock(ex, opts);

    std::vector<std::byte> cleartext_pkt{
        std::byte{0x00}, std::byte{0x01}, std::byte{0x02}, std::byte{0x03}};
    sock.inner().enqueue(cleartext_pkt);

    bool handler_called = false;
    sock.async_receive(
        [&](const mdnspp::recv_metadata &, std::span<std::byte>)
        {
            handler_called = true;
        });

    CHECK_FALSE(handler_called);
}

// ---------------------------------------------------------------------------
// SOCK-06: corrupted auth tag silently dropped
// ---------------------------------------------------------------------------

TEST_CASE("SOCK-06: corrupted auth tag silently dropped", "[encrypted_socket][tamper]")
{
    mdnspp::testing::mock_executor ex;
    auto send_opts = make_test_opts(std::byte{0x42}, 1);
    auto recv_opts = make_test_opts(std::byte{0x42}, 2);

    mdnspp::encrypted_socket<mdnspp::testing::MockSocket> sender(ex, send_opts);
    mdnspp::encrypted_socket<mdnspp::testing::MockSocket> receiver(ex, recv_opts);

    std::vector<std::byte> plaintext{std::byte{0x55}, std::byte{0x66}};
    sender.send(mdnspp::endpoint{}, std::span<const std::byte>(plaintext));

    auto corrupted = sender.inner().sent_packets()[0].data;
    corrupted.back() ^= std::byte{0xFF};  // flip a bit in the auth tag
    receiver.inner().enqueue(corrupted);

    bool handler_called = false;
    receiver.async_receive(
        [&](const mdnspp::recv_metadata &, std::span<std::byte>)
        {
            handler_called = true;
        });

    CHECK_FALSE(handler_called);
}

// ---------------------------------------------------------------------------
// SOCK-06: replayed sequence number silently dropped
// ---------------------------------------------------------------------------

TEST_CASE("SOCK-06: replayed sequence silently dropped", "[encrypted_socket][replay]")
{
    mdnspp::testing::mock_executor ex;
    auto send_opts = make_test_opts(std::byte{0x42}, 1);
    auto recv_opts = make_test_opts(std::byte{0x42}, 2);

    mdnspp::encrypted_socket<mdnspp::testing::MockSocket> sender(ex, send_opts);
    mdnspp::encrypted_socket<mdnspp::testing::MockSocket> receiver(ex, recv_opts);

    std::vector<std::byte> plaintext{std::byte{0xAA}};
    sender.send(mdnspp::endpoint{}, std::span<const std::byte>(plaintext));

    auto encrypted_pkt = sender.inner().sent_packets()[0].data;

    // First receive: should call handler
    receiver.inner().enqueue(encrypted_pkt);
    bool first_called = false;
    receiver.async_receive(
        [&](const mdnspp::recv_metadata &, std::span<std::byte>)
        {
            first_called = true;
        });
    CHECK(first_called);

    // Second receive with same packet: replay — should be dropped
    receiver.inner().enqueue(encrypted_pkt);
    bool second_called = false;
    receiver.async_receive(
        [&](const mdnspp::recv_metadata &, std::span<std::byte>)
        {
            second_called = true;
        });
    CHECK_FALSE(second_called);
}
