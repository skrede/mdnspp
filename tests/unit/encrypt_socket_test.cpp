#include "mdnspp/encrypt/encrypted_socket.h"
#include "mdnspp/encrypt/encrypt_socket_options.h"
#include "mdnspp/encrypt/packet_header.h"
#include "mdnspp/encrypt/aead.h"

#include "mdnspp/testing/mock_policy.h"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <type_traits>
#include <system_error>

// SOCK-01: encrypted_socket<mock_socket> must satisfy socket_like
static_assert(mdnspp::socket_like<mdnspp::encrypt::encrypted_socket<mdnspp::testing::mock_socket>>,
    "SOCK-01: encrypted_socket<mock_socket> must satisfy socket_like");

// SOCK-11: encrypted_socket is non-movable (key state is mutex-guarded and the
// receive handler captures `this`)
static_assert(!std::is_move_constructible_v<mdnspp::encrypt::encrypted_socket<mdnspp::testing::mock_socket>>,
    "SOCK-11: encrypted_socket must not be move-constructible");
static_assert(!std::is_move_assignable_v<mdnspp::encrypt::encrypted_socket<mdnspp::testing::mock_socket>>,
    "SOCK-11: encrypted_socket must not be move-assignable");

namespace {

mdnspp::encrypt::encrypt_socket_options make_test_opts(
    std::byte fill = std::byte{0x42},
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
// SOCK-02: send encrypts plaintext and forwards to inner socket
// ---------------------------------------------------------------------------

TEST_CASE("SOCK-02: send encrypts plaintext and forwards to inner socket", "[encrypted_socket][send]")
{
    mdnspp::testing::mock_executor ex;
    auto opts = make_test_opts();
    mdnspp::encrypt::encrypted_socket<mdnspp::testing::mock_socket> sock(ex, opts);

    std::vector<std::byte> plaintext{std::byte{0xDE}, std::byte{0xAD}};
    sock.send(mdnspp::endpoint{}, std::span<const std::byte>(plaintext));

    CHECK(sock.inner().sent_packets().size() == 1);
    const auto &pkt = sock.inner().sent_packets()[0].data;
    CHECK(pkt.size() == plaintext.size() + mdnspp::encrypt::encrypted_overhead);
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
    mdnspp::encrypt::encrypted_socket<mdnspp::testing::mock_socket> sock(ex, opts);

    std::vector<std::byte> plaintext{std::byte{0xAB}};
    sock.send(mdnspp::endpoint{}, std::span<const std::byte>(plaintext));
    sock.send(mdnspp::endpoint{}, std::span<const std::byte>(plaintext));
    sock.send(mdnspp::endpoint{}, std::span<const std::byte>(plaintext));

    REQUIRE(sock.inner().sent_packets().size() == 3);

    // The counter starts at a per-boot randomized base (top 24 bits random,
    // low 40 bits zero) and increments by one per packet.
    constexpr uint64_t low40_mask = (uint64_t{1} << 40) - 1;
    auto hdr0 = mdnspp::encrypt::deserialize_header(sock.inner().sent_packets()[0].data.data());
    CHECK((hdr0.sequence & low40_mask) == 1);

    for (std::size_t i = 0; i < 3; ++i)
    {
        const auto &pkt = sock.inner().sent_packets()[i].data;
        auto hdr = mdnspp::encrypt::deserialize_header(pkt.data());
        CHECK(hdr.sequence == hdr0.sequence + i);
    }
}

// ---------------------------------------------------------------------------
// SOCK-02: sequence counter start is randomized per socket
// ---------------------------------------------------------------------------

TEST_CASE("SOCK-02: sequence counter start is randomized per socket", "[encrypted_socket][sequence]")
{
    mdnspp::testing::mock_executor ex;
    auto opts_a = make_test_opts(std::byte{0x42}, 1);
    auto opts_b = make_test_opts(std::byte{0x42}, 2);

    mdnspp::encrypt::encrypted_socket<mdnspp::testing::mock_socket> sock_a(ex, opts_a);
    mdnspp::encrypt::encrypted_socket<mdnspp::testing::mock_socket> sock_b(ex, opts_b);

    std::vector<std::byte> plaintext{std::byte{0x01}};
    sock_a.send(mdnspp::endpoint{}, std::span<const std::byte>(plaintext));
    sock_b.send(mdnspp::endpoint{}, std::span<const std::byte>(plaintext));

    auto hdr_a = mdnspp::encrypt::deserialize_header(sock_a.inner().sent_packets()[0].data.data());
    auto hdr_b = mdnspp::encrypt::deserialize_header(sock_b.inner().sent_packets()[0].data.data());

    // Independent CSPRNG draws of the top 24 bits collide with probability 2^-24.
    CHECK(hdr_a.sequence != hdr_b.sequence);
}

// ---------------------------------------------------------------------------
// SOCK-12: construction-time validation (release-build enforced)
// ---------------------------------------------------------------------------

TEST_CASE("SOCK-12: constructor rejects invalid encrypt_options", "[encrypted_socket][validate]")
{
    mdnspp::testing::mock_executor ex;

    SECTION("all-zero PSK sets invalid_argument in the error_code constructor")
    {
        mdnspp::encrypt::encrypt_socket_options opts;
        opts.encrypt.sender_id = 1;

        std::error_code ec;
        mdnspp::encrypt::encrypted_socket<mdnspp::testing::mock_socket> sock(ex, opts, ec);
        CHECK(ec == std::make_error_code(std::errc::invalid_argument));
    }

    SECTION("sender_id == 0 sets invalid_argument in the error_code constructor")
    {
        auto opts = make_test_opts(std::byte{0x42}, 0);

        std::error_code ec;
        mdnspp::encrypt::encrypted_socket<mdnspp::testing::mock_socket> sock(ex, opts, ec);
        CHECK(ec == std::make_error_code(std::errc::invalid_argument));
    }

    SECTION("replay_window_size == 0 sets invalid_argument in the error_code constructor")
    {
        auto opts = make_test_opts();
        opts.encrypt.replay_window_size = 0;

        std::error_code ec;
        mdnspp::encrypt::encrypted_socket<mdnspp::testing::mock_socket> sock(ex, opts, ec);
        CHECK(ec == std::make_error_code(std::errc::invalid_argument));
    }

    SECTION("throwing constructor throws std::system_error on an all-zero PSK")
    {
        mdnspp::encrypt::encrypt_socket_options opts;
        opts.encrypt.sender_id = 1;

        CHECK_THROWS_AS(
            (mdnspp::encrypt::encrypted_socket<mdnspp::testing::mock_socket>(ex, opts)),
            std::system_error);
    }

    SECTION("throwing constructor throws std::system_error on sender_id == 0")
    {
        auto opts = make_test_opts(std::byte{0x42}, 0);

        CHECK_THROWS_AS(
            (mdnspp::encrypt::encrypted_socket<mdnspp::testing::mock_socket>(ex, opts)),
            std::system_error);
    }

    SECTION("valid options pass both constructors")
    {
        auto opts = make_test_opts();
        std::error_code ec;
        mdnspp::encrypt::encrypted_socket<mdnspp::testing::mock_socket> sock(ex, opts, ec);
        CHECK_FALSE(ec);
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

    mdnspp::encrypt::encrypted_socket<mdnspp::testing::mock_socket> sender(ex, send_opts);
    mdnspp::encrypt::encrypted_socket<mdnspp::testing::mock_socket> receiver(ex, recv_opts);

    std::vector<std::byte> plaintext{std::byte{0x01}, std::byte{0x02}, std::byte{0x03}};
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

// ---------------------------------------------------------------------------
// SOCK-04: recv_metadata forwarded unchanged
// ---------------------------------------------------------------------------

TEST_CASE("SOCK-04: recv_metadata forwarded unchanged", "[encrypted_socket][metadata]")
{
    mdnspp::testing::mock_executor ex;
    auto send_opts = make_test_opts(std::byte{0x42}, 1);
    auto recv_opts = make_test_opts(std::byte{0x42}, 2);

    mdnspp::encrypt::encrypted_socket<mdnspp::testing::mock_socket> sender(ex, send_opts);
    mdnspp::encrypt::encrypted_socket<mdnspp::testing::mock_socket> receiver(ex, recv_opts);

    std::vector<std::byte> plaintext{std::byte{0xFF}};
    sender.send(mdnspp::endpoint{}, std::span<const std::byte>(plaintext));

    auto encrypted_pkt = sender.inner().sent_packets()[0].data;
    receiver.inner().enqueue(encrypted_pkt,
                             mdnspp::endpoint{"1.2.3.4", 5353},
                             std::optional<uint8_t>{uint8_t{128}});

    mdnspp::recv_metadata captured_meta;
    receiver.async_receive(
        [&](std::error_code, const mdnspp::recv_metadata &meta, std::span<std::byte>)
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
        opts.encrypt.detection = mdnspp::encrypt::cleartext_detection::magic_byte;

        mdnspp::encrypt::encrypted_socket<mdnspp::testing::mock_socket> sock(ex, opts);
        sock.inner().enqueue(cleartext_pkt);

        bool handler_called = false;
        sock.async_receive(
            [&](std::error_code, const mdnspp::recv_metadata &, std::span<std::byte>)
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
        opts.encrypt.detection = mdnspp::encrypt::cleartext_detection::magic_byte;

        mdnspp::encrypt::encrypted_socket<mdnspp::testing::mock_socket> sock(ex, opts);
        sock.inner().enqueue(cleartext_pkt);

        bool handler_called = false;
        sock.async_receive(
            [&](std::error_code, const mdnspp::recv_metadata &, std::span<std::byte>)
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
    opts.encrypt.detection = mdnspp::encrypt::cleartext_detection::reject_all;

    mdnspp::encrypt::encrypted_socket<mdnspp::testing::mock_socket> sock(ex, opts);

    std::vector<std::byte> cleartext_pkt{
        std::byte{0x00}, std::byte{0x01}, std::byte{0x02}, std::byte{0x03}};
    sock.inner().enqueue(cleartext_pkt);

    bool handler_called = false;
    sock.async_receive(
        [&](std::error_code, const mdnspp::recv_metadata &, std::span<std::byte>)
        {
            handler_called = true;
        });

    CHECK_FALSE(handler_called);
}

// ---------------------------------------------------------------------------
// SOCK-05: attempt_decrypt delivers small cleartext packets
// ---------------------------------------------------------------------------

TEST_CASE("SOCK-05: attempt_decrypt delivers cleartext shorter than the encrypted header",
    "[encrypted_socket][cleartext][attempt_decrypt]")
{
    // A legitimate cleartext mDNS query can be ~28 bytes, below
    // encrypted_header_size (44). It must still be deliverable under
    // attempt_decrypt with accept_cleartext = true.
    std::vector<std::byte> small_cleartext(28, std::byte{0x00});
    small_cleartext[2] = std::byte{0x01};

    SECTION("accept_cleartext=true delivers the packet")
    {
        mdnspp::testing::mock_executor ex;
        auto opts = make_test_opts();
        opts.encrypt.accept_cleartext = true;
        opts.encrypt.detection = mdnspp::encrypt::cleartext_detection::attempt_decrypt;

        mdnspp::encrypt::encrypted_socket<mdnspp::testing::mock_socket> sock(ex, opts);
        sock.inner().enqueue(small_cleartext);

        bool handler_called = false;
        std::vector<std::byte> received;
        sock.async_receive(
            [&](std::error_code, const mdnspp::recv_metadata &, std::span<std::byte> data)
            {
                handler_called = true;
                received.assign(data.begin(), data.end());
            });

        CHECK(handler_called);
        CHECK(received == small_cleartext);
    }

    SECTION("accept_cleartext=false drops the packet")
    {
        mdnspp::testing::mock_executor ex;
        auto opts = make_test_opts();
        opts.encrypt.accept_cleartext = false;
        opts.encrypt.detection = mdnspp::encrypt::cleartext_detection::attempt_decrypt;

        mdnspp::encrypt::encrypted_socket<mdnspp::testing::mock_socket> sock(ex, opts);
        sock.inner().enqueue(small_cleartext);

        bool handler_called = false;
        sock.async_receive(
            [&](std::error_code, const mdnspp::recv_metadata &, std::span<std::byte>)
            {
                handler_called = true;
            });

        CHECK_FALSE(handler_called);
    }

    SECTION("reject_all drops the packet regardless of accept_cleartext")
    {
        mdnspp::testing::mock_executor ex;
        auto opts = make_test_opts();
        opts.encrypt.accept_cleartext = true;
        opts.encrypt.detection = mdnspp::encrypt::cleartext_detection::reject_all;

        mdnspp::encrypt::encrypted_socket<mdnspp::testing::mock_socket> sock(ex, opts);
        sock.inner().enqueue(small_cleartext);

        bool handler_called = false;
        sock.async_receive(
            [&](std::error_code, const mdnspp::recv_metadata &, std::span<std::byte>)
            {
                handler_called = true;
            });

        CHECK_FALSE(handler_called);
    }
}

// ---------------------------------------------------------------------------
// SOCK-06: corrupted auth tag silently dropped
// ---------------------------------------------------------------------------

TEST_CASE("SOCK-06: corrupted auth tag silently dropped", "[encrypted_socket][tamper]")
{
    mdnspp::testing::mock_executor ex;
    auto send_opts = make_test_opts(std::byte{0x42}, 1);
    auto recv_opts = make_test_opts(std::byte{0x42}, 2);

    mdnspp::encrypt::encrypted_socket<mdnspp::testing::mock_socket> sender(ex, send_opts);
    mdnspp::encrypt::encrypted_socket<mdnspp::testing::mock_socket> receiver(ex, recv_opts);

    std::vector<std::byte> plaintext{std::byte{0x55}, std::byte{0x66}};
    sender.send(mdnspp::endpoint{}, std::span<const std::byte>(plaintext));

    auto corrupted = sender.inner().sent_packets()[0].data;
    REQUIRE_FALSE(corrupted.empty());
    if (!corrupted.empty())
        corrupted.back() ^= std::byte{0xFF};  // flip a bit in the auth tag
    receiver.inner().enqueue(corrupted);

    bool handler_called = false;
    receiver.async_receive(
        [&](std::error_code, const mdnspp::recv_metadata &, std::span<std::byte>)
        {
            handler_called = true;
        });

    CHECK_FALSE(handler_called);
}

// ---------------------------------------------------------------------------
// SOCK-07: auth-only send produces flag=0 in header
// ---------------------------------------------------------------------------

TEST_CASE("Auth-only: received payload matches sent plaintext", "[encrypted_socket][auth_only]")
{
    mdnspp::testing::mock_executor ex;

    auto send_opts = make_test_opts(std::byte{0x42}, 1);
    send_opts.encrypt.auth_only = true;

    auto recv_opts = make_test_opts(std::byte{0x42}, 2);

    mdnspp::encrypt::encrypted_socket<mdnspp::testing::mock_socket> sender(ex, send_opts);
    mdnspp::encrypt::encrypted_socket<mdnspp::testing::mock_socket> receiver(ex, recv_opts);

    std::vector<std::byte> plaintext{std::byte{0xDE}, std::byte{0xAD}, std::byte{0xBE}, std::byte{0xEF}};
    sender.send(mdnspp::endpoint{}, std::span<const std::byte>(plaintext));

    REQUIRE(sender.inner().sent_packets().size() == 1);
    const auto &sent_data = sender.inner().sent_packets()[0].data;

    auto hdr = mdnspp::encrypt::deserialize_header(sent_data.data());
    CHECK(hdr.flags == 0);

    receiver.inner().enqueue(sent_data);
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

// ---------------------------------------------------------------------------
// SOCK-07: auth-only tampered payload dropped
// ---------------------------------------------------------------------------

TEST_CASE("Auth-only: tampered payload dropped", "[encrypted_socket][auth_only][tamper]")
{
    mdnspp::testing::mock_executor ex;

    auto send_opts = make_test_opts(std::byte{0x42}, 1);
    send_opts.encrypt.auth_only = true;

    auto recv_opts = make_test_opts(std::byte{0x42}, 2);

    mdnspp::encrypt::encrypted_socket<mdnspp::testing::mock_socket> sender(ex, send_opts);
    mdnspp::encrypt::encrypted_socket<mdnspp::testing::mock_socket> receiver(ex, recv_opts);

    std::vector<std::byte> plaintext{std::byte{0xCA}, std::byte{0xFE}};
    sender.send(mdnspp::endpoint{}, std::span<const std::byte>(plaintext));

    REQUIRE(sender.inner().sent_packets().size() == 1);
    auto tampered = sender.inner().sent_packets()[0].data;
    tampered[mdnspp::encrypt::encrypted_header_size] ^= std::byte{0xFF};

    receiver.inner().enqueue(tampered);
    bool handler_called = false;
    receiver.async_receive(
        [&](std::error_code, const mdnspp::recv_metadata &, std::span<std::byte>)
        {
            handler_called = true;
        });

    CHECK_FALSE(handler_called);
}

// ---------------------------------------------------------------------------
// SOCK-08: receive_mode::encrypted_only drops auth-only packets
// ---------------------------------------------------------------------------

TEST_CASE("receive_mode::encrypted_only drops auth-only packets", "[encrypted_socket][receive_mode]")
{
    mdnspp::testing::mock_executor ex;

    auto send_opts = make_test_opts(std::byte{0x42}, 1);
    send_opts.encrypt.auth_only = true;

    auto recv_opts = make_test_opts(std::byte{0x42}, 2);
    recv_opts.encrypt.recv_mode = mdnspp::encrypt::receive_mode::encrypted_only;

    mdnspp::encrypt::encrypted_socket<mdnspp::testing::mock_socket> sender(ex, send_opts);
    mdnspp::encrypt::encrypted_socket<mdnspp::testing::mock_socket> receiver(ex, recv_opts);

    std::vector<std::byte> plaintext{std::byte{0x11}};
    sender.send(mdnspp::endpoint{}, std::span<const std::byte>(plaintext));

    REQUIRE(sender.inner().sent_packets().size() == 1);
    receiver.inner().enqueue(sender.inner().sent_packets()[0].data);

    bool handler_called = false;
    receiver.async_receive(
        [&](std::error_code, const mdnspp::recv_metadata &, std::span<std::byte>)
        {
            handler_called = true;
        });

    CHECK_FALSE(handler_called);
}

// ---------------------------------------------------------------------------
// SOCK-09: receive_mode::auth_only drops encrypted packets
// ---------------------------------------------------------------------------

TEST_CASE("receive_mode::auth_only drops encrypted packets", "[encrypted_socket][receive_mode]")
{
    mdnspp::testing::mock_executor ex;

    auto send_opts = make_test_opts(std::byte{0x42}, 1);

    auto recv_opts = make_test_opts(std::byte{0x42}, 2);
    recv_opts.encrypt.recv_mode = mdnspp::encrypt::receive_mode::auth_only;

    mdnspp::encrypt::encrypted_socket<mdnspp::testing::mock_socket> sender(ex, send_opts);
    mdnspp::encrypt::encrypted_socket<mdnspp::testing::mock_socket> receiver(ex, recv_opts);

    std::vector<std::byte> plaintext{std::byte{0x22}};
    sender.send(mdnspp::endpoint{}, std::span<const std::byte>(plaintext));

    REQUIRE(sender.inner().sent_packets().size() == 1);
    receiver.inner().enqueue(sender.inner().sent_packets()[0].data);

    bool handler_called = false;
    receiver.async_receive(
        [&](std::error_code, const mdnspp::recv_metadata &, std::span<std::byte>)
        {
            handler_called = true;
        });

    CHECK_FALSE(handler_called);
}

// ---------------------------------------------------------------------------
// SOCK-10: receive_mode::accept_both accepts both encrypted and auth-only
// ---------------------------------------------------------------------------

TEST_CASE("receive_mode::accept_both accepts both encrypted and auth-only", "[encrypted_socket][receive_mode]")
{
    mdnspp::testing::mock_executor ex;

    auto enc_send_opts = make_test_opts(std::byte{0x42}, 1);

    auto ao_send_opts = make_test_opts(std::byte{0x42}, 3);
    ao_send_opts.encrypt.auth_only = true;

    auto recv_opts = make_test_opts(std::byte{0x42}, 2);
    recv_opts.encrypt.recv_mode = mdnspp::encrypt::receive_mode::accept_both;

    mdnspp::encrypt::encrypted_socket<mdnspp::testing::mock_socket> enc_sender(ex, enc_send_opts);
    mdnspp::encrypt::encrypted_socket<mdnspp::testing::mock_socket> ao_sender(ex, ao_send_opts);
    mdnspp::encrypt::encrypted_socket<mdnspp::testing::mock_socket> receiver(ex, recv_opts);

    std::vector<std::byte> plaintext{std::byte{0x33}};

    enc_sender.send(mdnspp::endpoint{}, std::span<const std::byte>(plaintext));
    ao_sender.send(mdnspp::endpoint{}, std::span<const std::byte>(plaintext));

    REQUIRE(enc_sender.inner().sent_packets().size() == 1);
    REQUIRE(ao_sender.inner().sent_packets().size() == 1);

    receiver.inner().enqueue(enc_sender.inner().sent_packets()[0].data);
    receiver.inner().enqueue(ao_sender.inner().sent_packets()[0].data);

    int handler_count = 0;
    receiver.async_receive(
        [&](std::error_code, const mdnspp::recv_metadata &, std::span<std::byte>)
        {
            ++handler_count;
        });
    receiver.async_receive(
        [&](std::error_code, const mdnspp::recv_metadata &, std::span<std::byte>)
        {
            ++handler_count;
        });

    CHECK(handler_count == 2);
}

// ---------------------------------------------------------------------------
// SOCK-06: replayed sequence number silently dropped
// ---------------------------------------------------------------------------

TEST_CASE("SOCK-06: replayed sequence silently dropped", "[encrypted_socket][replay]")
{
    mdnspp::testing::mock_executor ex;
    auto send_opts = make_test_opts(std::byte{0x42}, 1);
    auto recv_opts = make_test_opts(std::byte{0x42}, 2);

    mdnspp::encrypt::encrypted_socket<mdnspp::testing::mock_socket> sender(ex, send_opts);
    mdnspp::encrypt::encrypted_socket<mdnspp::testing::mock_socket> receiver(ex, recv_opts);

    std::vector<std::byte> plaintext{std::byte{0xAA}};
    sender.send(mdnspp::endpoint{}, std::span<const std::byte>(plaintext));

    auto encrypted_pkt = sender.inner().sent_packets()[0].data;

    // First receive: should call handler
    receiver.inner().enqueue(encrypted_pkt);
    bool first_called = false;
    receiver.async_receive(
        [&](std::error_code, const mdnspp::recv_metadata &, std::span<std::byte>)
        {
            first_called = true;
        });
    CHECK(first_called);

    // Second receive with same packet: replay — should be dropped
    receiver.inner().enqueue(encrypted_pkt);
    bool second_called = false;
    receiver.async_receive(
        [&](std::error_code, const mdnspp::recv_metadata &, std::span<std::byte>)
        {
            second_called = true;
        });
    CHECK_FALSE(second_called);
}
