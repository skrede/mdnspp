#include "mdnspp/encrypt/encrypted_socket.h"
#include "mdnspp/encrypt/encrypt_socket_options.h"
#include "mdnspp/encrypt/packet_header.h"
#include "mdnspp/encrypt/secure_key.h"
#include "mdnspp/encrypt/encrypt_options.h"

#include "mdnspp/testing/mock_policy.h"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <thread>
#include <vector>

namespace {

mdnspp::encrypt::secure_key make_key(std::byte fill)
{
    std::array<std::byte, 32> k;
    k.fill(fill);
    return mdnspp::encrypt::secure_key(k);
}

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
// KEYM-01: Epoch field reflects current epoch in sent packets
// ---------------------------------------------------------------------------

TEST_CASE("KEYM-01: epoch field reflects current epoch in sent packets", "[encrypted_socket][key_rotation][KEYM-01]")
{
    using namespace std::chrono_literals;

    mdnspp::testing::mock_executor ex;
    auto opts = make_test_opts(std::byte{0x42}, 1);
    mdnspp::encrypt::encrypted_socket<mdnspp::testing::mock_socket> sender(ex, opts);

    std::vector<std::byte> plaintext{std::byte{0x01}};

    sender.send(mdnspp::endpoint{}, std::span<const std::byte>(plaintext));
    REQUIRE(sender.inner().sent_packets().size() == 1);
    auto hdr0 = mdnspp::encrypt::deserialize_header(sender.inner().sent_packets()[0].data.data());
    CHECK(hdr0.epoch == 0);

    sender.update_key(make_key(std::byte{0x43}), mdnspp::encrypt::grace_period{.duration = 10s});
    sender.send(mdnspp::endpoint{}, std::span<const std::byte>(plaintext));
    REQUIRE(sender.inner().sent_packets().size() == 2);
    auto hdr1 = mdnspp::encrypt::deserialize_header(sender.inner().sent_packets()[1].data.data());
    CHECK(hdr1.epoch == 1);

    sender.update_key(make_key(std::byte{0x44}), mdnspp::encrypt::grace_period{.duration = 10s});
    sender.send(mdnspp::endpoint{}, std::span<const std::byte>(plaintext));
    REQUIRE(sender.inner().sent_packets().size() == 3);
    auto hdr2 = mdnspp::encrypt::deserialize_header(sender.inner().sent_packets()[2].data.data());
    CHECK(hdr2.epoch == 2);
}

// ---------------------------------------------------------------------------
// KEYM-02: Previous epoch packets accepted during grace window
// ---------------------------------------------------------------------------

TEST_CASE("KEYM-02: previous epoch packets accepted during grace window", "[encrypted_socket][key_rotation][KEYM-02]")
{
    using namespace std::chrono_literals;

    mdnspp::testing::mock_executor ex;
    auto send_opts = make_test_opts(std::byte{0x42}, 1);
    auto recv_opts = make_test_opts(std::byte{0x42}, 2);

    mdnspp::encrypt::encrypted_socket<mdnspp::testing::mock_socket> sender(ex, send_opts);
    mdnspp::encrypt::encrypted_socket<mdnspp::testing::mock_socket> receiver(ex, recv_opts);

    std::vector<std::byte> plaintext{std::byte{0xAB}, std::byte{0xCD}};
    sender.send(mdnspp::endpoint{}, std::span<const std::byte>(plaintext));

    REQUIRE(sender.inner().sent_packets().size() == 1);
    auto epoch0_pkt = sender.inner().sent_packets()[0].data;

    receiver.update_key(make_key(std::byte{0x43}), mdnspp::encrypt::grace_period{.duration = 10s});

    receiver.inner().enqueue(epoch0_pkt);
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
// KEYM-02: Unknown epoch packets rejected immediately (D-07)
// ---------------------------------------------------------------------------

TEST_CASE("KEYM-02: unknown epoch packets rejected immediately", "[encrypted_socket][key_rotation][KEYM-02]")
{
    using namespace std::chrono_literals;

    mdnspp::testing::mock_executor ex;
    auto send_opts = make_test_opts(std::byte{0x42}, 1);
    auto recv_opts = make_test_opts(std::byte{0x42}, 2);

    mdnspp::encrypt::encrypted_socket<mdnspp::testing::mock_socket> sender(ex, send_opts);
    mdnspp::encrypt::encrypted_socket<mdnspp::testing::mock_socket> receiver(ex, recv_opts);

    std::vector<std::byte> plaintext{std::byte{0x77}};
    sender.send(mdnspp::endpoint{}, std::span<const std::byte>(plaintext));

    REQUIRE(sender.inner().sent_packets().size() == 1);
    auto epoch0_pkt = sender.inner().sent_packets()[0].data;

    receiver.update_key(make_key(std::byte{0x43}), mdnspp::encrypt::grace_period{.duration = 10s});
    receiver.update_key(make_key(std::byte{0x44}), mdnspp::encrypt::grace_period{.duration = 10s});

    receiver.inner().enqueue(epoch0_pkt);
    bool handler_called = false;
    receiver.async_receive(
        [&](std::error_code, const mdnspp::recv_metadata &, std::span<std::byte>)
        {
            handler_called = true;
        });

    CHECK_FALSE(handler_called);
}

// ---------------------------------------------------------------------------
// KEYM-03: Time-based grace expiry
// ---------------------------------------------------------------------------

TEST_CASE("KEYM-03: time-based grace expiry drops previous epoch packets", "[encrypted_socket][key_rotation][KEYM-03]")
{
    using namespace std::chrono_literals;

    mdnspp::testing::mock_executor ex;
    auto send_opts = make_test_opts(std::byte{0x42}, 1);
    auto recv_opts = make_test_opts(std::byte{0x42}, 2);

    mdnspp::encrypt::encrypted_socket<mdnspp::testing::mock_socket> sender(ex, send_opts);
    mdnspp::encrypt::encrypted_socket<mdnspp::testing::mock_socket> receiver(ex, recv_opts);

    std::vector<std::byte> plaintext{std::byte{0x55}};
    sender.send(mdnspp::endpoint{}, std::span<const std::byte>(plaintext));

    REQUIRE(sender.inner().sent_packets().size() == 1);
    auto epoch0_pkt = sender.inner().sent_packets()[0].data;

    receiver.update_key(make_key(std::byte{0x43}), mdnspp::encrypt::grace_period{.duration = 1ms});
    std::this_thread::sleep_for(5ms);

    receiver.inner().enqueue(epoch0_pkt);
    bool handler_called = false;
    receiver.async_receive(
        [&](std::error_code, const mdnspp::recv_metadata &, std::span<std::byte>)
        {
            handler_called = true;
        });

    CHECK_FALSE(handler_called);
}

// ---------------------------------------------------------------------------
// KEYM-03: Count-based grace expiry
// ---------------------------------------------------------------------------

TEST_CASE("KEYM-03: count-based grace expiry drops previous epoch packets after limit", "[encrypted_socket][key_rotation][KEYM-03]")
{
    using namespace std::chrono_literals;

    mdnspp::testing::mock_executor ex;
    auto send_opts = make_test_opts(std::byte{0x42}, 1);
    auto recv_opts = make_test_opts(std::byte{0x42}, 2);

    mdnspp::encrypt::encrypted_socket<mdnspp::testing::mock_socket> sender(ex, send_opts);
    mdnspp::encrypt::encrypted_socket<mdnspp::testing::mock_socket> receiver(ex, recv_opts);

    std::vector<std::byte> p1{std::byte{0x01}};
    std::vector<std::byte> p2{std::byte{0x02}};
    std::vector<std::byte> p3{std::byte{0x03}};
    sender.send(mdnspp::endpoint{}, std::span<const std::byte>(p1));
    sender.send(mdnspp::endpoint{}, std::span<const std::byte>(p2));
    sender.send(mdnspp::endpoint{}, std::span<const std::byte>(p3));

    REQUIRE(sender.inner().sent_packets().size() == 3);
    auto pkt1 = sender.inner().sent_packets()[0].data;
    auto pkt2 = sender.inner().sent_packets()[1].data;
    auto pkt3 = sender.inner().sent_packets()[2].data;

    receiver.update_key(make_key(std::byte{0x43}), mdnspp::encrypt::grace_period{.packet_count = 2});

    receiver.inner().enqueue(pkt1);
    bool called1 = false;
    receiver.async_receive(
        [&](std::error_code, const mdnspp::recv_metadata &, std::span<std::byte>)
        {
            called1 = true;
        });
    CHECK(called1);

    receiver.inner().enqueue(pkt2);
    bool called2 = false;
    receiver.async_receive(
        [&](std::error_code, const mdnspp::recv_metadata &, std::span<std::byte>)
        {
            called2 = true;
        });
    CHECK(called2);

    receiver.inner().enqueue(pkt3);
    bool called3 = false;
    receiver.async_receive(
        [&](std::error_code, const mdnspp::recv_metadata &, std::span<std::byte>)
        {
            called3 = true;
        });
    CHECK_FALSE(called3);
}

// ---------------------------------------------------------------------------
// KEYM-04: update_key() bumps epoch and uses new key for encryption
// ---------------------------------------------------------------------------

TEST_CASE("KEYM-04: update_key bumps epoch and encrypts with new key", "[encrypted_socket][key_rotation][KEYM-04]")
{
    using namespace std::chrono_literals;

    mdnspp::testing::mock_executor ex;

    auto sender_opts = make_test_opts(std::byte{0x42}, 1);
    mdnspp::encrypt::encrypted_socket<mdnspp::testing::mock_socket> sender(ex, sender_opts);

    auto recv1_opts = make_test_opts(std::byte{0x42}, 2);
    mdnspp::encrypt::encrypted_socket<mdnspp::testing::mock_socket> receiver1(ex, recv1_opts);

    std::vector<std::byte> plaintext{std::byte{0xBE}, std::byte{0xEF}};

    sender.send(mdnspp::endpoint{}, std::span<const std::byte>(plaintext));
    REQUIRE(sender.inner().sent_packets().size() == 1);

    auto pkt_epoch0 = sender.inner().sent_packets()[0].data;
    auto hdr_epoch0 = mdnspp::encrypt::deserialize_header(pkt_epoch0.data());
    CHECK(hdr_epoch0.epoch == 0);

    receiver1.inner().enqueue(pkt_epoch0);
    bool recv1_called = false;
    receiver1.async_receive(
        [&](std::error_code, const mdnspp::recv_metadata &, std::span<std::byte>)
        {
            recv1_called = true;
        });
    CHECK(recv1_called);

    // Both sender and receiver2 rotate to the new key at epoch 1.
    // receiver2 starts with same initial key (0x42, epoch 0), then rotates to 0x43.
    sender.update_key(make_key(std::byte{0x43}), mdnspp::encrypt::grace_period{.duration = 10s});

    auto recv2_opts = make_test_opts(std::byte{0x42}, 3);
    mdnspp::encrypt::encrypted_socket<mdnspp::testing::mock_socket> receiver2(ex, recv2_opts);
    receiver2.update_key(make_key(std::byte{0x43}), mdnspp::encrypt::grace_period{.duration = 10s});

    sender.send(mdnspp::endpoint{}, std::span<const std::byte>(plaintext));
    REQUIRE(sender.inner().sent_packets().size() == 2);

    auto pkt_epoch1 = sender.inner().sent_packets()[1].data;
    auto hdr_epoch1 = mdnspp::encrypt::deserialize_header(pkt_epoch1.data());
    CHECK(hdr_epoch1.epoch == 1);

    receiver2.inner().enqueue(pkt_epoch1);
    bool recv2_called = false;
    std::vector<std::byte> recv2_data;
    receiver2.async_receive(
        [&](std::error_code, const mdnspp::recv_metadata &, std::span<std::byte> data)
        {
            recv2_called = true;
            recv2_data.assign(data.begin(), data.end());
        });
    CHECK(recv2_called);
    CHECK(recv2_data == plaintext);
}
