#ifndef HPP_GUARD_MDNSPP_ENCRYPT_HELPERS_H
#define HPP_GUARD_MDNSPP_ENCRYPT_HELPERS_H

#include "mdnspp/encrypt/secure_key.h"
#include "mdnspp/encrypt/packet_header.h"
#include "mdnspp/encrypt/encrypt_options.h"
#include "mdnspp/encrypt/encrypted_socket.h"
#include "mdnspp/encrypt/encrypt_socket_options.h"

#include "mdnspp/testing/mock_policy.h"

#include <array>
#include <chrono>
#include <memory>
#include <span>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <optional>
#include <system_error>

using test_socket = mdnspp::encrypt::encrypted_socket<mdnspp::testing::mock_socket>;
using plain_bytes = std::vector<std::byte>;

struct received_packet
{
    bool called;
    plain_bytes data;
    mdnspp::recv_metadata meta;
};

inline mdnspp::encrypt::secure_key make_key(std::byte fill)
{
    std::array<std::byte, 32> key_bytes;
    key_bytes.fill(fill);
    return mdnspp::encrypt::secure_key(key_bytes);
}

inline mdnspp::encrypt::encrypt_socket_options make_test_opts(std::byte fill = std::byte{0x42}, uint32_t sender_id = 1)
{
    mdnspp::encrypt::encrypt_socket_options opts;
    opts.encrypt.psk = make_key(fill);
    opts.encrypt.sender_id = sender_id;
    opts.encrypt.accept_cleartext = false;
    opts.encrypt.detection = mdnspp::encrypt::cleartext_detection::magic_byte;
    return opts;
}

inline mdnspp::encrypt::grace_period ten_second_grace()
{
    using namespace std::chrono_literals;
    return mdnspp::encrypt::grace_period{.duration = 10s, .packet_count = std::nullopt};
}

inline void rotate_key(test_socket &sock, std::byte fill, mdnspp::encrypt::grace_period grace = ten_second_grace())
{
    sock.update_key(make_key(fill), grace);
}

inline void send_bytes(test_socket &sock, const plain_bytes &data)
{
    sock.send(mdnspp::endpoint{}, std::span<const std::byte>(data));
}

inline std::size_t sent_count(test_socket &sock)
{
    return sock.inner().sent_packets().size();
}

inline plain_bytes sent_packet_at(test_socket &sock, std::size_t index)
{
    return sock.inner().sent_packets()[index].data;
}

inline mdnspp::encrypt::encrypted_packet_header header_of(const plain_bytes &packet)
{
    return mdnspp::encrypt::deserialize_header(packet.data());
}

inline received_packet receive_one(test_socket &sock)
{
    auto state = std::make_shared<received_packet>(received_packet{false, {}, {}});
    sock.async_receive(
        [state](std::error_code, const mdnspp::recv_metadata &meta, std::span<std::byte> data)
        {
            state->called = true;
            state->meta = meta;
            state->data.assign(data.begin(), data.end());
        });
    return *state;
}

inline received_packet receive_packet(test_socket &sock, plain_bytes packet)
{
    sock.inner().enqueue(std::move(packet));
    return receive_one(sock);
}

struct paired_sockets
{
    mdnspp::testing::mock_executor ex;
    test_socket sender;
    test_socket receiver;

    paired_sockets()
        : paired_sockets(make_test_opts(std::byte{0x42}, 1), make_test_opts(std::byte{0x42}, 2))
    {
    }

    paired_sockets(const mdnspp::encrypt::encrypt_socket_options &send_opts,
                   const mdnspp::encrypt::encrypt_socket_options &recv_opts)
        : sender(ex, send_opts)
        , receiver(ex, recv_opts)
    {
    }
};

#endif
