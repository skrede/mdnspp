#include "helpers.h"

#include <catch2/generators/catch_generators.hpp>
#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators_range.hpp>

#include <vector>
#include <cstddef>
#include <cstdint>
#include <algorithm>

namespace {

using mdnspp::encrypt::cleartext_detection;
using mdnspp::encrypt::encrypted_header_size;
using mdnspp::encrypt::encrypted_overhead;
using mdnspp::encrypt::receive_mode;

std::vector<std::size_t> cleartext_lengths()
{
    return {0, 12, 28, encrypted_header_size - 1, encrypted_header_size, encrypted_header_size + 1,
            encrypted_overhead - 1, encrypted_overhead, encrypted_overhead + 1, 120, 1400};
}

plain_bytes non_magic_packet(std::size_t size, std::byte third)
{
    plain_bytes packet(size, std::byte{0x11});
    const plain_bytes lead{std::byte{0x12}, std::byte{0x34}, third};
    std::copy_n(lead.begin(), std::min(size, lead.size()), packet.begin());
    return packet;
}

mdnspp::encrypt::encrypt_socket_options encrypted_only_receiver()
{
    auto opts = receiver_options(cleartext_detection::attempt_decrypt, true);
    opts.encrypt.recv_mode = receive_mode::encrypted_only;
    return opts;
}

}

TEST_CASE("attempt_decrypt delivers non-magic cleartext of every size", "[encrypted_socket][receive_cleartext]")
{
    const auto size = GENERATE_COPY(from_range(cleartext_lengths()));
    const auto third = GENERATE(std::byte{0x00}, std::byte{0xFF});
    const auto packet = non_magic_packet(size, third);

    const auto got = deliveries_after(receiver_options(cleartext_detection::attempt_decrypt, true), packet);

    REQUIRE(got == payloads{packet, follow_up});
}

TEST_CASE("magic_byte delivers non-magic cleartext of every size", "[encrypted_socket][receive_cleartext]")
{
    const auto size = GENERATE_COPY(from_range(cleartext_lengths()));
    const auto packet = non_magic_packet(size, std::byte{0x00});

    const auto got = deliveries_after(receiver_options(cleartext_detection::magic_byte, true), packet);

    REQUIRE(got == payloads{packet, follow_up});
}

TEST_CASE("cleartext of every size is dropped unless accept_cleartext is set and detection allows it",
          "[encrypted_socket][receive_cleartext]")
{
    const auto size = GENERATE_COPY(from_range(cleartext_lengths()));
    const auto packet = non_magic_packet(size, std::byte{0x00});
    const auto detection = GENERATE(cleartext_detection::magic_byte, cleartext_detection::attempt_decrypt);

    CHECK(deliveries_after(receiver_options(detection, false), packet) == payloads{follow_up});
    CHECK(deliveries_after(receiver_options(cleartext_detection::reject_all, true), packet) == payloads{follow_up});
}

TEST_CASE("an authenticated packet of the wrong mode is dropped, never delivered as cleartext",
          "[encrypted_socket][receive_cleartext]")
{
    paired_sockets pair(make_test_opts(std::byte{0x42}, 1), encrypted_only_receiver());
    auto auth_opts = make_test_opts(std::byte{0x42}, 3);
    auth_opts.encrypt.auth_only = true;
    test_socket auth_sender(pair.ex, auth_opts);
    payloads got;

    arm_collecting(pair.receiver, got);
    inject(pair.receiver, sealed_by(auth_sender, probe));
    inject(pair.receiver, sealed(pair, follow_up));

    REQUIRE(got == payloads{follow_up});
}

TEST_CASE("a replayed authenticated packet is dropped, never delivered as cleartext",
          "[encrypted_socket][receive_cleartext]")
{
    paired_sockets pair(make_test_opts(std::byte{0x42}, 1), receiver_options(cleartext_detection::attempt_decrypt, true));
    const auto original = sealed(pair, probe);
    payloads got;

    arm_collecting(pair.receiver, got);
    inject(pair.receiver, original);
    inject(pair.receiver, original);
    inject(pair.receiver, sealed(pair, follow_up));

    REQUIRE(got == payloads{probe, follow_up});
}

TEST_CASE("interleaved cleartext and encrypted packets arrive in order", "[encrypted_socket][receive_cleartext]")
{
    paired_sockets pair(make_test_opts(std::byte{0x42}, 1), receiver_options(cleartext_detection::attempt_decrypt, true));
    const auto large = non_magic_packet(1400, std::byte{0x00});
    const auto small = non_magic_packet(28, std::byte{0xFF});
    payloads got;

    arm_collecting(pair.receiver, got);
    inject(pair.receiver, large);
    inject(pair.receiver, sealed(pair, probe));
    inject(pair.receiver, small);
    inject(pair.receiver, sealed(pair, follow_up));

    REQUIRE(got == payloads{large, probe, small, follow_up});
}
