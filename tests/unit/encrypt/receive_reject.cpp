#include "helpers.h"

#include <catch2/catch_test_macros.hpp>

#include <catch2/generators/catch_generators.hpp>

#include <span>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <system_error>

namespace {

using mdnspp::encrypt::cleartext_detection;
using mdnspp::encrypt::encrypt_socket_options;
using mdnspp::encrypt::receive_mode;

encrypt_socket_options receiver_opts(receive_mode mode, cleartext_detection detection)
{
    auto opts = make_test_opts(std::byte{0x42}, 2);
    opts.encrypt.recv_mode = mode;
    opts.encrypt.detection = detection;
    return opts;
}

plain_bytes forged_tag(paired_sockets &pair)
{
    auto packet = sealed(pair, probe);
    packet.back() ^= std::byte{0x01};
    return packet;
}

plain_bytes bad_magic(paired_sockets &pair)
{
    auto packet = sealed(pair, probe);
    packet[0] = std::byte{0x00};
    return packet;
}

plain_bytes unsupported_version(paired_sockets &pair)
{
    auto packet = sealed(pair, probe);
    packet[2] = std::byte{0x01};
    return packet;
}

plain_bytes short_magic_packet(paired_sockets &)
{
    return {std::byte{0x4D}, std::byte{0x43}, std::byte{0x01}};
}

plain_bytes auth_only_packet(paired_sockets &pair)
{
    auto opts = make_test_opts(std::byte{0x42}, 3);
    opts.encrypt.auth_only = true;
    test_socket auth_sender(pair.ex, opts);
    return sealed_by(auth_sender, probe);
}

plain_bytes unknown_epoch_packet(paired_sockets &pair)
{
    auto opts = make_test_opts(std::byte{0x42}, 3);
    opts.encrypt.initial_epoch = 5;
    test_socket skewed_sender(pair.ex, opts);
    return sealed_by(skewed_sender, probe);
}

plain_bytes cleartext_noise(paired_sockets &)
{
    return plain_bytes(64, std::byte{0x11});
}

struct reject_row
{
    receive_mode mode;
    cleartext_detection detection;
    plain_bytes (*rejected)(paired_sockets &);
};

}

TEST_CASE("a rejected packet never stalls the next valid packet", "[encrypted_socket][receive_reject]")
{
    constexpr auto magic = cleartext_detection::magic_byte;
    constexpr auto reject_all = cleartext_detection::reject_all;
    const auto row = GENERATE(
        reject_row{receive_mode::accept_both, magic, &forged_tag},
        reject_row{receive_mode::accept_both, magic, &bad_magic},
        reject_row{receive_mode::accept_both, magic, &unsupported_version},
        reject_row{receive_mode::accept_both, magic, &short_magic_packet},
        reject_row{receive_mode::encrypted_only, magic, &auth_only_packet},
        reject_row{receive_mode::accept_both, magic, &unknown_epoch_packet},
        reject_row{receive_mode::accept_both, reject_all, &cleartext_noise});

    paired_sockets pair(make_test_opts(std::byte{0x42}, 1), receiver_opts(row.mode, row.detection));
    payloads got;
    arm_collecting(pair.receiver, got);
    inject(pair.receiver, row.rejected(pair));
    inject(pair.receiver, sealed(pair, follow_up));

    REQUIRE(got == payloads{follow_up});
}

TEST_CASE("a replayed packet never stalls the next valid packet", "[encrypted_socket][receive_reject]")
{
    paired_sockets pair;
    payloads got;
    const auto original = sealed(pair, probe);

    arm_collecting(pair.receiver, got);
    inject(pair.receiver, original);
    inject(pair.receiver, original);
    inject(pair.receiver, sealed(pair, follow_up));

    REQUIRE(got == payloads{probe, follow_up});
}

TEST_CASE("a forged packet between two valid ones does not stall reception", "[encrypted_socket][receive_reject]")
{
    paired_sockets pair;
    payloads got;

    arm_collecting(pair.receiver, got);
    inject(pair.receiver, sealed(pair, probe));
    inject(pair.receiver, forged_tag(pair));
    inject(pair.receiver, sealed(pair, follow_up));

    REQUIRE(got == payloads{probe, follow_up});
}

TEST_CASE("a queued flood of forged packets is consumed iteratively", "[encrypted_socket][receive_reject]")
{
    constexpr std::size_t flood = 100000;
    paired_sockets pair;
    payloads got;
    const auto forged = forged_tag(pair);

    for(std::size_t i = 0; i < flood; ++i)
        pair.receiver.inner().enqueue(forged);
    pair.receiver.inner().enqueue(sealed(pair, follow_up));
    arm_collecting(pair.receiver, got);

    REQUIRE(got == payloads{follow_up});
}
