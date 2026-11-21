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
using mdnspp::encrypt::encrypt_socket_options;

struct config
{
    cleartext_detection detection;
    bool accept_cleartext;
};

constexpr std::size_t smallest_header = 44;

plain_bytes magic_packet(std::size_t size, std::byte version)
{
    plain_bytes packet(size, std::byte{0x11});
    const plain_bytes lead{std::byte{0x4D}, std::byte{0x43}, version};
    std::copy_n(lead.begin(), std::min(size, lead.size()), packet.begin());
    return packet;
}

plain_bytes dns_shaped_packet(std::size_t size)
{
    plain_bytes packet(size, std::byte{0x00});
    packet[0] = std::byte{0x4D};
    packet[1] = std::byte{0x43};
    packet[2] = std::byte{0x01};
    return packet;
}

encrypt_socket_options options_of(const config &cfg)
{
    return receiver_options(cfg.detection, cfg.accept_cleartext);
}

std::vector<config> all_configs()
{
    return {{cleartext_detection::magic_byte, false}, {cleartext_detection::magic_byte, true},
            {cleartext_detection::attempt_decrypt, false}, {cleartext_detection::attempt_decrypt, true},
            {cleartext_detection::reject_all, false}, {cleartext_detection::reject_all, true}};
}

}

TEST_CASE("a magic-prefixed packet below the smallest header is cleartext in attempt_decrypt",
          "[encrypted_socket][receive_magic]")
{
    const auto size = GENERATE(std::size_t{2}, std::size_t{12}, std::size_t{28}, smallest_header - 1);
    const auto packet = magic_packet(size, std::byte{0x01});
    const config cfg{cleartext_detection::attempt_decrypt, true};

    REQUIRE(deliveries_after(options_of(cfg), packet) == payloads{packet, follow_up});
}

TEST_CASE("a short magic-prefixed packet is never cleartext outside attempt_decrypt with accept_cleartext",
          "[encrypted_socket][receive_magic]")
{
    const auto size = GENERATE(std::size_t{12}, smallest_header - 1, smallest_header);
    const auto cfg = GENERATE(config{cleartext_detection::magic_byte, true},
                              config{cleartext_detection::attempt_decrypt, false},
                              config{cleartext_detection::reject_all, true});

    REQUIRE(deliveries_after(options_of(cfg), magic_packet(size, std::byte{0x01})) == payloads{follow_up});
}

TEST_CASE("a magic-prefixed packet of the smallest header size or more is never cleartext",
          "[encrypted_socket][receive_magic]")
{
    const auto size = GENERATE(smallest_header, smallest_header + 1, std::size_t{59}, std::size_t{60},
                               std::size_t{120}, std::size_t{1400});
    const auto version = GENERATE(std::byte{0x00}, std::byte{0x01}, std::byte{0xFF});
    const auto cfg = GENERATE_COPY(from_range(all_configs()));

    REQUIRE(deliveries_after(options_of(cfg), magic_packet(size, version)) == payloads{follow_up});
}

TEST_CASE("a sealed packet with a foreign version or a forged tag is dropped in every configuration",
          "[encrypted_socket][receive_magic]")
{
    const auto cfg = GENERATE_COPY(from_range(all_configs()));
    paired_sockets pair(make_test_opts(std::byte{0x42}, 1), options_of(cfg));
    auto foreign = sealed(pair, probe);
    foreign[2] = GENERATE(std::byte{0x00}, std::byte{0x01}, std::byte{0xFF});
    auto forged = sealed(pair, probe);
    forged.back() ^= std::byte{0x01};
    payloads got;

    arm_collecting(pair.receiver, got);
    inject(pair.receiver, foreign);
    inject(pair.receiver, forged);
    inject(pair.receiver, sealed(pair, follow_up));

    REQUIRE(got == payloads{follow_up});
}

TEST_CASE("a cleartext with transaction id 4D43 is delivered below the smallest header and dropped from it",
          "[encrypted_socket][receive_magic]")
{
    const config cfg{cleartext_detection::attempt_decrypt, true};
    const auto below = dns_shaped_packet(smallest_header - 1);
    const auto at = dns_shaped_packet(smallest_header);

    CHECK(deliveries_after(options_of(cfg), below) == payloads{below, follow_up});
    CHECK(deliveries_after(options_of(cfg), at) == payloads{follow_up});
}
