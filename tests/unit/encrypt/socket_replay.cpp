#include "helpers.h"

#include <catch2/catch_test_macros.hpp>

#include <catch2/generators/catch_generators.hpp>

#include <cstddef>
#include <algorithm>

namespace {

struct restart_rig
{
    mdnspp::testing::mock_executor ex;
    test_socket old_boot;
    test_socket restarted;
    test_socket receiver;
    payloads got;

    restart_rig()
        : old_boot(ex, make_test_opts(std::byte{0x42}, 1))
        , restarted(ex, make_test_opts(std::byte{0x42}, 1))
        , receiver(ex, make_test_opts(std::byte{0x42}, 2))
    {
        arm_collecting(receiver, got);
    }
};

plain_bytes payload_of(uint8_t tag)
{
    return plain_bytes{std::byte{tag}, std::byte{0x7E}};
}

plain_bytes version_one_packet(std::size_t size)
{
    plain_bytes packet(size, std::byte{0xAB});
    const plain_bytes lead{std::byte{0x4D}, std::byte{0x43}, std::byte{0x01}, std::byte{0x01}};
    std::copy_n(lead.begin(), std::min(size, lead.size()), packet.begin());
    return packet;
}

}

TEST_CASE("replaying a packet of an earlier boot alternating with the current session delivers each packet once",
          "[encrypted_socket][replay][session]")
{
    restart_rig rig;
    const auto p = sealed_by(rig.old_boot, payload_of(0x10));
    const auto q1 = sealed_by(rig.restarted, payload_of(0x21));
    const auto q2 = sealed_by(rig.restarted, payload_of(0x22));
    const auto q3 = sealed_by(rig.restarted, payload_of(0x23));

    for(const auto &packet : {p, q1, q2, q3, p})
        inject(rig.receiver, packet);
    for(int i = 0; i < 50; ++i)
    {
        inject(rig.receiver, q1);
        inject(rig.receiver, p);
    }
    inject(rig.receiver, q2);
    inject(rig.receiver, q3);

    CHECK(rig.got == payloads{payload_of(0x10), payload_of(0x21), payload_of(0x22), payload_of(0x23)});
}

TEST_CASE("a restarted sender with the same sender id is accepted from its first packet",
          "[encrypted_socket][replay][session]")
{
    restart_rig rig;
    inject(rig.receiver, sealed_by(rig.old_boot, payload_of(0x10)));
    inject(rig.receiver, sealed_by(rig.old_boot, payload_of(0x11)));

    inject(rig.receiver, sealed_by(rig.restarted, payload_of(0x21)));

    CHECK(rig.got == payloads{payload_of(0x10), payload_of(0x11), payload_of(0x21)});
}

TEST_CASE("a version 1 packet is dropped without stalling reception in every detection configuration",
          "[encrypted_socket][replay][version]")
{
    const auto detection = GENERATE(mdnspp::encrypt::cleartext_detection::magic_byte,
                                    mdnspp::encrypt::cleartext_detection::attempt_decrypt);
    const bool accept_cleartext = GENERATE(false, true);
    const auto size = GENERATE(std::size_t{44}, std::size_t{51}, std::size_t{52}, std::size_t{62}, std::size_t{67});

    const auto got = deliveries_after(receiver_options(detection, accept_cleartext), version_one_packet(size));

    CHECK(got == payloads{follow_up});
}
