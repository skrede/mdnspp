#include "interfaces.h"
#include "qu_packets.h"

#include "mdnspp/policy.h"
#include "mdnspp/endpoint.h"

#include "mdnspp/detail/qu_history.h"
#include "mdnspp/detail/packet_gate.h"
#include "mdnspp/detail/ip_address_ops.h"

#include "mdnspp/testing/test_clock.h"
#include "mdnspp/testing/mock_policy.h"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <initializer_list>

using mdnspp::testing::test_clock;
using namespace std::chrono_literals;

namespace {

using history = mdnspp::detail::qu_history<test_clock>;

constexpr uint16_t a_type = 1;
constexpr uint16_t chaos_class = 3;

history recorded(std::initializer_list<wire_entry> questions)
{
    test_clock::reset();
    history h{2s};
    h.record_sent(question_packet(questions));
    return h;
}

bool answered(const history &h, std::string_view name, uint16_t type, uint16_t rclass)
{
    return h.answers(answer_packet({{name, type, rclass, "target.local."}}));
}

mdnspp::recv_metadata from(const char *source, std::optional<const char *> destination)
{
    mdnspp::recv_metadata meta;
    meta.sender = mdnspp::endpoint{source, 5353};
    meta.ttl = uint8_t{255};
    meta.recv_ifindex = 2;
    if(destination)
        meta.destination = mdnspp::detail::parse_ip_address(*destination);
    return meta;
}

}

TEST_CASE("qu_history does not record a QM question", "[gate][qu-history]")
{
    const history h = recorded({{"host.local.", ptr_type, in_class, {}}});
    CHECK_FALSE(answered(h, "host.local.", ptr_type, in_class));
}

TEST_CASE("qu_history matches type and class unless the question asked ANY", "[gate][qu-history]")
{
    const history typed = recorded({{"host.local.", ptr_type, qu_in_class, {}}});
    CHECK(answered(typed, "host.local.", ptr_type, in_class));
    CHECK(answered(typed, "host.local.", ptr_type, 0x8001));
    CHECK_FALSE(answered(typed, "host.local.", a_type, in_class));
    CHECK_FALSE(answered(typed, "host.local.", ptr_type, chaos_class));
    CHECK_FALSE(answered(typed, "other.local.", ptr_type, in_class));

    const history any_type = recorded({{"host.local.", any_value, qu_in_class, {}}});
    CHECK(answered(any_type, "host.local.", a_type, in_class));
    CHECK_FALSE(answered(any_type, "host.local.", a_type, chaos_class));

    const history any_class = recorded({{"host.local.", ptr_type, 0x8000 | any_value, {}}});
    CHECK(answered(any_class, "host.local.", ptr_type, chaos_class));
    CHECK_FALSE(answered(any_class, "host.local.", a_type, in_class));
}

TEST_CASE("qu_history ignores a matching record in the additional section", "[gate][qu-history]")
{
    const history h = recorded({{"host.local.", ptr_type, qu_in_class, {}}});
    CHECK_FALSE(h.answers(answer_packet({{"other.local.", ptr_type, in_class, "target.local."}},
                                        {{"host.local.", ptr_type, in_class, "target.local."}})));
}

TEST_CASE("qu_history forgets a question once the window has passed", "[gate][qu-history]")
{
    const history h = recorded({{"host.local.", ptr_type, qu_in_class, {}}});
    test_clock::advance(2s);
    CHECK(answered(h, "host.local.", ptr_type, in_class));
    test_clock::advance(1ms);
    CHECK_FALSE(answered(h, "host.local.", ptr_type, in_class));
}

TEST_CASE("qu_history keeps the 64 most recent questions", "[gate][qu-history]")
{
    test_clock::reset();
    history h{2s};
    std::vector<std::string> names;
    for(uint32_t i = 0; i < 65; ++i)
        names.push_back("host" + std::to_string(i) + ".local.");
    for(const std::string &name : names)
        h.record_sent(question_packet({{name, ptr_type, qu_in_class, {}}}));

    CHECK_FALSE(answered(h, names.front(), ptr_type, in_class));
    CHECK(answered(h, names[1], ptr_type, in_class));
    CHECK(answered(h, names.back(), ptr_type, in_class));
}

TEST_CASE("a response of unknown destination skips the QU rule but not the on-link rule", "[gate][qu-history]")
{
    interface_snapshot snapshot{{nic_with(2, {network_of("192.0.2.1", 24)})}};
    mdnspp::detail::packet_gate<mdnspp::testing::mock_policy> gate{5353, {}, 0, enumerate_from(snapshot)};
    const std::vector<std::byte> unasked = answer_packet({{"host.local.", ptr_type, in_class, "target.local."}});

    CHECK(gate.admit(from("192.0.2.7", std::nullopt), unasked));
    CHECK_FALSE(gate.admit(from("203.0.113.9", std::nullopt), unasked));
    CHECK_FALSE(gate.admit(from("192.0.2.7", "192.0.2.1"), unasked));
}
