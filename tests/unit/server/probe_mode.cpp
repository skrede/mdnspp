#include "fixture.h"

#include "mdnspp/detail/sibling_records.h"
#include "mdnspp/detail/server_question_section.h"

#include <catch2/catch_test_macros.hpp>

#include <span>
#include <memory>
#include <vector>
#include <cstddef>
#include <cstdint>

namespace {

std::vector<uint16_t> probe_qclasses(const sent_packet &probe)
{
    std::vector<uint16_t> qclasses;
    std::size_t offset = 12;
    const std::span<const std::byte> data{probe.data};
    for(uint32_t i = 0; i < 2; ++i)
    {
        const auto question = read_question(data, offset);
        REQUIRE(question.has_value());
        qclasses.push_back(question->qclass);
    }
    return qclasses;
}

}

TEST_CASE("a server built with a sibling registry probes without the unicast-response bit", "[service_server][probing]")
{
    mock_executor ex;
    auto siblings = std::make_shared<detail::sibling_records>();
    basic_service_server<mock_policy> server{ex, make_test_info(), {}, {}, {}, siblings, 0};
    server.async_start();
    server.timer().fire();

    REQUIRE(server.socket().sent_packets().size() == 1);
    CHECK(probe_qclasses(server.socket().sent_packets()[0]) == std::vector<uint16_t>{0x0001, 0x0001});
}

TEST_CASE("a standalone server probes with the unicast-response bit", "[service_server][probing]")
{
    server_fixture f;
    f.start();
    f.fire();

    REQUIRE(f.sent().size() == 1);
    CHECK(probe_qclasses(f.sent()[0]) == std::vector<uint16_t>{0x8001, 0x8001});
}
