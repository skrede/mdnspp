#include "helpers.h"

#include "mdnspp/service_options.h"

#include "mdnspp/detail/dns_response.h"
#include "mdnspp/detail/server_known_answer.h"
#include "mdnspp/detail/server_response_aggregation.h"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstdint>

namespace {

constexpr uint32_t rfc2181_max_ttl = 2147483647u;

std::chrono::seconds above_uint32(int64_t extra)
{
    return std::chrono::seconds{(int64_t{1} << 32) + extra};
}

}

TEST_CASE("make_response_ttls clamps a TTL above 32 bits before the legacy unicast cap", "[server_wire_ttl]")
{
    service_options opts;
    opts.ptr_ttl = above_uint32(5);

    CHECK(make_response_ttls(opts, UINT32_MAX).ptr == rfc2181_max_ttl);
    CHECK(make_response_ttls(opts, 10).ptr == 10);
}

TEST_CASE("make_response_ttls sends a TTL with the top bit set as 2^31 - 1", "[server_wire_ttl]")
{
    service_options opts;
    opts.srv_ttl = std::chrono::seconds{int64_t{rfc2181_max_ttl} + 2};

    CHECK(make_response_ttls(opts, UINT32_MAX).srv == rfc2181_max_ttl);
}

TEST_CASE("answer_sections clamps a TTL above 32 bits before its cap", "[server_wire_ttl]")
{
    response_header_options uncapped;
    response_header_options capped;
    capped.ttl_cap = 10;

    CHECK(answer_sections(uncapped).ttl_for(above_uint32(5)) == rfc2181_max_ttl);
    CHECK(answer_sections(capped).ttl_for(above_uint32(5)) == 10);
}

TEST_CASE("make_ka_thresholds derives a threshold from the clamped TTL", "[server_wire_ttl]")
{
    service_options opts;
    opts.ptr_ttl = above_uint32(5);

    auto th = make_ka_thresholds(opts, 0.5);
    CHECK(th.ptr == static_cast<uint32_t>(static_cast<double>(rfc2181_max_ttl) * 0.5));
}
