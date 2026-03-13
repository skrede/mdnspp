#include "mdnspp/detail/duplicate_answer_suppression.h"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <vector>

using namespace mdnspp;
using namespace mdnspp::detail;

namespace {

record_a make_a(std::string name, std::string addr, uint32_t ttl = 120,
                dns_class rclass = dns_class::in)
{
    return record_a{
        .name = std::move(name),
        .ttl = ttl,
        .rclass = rclass,
        .sender_address = addr,
        .address_string = std::move(addr),
    };
}

record_ptr make_ptr(std::string name, std::string ptr_name, uint32_t ttl = 120)
{
    return record_ptr{
        .name = std::move(name),
        .ttl = ttl,
        .rclass = dns_class::in,
        .sender_address = "1.2.3.4",
        .ptr_name = std::move(ptr_name),
    };
}

}

TEST_CASE("is_suppressed returns false on empty state", "[duplicate_suppression]")
{
    duplicate_suppression_state state;
    auto rec = mdns_record_variant{make_a("host.local.", "1.2.3.4")};
    CHECK_FALSE(state.is_suppressed(rec, 4500));
}

TEST_CASE("after observe ttl=4500, is_suppressed with our_ttl=4500 returns true (>= threshold)", "[duplicate_suppression]")
{
    duplicate_suppression_state state;
    auto rec = mdns_record_variant{make_a("host.local.", "1.2.3.4")};
    state.observe(rec, 4500);
    CHECK(state.is_suppressed(rec, 4500));
}

TEST_CASE("after observe ttl=4499, is_suppressed with our_ttl=4500 returns false (< threshold, RFC 6762 s7.4)", "[duplicate_suppression]")
{
    duplicate_suppression_state state;
    auto rec = mdns_record_variant{make_a("host.local.", "1.2.3.4")};
    state.observe(rec, 4499);
    CHECK_FALSE(state.is_suppressed(rec, 4500));
}

TEST_CASE("after observe ttl=5000, is_suppressed with our_ttl=4500 returns true", "[duplicate_suppression]")
{
    duplicate_suppression_state state;
    auto rec = mdns_record_variant{make_a("host.local.", "1.2.3.4")};
    state.observe(rec, 5000);
    CHECK(state.is_suppressed(rec, 4500));
}

TEST_CASE("different record rdata does not suppress", "[duplicate_suppression]")
{
    duplicate_suppression_state state;
    auto observed = mdns_record_variant{make_a("host.local.", "1.2.3.4")};
    auto candidate = mdns_record_variant{make_a("host.local.", "5.6.7.8")};
    state.observe(observed, 4500);
    CHECK_FALSE(state.is_suppressed(candidate, 4500));
}

TEST_CASE("different record type with same name does not suppress", "[duplicate_suppression]")
{
    duplicate_suppression_state state;
    auto observed = mdns_record_variant{make_ptr("host.local.", "service._tcp.local.")};
    auto candidate = mdns_record_variant{make_a("host.local.", "1.2.3.4")};
    state.observe(observed, 4500);
    CHECK_FALSE(state.is_suppressed(candidate, 4500));
}

TEST_CASE("reset clears all seen answers; subsequent is_suppressed returns false", "[duplicate_suppression]")
{
    duplicate_suppression_state state;
    auto rec = mdns_record_variant{make_a("host.local.", "1.2.3.4")};
    state.observe(rec, 4500);
    REQUIRE(state.is_suppressed(rec, 4500));

    state.reset();

    CHECK_FALSE(state.is_suppressed(rec, 4500));
    CHECK(state.empty());
}

TEST_CASE("multiple observed records tracked independently", "[duplicate_suppression]")
{
    duplicate_suppression_state state;
    auto rec_a = mdns_record_variant{make_a("host.local.", "1.2.3.4")};
    auto rec_b = mdns_record_variant{make_a("other.local.", "5.6.7.8")};
    auto rec_c = mdns_record_variant{make_ptr("_http._tcp.local.", "svc._http._tcp.local.")};

    state.observe(rec_a, 4500);
    state.observe(rec_b, 4499); // below threshold
    state.observe(rec_c, 5000);

    CHECK(state.is_suppressed(rec_a, 4500));
    CHECK_FALSE(state.is_suppressed(rec_b, 4500)); // 4499 < 4500
    CHECK(state.is_suppressed(rec_c, 4500));
}
