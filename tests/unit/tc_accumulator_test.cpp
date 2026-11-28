#include "mdnspp/detail/tc_accumulator.h"

#include "mdnspp/testing/test_clock.h"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <string>
#include <vector>

using namespace mdnspp;
using namespace std::chrono_literals;
using clock_type = mdnspp::testing::test_clock;
using accumulator_type = detail::tc_accumulator<clock_type>;

namespace {

struct clock_guard
{
    clock_guard() { clock_type::reset(); }
    ~clock_guard() { clock_type::reset(); }
};

constexpr auto tc_wait = std::chrono::milliseconds{500};

endpoint src_a()
{
    return endpoint{.address = "192.168.1.1", .port = 5353};
}

endpoint src_b()
{
    return endpoint{.address = "192.168.1.2", .port = 5353};
}

endpoint src_n(uint16_t n)
{
    return endpoint{.address = "10.0.0." + std::to_string(n), .port = 5353};
}

std::vector<mdns_record_variant> one_a(std::string name = "host.local.", std::string addr = "1.2.3.4")
{
    return {record_a{
        .name = std::move(name),
        .ttl = 120,
        .rclass = dns_class::in,
        .sender_address = addr,
        .address_string = std::move(addr),
    }};
}

void check_single_drain(accumulator_type &acc, const endpoint &source, const std::string &address)
{
    auto expired = acc.take_expired(clock_type::now());
    REQUIRE(expired.size() == 1);
    CHECK(expired[0].first == source);
    CHECK(std::get<record_a>(expired[0].second.at(0)).address_string == address);
}

}

TEST_CASE("take_expired returns nothing when no sources are pending", "[tc_accumulator]")
{
    clock_guard cg;
    accumulator_type acc;

    CHECK(acc.take_expired(clock_type::now()).empty());
    CHECK_FALSE(acc.next_deadline().has_value());
}

TEST_CASE("accumulate stores records; take_expired before deadline returns nothing", "[tc_accumulator]")
{
    clock_guard cg;
    accumulator_type acc;

    acc.accumulate(src_a(), one_a(), tc_wait);

    CHECK(acc.take_expired(clock_type::now()).empty());
    CHECK_FALSE(acc.empty());
    REQUIRE(acc.next_deadline().has_value());
    CHECK(*acc.next_deadline() == clock_type::now() + tc_wait);
}

TEST_CASE("take_expired after deadline returns merged vector and erases entry", "[tc_accumulator]")
{
    clock_guard cg;
    accumulator_type acc;

    acc.accumulate(src_a(), one_a(), tc_wait);

    clock_type::advance(tc_wait);
    auto expired = acc.take_expired(clock_type::now());
    REQUIRE(expired.size() == 1);
    CHECK(expired[0].first == src_a());
    CHECK(expired[0].second.size() == 1);

    CHECK(acc.empty());
    CHECK_FALSE(acc.next_deadline().has_value());
}

TEST_CASE("continuation packets merge records without resetting the deadline", "[tc_accumulator]")
{
    clock_guard cg;
    accumulator_type acc;

    acc.accumulate(src_a(), one_a("host.local.", "1.2.3.4"), tc_wait);

    clock_type::advance(100ms);
    acc.accumulate(src_a(), one_a("host.local.", "5.6.7.8"), tc_wait);

    CHECK(acc.take_expired(clock_type::now()).empty());

    clock_type::advance(400ms);
    auto expired = acc.take_expired(clock_type::now());
    REQUIRE(expired.size() == 1);
    CHECK(expired[0].second.size() == 2);
}

TEST_CASE("multi-source interleaving: each source keeps its own deadline", "[tc_accumulator]")
{
    clock_guard cg;
    accumulator_type acc;

    acc.accumulate(src_a(), one_a("a.local.", "1.1.1.1"), tc_wait);
    clock_type::advance(300ms);
    acc.accumulate(src_b(), one_a("b.local.", "2.2.2.2"), tc_wait);
    REQUIRE(acc.next_deadline().has_value());
    CHECK(*acc.next_deadline() == clock_type::time_point{} + 500ms);

    clock_type::advance(200ms);
    check_single_drain(acc, src_a(), "1.1.1.1");
    CHECK(acc.has_pending(src_b()));
    REQUIRE(acc.next_deadline().has_value());
    CHECK(*acc.next_deadline() == clock_type::time_point{} + 800ms);

    clock_type::advance(300ms);
    check_single_drain(acc, src_b(), "2.2.2.2");
    CHECK(acc.empty());
}

TEST_CASE("take_expired drains ALL sources whose deadlines passed", "[tc_accumulator]")
{
    clock_guard cg;
    accumulator_type acc;

    acc.accumulate(src_a(), one_a("a.local.", "1.1.1.1"), tc_wait);
    clock_type::advance(50ms);
    acc.accumulate(src_b(), one_a("b.local.", "2.2.2.2"), tc_wait);

    clock_type::advance(tc_wait);
    auto expired = acc.take_expired(clock_type::now());
    REQUIRE(expired.size() == 2);
    CHECK(acc.empty());
}

TEST_CASE("entry cap drops the oldest source to admit a new one", "[tc_accumulator]")
{
    clock_guard cg;
    accumulator_type acc;

    for(uint16_t i = 0; i < accumulator_type::max_pending_sources; ++i)
    {
        acc.accumulate(src_n(i), one_a(), tc_wait);
        clock_type::advance(1ms);
    }
    REQUIRE(acc.size() == accumulator_type::max_pending_sources);
    REQUIRE(acc.has_pending(src_n(0)));

    acc.accumulate(src_n(200), one_a(), tc_wait);
    CHECK(acc.size() == accumulator_type::max_pending_sources);
    CHECK_FALSE(acc.has_pending(src_n(0)));
    CHECK(acc.has_pending(src_n(200)));
}

TEST_CASE("clear removes all entries", "[tc_accumulator]")
{
    clock_guard cg;
    accumulator_type acc;

    acc.accumulate(src_a(), one_a(), tc_wait);
    acc.accumulate(src_b(), one_a(), tc_wait);

    CHECK_FALSE(acc.empty());

    acc.clear();

    CHECK(acc.empty());
}

TEST_CASE("has_pending tracks accumulated sources", "[tc_accumulator]")
{
    clock_guard cg;
    accumulator_type acc;

    CHECK_FALSE(acc.has_pending(src_a()));

    acc.accumulate(src_a(), one_a(), tc_wait);
    CHECK(acc.has_pending(src_a()));
    CHECK_FALSE(acc.has_pending(src_b()));
}
