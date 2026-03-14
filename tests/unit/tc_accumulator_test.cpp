#include "mdnspp/detail/tc_accumulator.h"

#include "mdnspp/testing/test_clock.h"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
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

record_a make_a(std::string name, std::string addr, uint32_t ttl = 120)
{
    return record_a{
        .name = std::move(name),
        .ttl = ttl,
        .rclass = dns_class::in,
        .sender_address = addr,
        .address_string = std::move(addr),
    };
}

std::vector<mdns_record_variant> one_a(std::string name = "host.local.", std::string addr = "1.2.3.4")
{
    return {make_a(std::move(name), std::move(addr))};
}

}

TEST_CASE("take_if_ready returns nullopt for unknown source", "[tc_accumulator]")
{
    clock_guard cg;
    accumulator_type acc;

    auto now = clock_type::now();
    auto result = acc.take_if_ready(src_a(), now, tc_wait);
    CHECK_FALSE(result.has_value());
}

TEST_CASE("accumulate stores records; take_if_ready before timeout returns nullopt", "[tc_accumulator]")
{
    clock_guard cg;
    accumulator_type acc;

    acc.accumulate(src_a(), one_a(), tc_wait);

    // Not enough time has passed
    auto now = clock_type::now();
    auto result = acc.take_if_ready(src_a(), now, tc_wait);
    CHECK_FALSE(result.has_value());
    CHECK_FALSE(acc.empty());
}

TEST_CASE("take_if_ready after timeout returns merged vector and erases entry", "[tc_accumulator]")
{
    clock_guard cg;
    accumulator_type acc;

    acc.accumulate(src_a(), one_a(), tc_wait);

    clock_type::advance(tc_wait);

    auto now = clock_type::now();
    auto result = acc.take_if_ready(src_a(), now, tc_wait);
    REQUIRE(result.has_value());
    CHECK(result->size() == 1);

    // Entry should be erased
    CHECK(acc.empty());
}

TEST_CASE("multiple accumulate calls from same source merge records, inserted_at not reset", "[tc_accumulator]")
{
    clock_guard cg;
    accumulator_type acc;

    acc.accumulate(src_a(), one_a("host.local.", "1.2.3.4"), tc_wait);

    // Advance partially, then accumulate again (simulating continuation packet)
    clock_type::advance(100ms);
    acc.accumulate(src_a(), one_a("host.local.", "5.6.7.8"), tc_wait);

    // Still before original timeout
    auto now = clock_type::now();
    auto before = acc.take_if_ready(src_a(), now, tc_wait);
    CHECK_FALSE(before.has_value());

    // Now advance to the original timeout (total elapsed = 500ms from start)
    clock_type::advance(400ms);
    now = clock_type::now();
    auto after = acc.take_if_ready(src_a(), now, tc_wait);
    REQUIRE(after.has_value());
    CHECK(after->size() == 2);
}

TEST_CASE("different sources maintain separate entries", "[tc_accumulator]")
{
    clock_guard cg;
    accumulator_type acc;

    acc.accumulate(src_a(), one_a("a.local.", "1.1.1.1"), tc_wait);
    acc.accumulate(src_b(), one_a("b.local.", "2.2.2.2"), tc_wait);

    CHECK(acc.has_pending(src_a()));
    CHECK(acc.has_pending(src_b()));

    clock_type::advance(tc_wait);
    auto now = clock_type::now();

    auto ra = acc.take_if_ready(src_a(), now, tc_wait);
    auto rb = acc.take_if_ready(src_b(), now, tc_wait);

    REQUIRE(ra.has_value());
    REQUIRE(rb.has_value());
    CHECK(ra->size() == 1);
    CHECK(rb->size() == 1);
    CHECK(std::get<record_a>(ra->at(0)).address_string == "1.1.1.1");
    CHECK(std::get<record_a>(rb->at(0)).address_string == "2.2.2.2");
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

TEST_CASE("second take_if_ready on same source after first consumed returns nullopt", "[tc_accumulator]")
{
    clock_guard cg;
    accumulator_type acc;

    acc.accumulate(src_a(), one_a(), tc_wait);
    clock_type::advance(tc_wait);

    auto now = clock_type::now();
    auto first = acc.take_if_ready(src_a(), now, tc_wait);
    REQUIRE(first.has_value());

    // Second call must return nullopt (entry was erased)
    auto second = acc.take_if_ready(src_a(), now, tc_wait);
    CHECK_FALSE(second.has_value());
}

TEST_CASE("has_pending returns false for unknown source", "[tc_accumulator]")
{
    clock_guard cg;
    accumulator_type acc;

    CHECK_FALSE(acc.has_pending(src_a()));
}

TEST_CASE("has_pending returns true after accumulate", "[tc_accumulator]")
{
    clock_guard cg;
    accumulator_type acc;

    acc.accumulate(src_a(), one_a(), tc_wait);
    CHECK(acc.has_pending(src_a()));
    CHECK_FALSE(acc.has_pending(src_b()));
}
