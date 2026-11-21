#include "helpers.h"

#include <system_error>

static void check_configured_grace_expiry(record_cache<clock_type> &cache)
{
    SECTION("goodbye record survives within configured grace period")
    {
        clock_type::advance(4s);
        auto expired = cache.erase_expired();
        CHECK(expired.empty());
        CHECK(cache.find("myhost.local.", dns_type::a).size() == 1);
    }

    SECTION("goodbye record expires after configured grace period")
    {
        clock_type::advance(5s);
        auto expired = cache.erase_expired();
        CHECK(expired.size() == 1);
        CHECK(cache.find("myhost.local.", dns_type::a).empty());
    }
}

TEST_CASE("cache_flush field propagated to cache_entry", "[record_cache]")
{
    clock_guard cg;
    record_cache<clock_type> cache;
    cache.insert(make_a_record("myhost.local.", "192.168.1.50", 120, dns_class::in, true), test_origin());

    auto results = cache.find("myhost.local.", dns_type::a);
    REQUIRE(results.size() == 1);
    CHECK(results[0].cache_flush);
}

TEST_CASE("mixed expired and unexpired entries", "[record_cache]")
{
    clock_guard cg;
    record_cache<clock_type> cache;
    cache.insert(make_a_record("short.local.", "10.0.0.1", 30), test_origin());
    cache.insert(make_a_record("long.local.", "10.0.0.2", 300), test_origin());

    clock_type::advance(60s);
    auto expired = cache.erase_expired();

    CHECK(expired.size() == 1);
    CHECK(std::get<record_a>(expired[0].record).name == "short.local.");
    CHECK(cache.find("long.local.", dns_type::a).size() == 1);
    CHECK(cache.find("short.local.", dns_type::a).empty());
}

TEST_CASE("default-constructed cache works without options", "[record_cache]")
{
    clock_guard cg;
    record_cache<clock_type> cache;
    cache.insert(make_a_record("myhost.local.", "192.168.1.50", 1), test_origin());

    clock_type::advance(2s);
    auto expired = cache.erase_expired();

    CHECK(expired.size() == 1);
}

TEST_CASE("goodbye_grace configurable", "[record_cache]")
{
    clock_guard cg;
    record_cache<clock_type> cache(cache_options{.goodbye_grace = std::chrono::seconds(5)});
    cache.insert(make_a_record("myhost.local.", "192.168.1.50", 0), test_origin());

    auto results = cache.find("myhost.local.", dns_type::a);
    REQUIRE(results.size() == 1);

    SECTION("goodbye record stored with configured grace period as effective TTL")
    {
        CHECK(results[0].wire_ttl == 5);
        CHECK(results[0].ttl_remaining > 0ns);
    }

    check_configured_grace_expiry(cache);
}

TEST_CASE("record_cache rejects a non-positive goodbye_grace", "[record_cache][validate]")
{
    SECTION("throwing constructor")
    {
        REQUIRE_THROWS_AS(record_cache<clock_type>(cache_options{.goodbye_grace = std::chrono::seconds(0)}),
                          std::system_error);
    }

    SECTION("non-throwing constructor sets ec and clamps")
    {
        std::error_code ec;
        record_cache<clock_type> cache{cache_options{.goodbye_grace = std::chrono::seconds(-1)}, ec};
        CHECK(ec == std::errc::invalid_argument);

        // Clamped to one second: a goodbye record is retained, then expires
        cache.insert(make_a_record("myhost.local.", "192.168.1.50", 0), test_origin());
        CHECK(cache.find("myhost.local.", dns_type::a).size() == 1);
        clock_type::advance(1s);
        CHECK(cache.erase_expired().size() == 1);
    }
}
