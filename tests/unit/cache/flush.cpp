#include "helpers.h"

TEST_CASE("cache-flush sets flush_deadline on other-origin entries", "[record_cache][cache_flush]")
{
    clock_guard cg;
    record_cache<clock_type> cache;

    cache.insert(make_a_record("myhost.local.", "192.168.1.50", 120), origin_a());

    // Past the one-second exemption window of RFC 6762 section 10.2
    clock_type::advance(2s);
    cache.insert(make_a_record("myhost.local.", "192.168.1.60", 120, dns_class::in, true), origin_b());

    auto results = cache.find("myhost.local.", dns_type::a);
    CHECK(results.size() == 2);

    clock_type::advance(1s);
    auto expired = cache.erase_expired();

    CHECK(expired.size() == 1);
    CHECK(std::get<record_a>(expired[0].record).address_string == "192.168.1.50");

    results = cache.find("myhost.local.", dns_type::a);
    REQUIRE(results.size() == 1);
    CHECK(std::get<record_a>(results[0].record).address_string == "192.168.1.60");
}

TEST_CASE("cache-flush does not affect same-origin entries", "[record_cache][cache_flush]")
{
    clock_guard cg;
    record_cache<clock_type> cache;

    cache.insert(make_a_record("myhost.local.", "192.168.1.50", 120), origin_a());
    cache.insert(make_a_record("myhost.local.", "192.168.1.51", 120), origin_a());

    // Aged past the exemption window, so only the same-origin rule protects them
    clock_type::advance(2s);
    cache.insert(make_a_record("myhost.local.", "192.168.1.52", 120, dns_class::in, true), origin_a());

    clock_type::advance(1s);
    auto expired = cache.erase_expired();

    CHECK(expired.empty());
    CHECK(cache.find("myhost.local.", dns_type::a).size() == 3);
}

TEST_CASE("flushed entry survives during grace period", "[record_cache][cache_flush]")
{
    clock_guard cg;
    record_cache<clock_type> cache;

    cache.insert(make_a_record("myhost.local.", "192.168.1.50", 120), origin_a());

    clock_type::advance(2s);
    cache.insert(make_a_record("myhost.local.", "192.168.1.60", 120, dns_class::in, true), origin_b());

    clock_type::advance(500ms);
    auto results = cache.find("myhost.local.", dns_type::a);
    CHECK(results.size() == 2);

    auto expired = cache.erase_expired();
    CHECK(expired.empty());
}

TEST_CASE("on_cache_flush callback fires with correct data", "[record_cache][cache_flush]")
{
    clock_guard cg;
    cache_entry authoritative_entry;
    std::vector<cache_entry> flushed_entries;

    record_cache<clock_type> cache(cache_options{
        .on_cache_flush = [&](const cache_entry &auth, std::vector<cache_entry> flushed) {
            authoritative_entry = auth;
            flushed_entries = std::move(flushed);
        },
    });

    cache.insert(make_a_record("myhost.local.", "192.168.1.50", 120), origin_a());

    clock_type::advance(2s);
    cache.insert(make_a_record("myhost.local.", "192.168.1.60", 120, dns_class::in, true), origin_b());

    CHECK(std::get<record_a>(authoritative_entry.record).address_string == "192.168.1.60");
    CHECK(authoritative_entry.cache_flush);
    REQUIRE(flushed_entries.size() == 1);
    CHECK(std::get<record_a>(flushed_entries[0].record).address_string == "192.168.1.50");
}

TEST_CASE("on_cache_flush not fired when no other-origin entries exist", "[record_cache][cache_flush]")
{
    clock_guard cg;
    bool called = false;
    record_cache<clock_type> cache(flag_cache_flush(called));

    cache.insert(make_a_record("myhost.local.", "192.168.1.60", 120, dns_class::in, true), origin_a());

    CHECK_FALSE(called);
}

TEST_CASE("new record from different origin during grace period stored normally", "[record_cache][cache_flush]")
{
    clock_guard cg;
    record_cache<clock_type> cache;

    cache.insert(make_a_record("myhost.local.", "192.168.1.50", 120), origin_a());
    clock_type::advance(2s);

    cache.insert(make_a_record("myhost.local.", "192.168.1.60", 120, dns_class::in, true), origin_b());

    clock_type::advance(500ms);
    cache.insert(make_a_record("myhost.local.", "192.168.1.70", 120), origin_c());

    CHECK(cache.find("myhost.local.", dns_type::a).size() == 3);

    clock_type::advance(500ms);
    auto expired = cache.erase_expired();

    CHECK(expired.size() == 1);
    CHECK(std::get<record_a>(expired[0].record).address_string == "192.168.1.50");
    CHECK(cache.find("myhost.local.", dns_type::a).size() == 2);
}

TEST_CASE("goodbye with cache_flush flushes other-origin and self-expires", "[record_cache][cache_flush]")
{
    clock_guard cg;
    record_cache<clock_type> cache;

    cache.insert(make_a_record("myhost.local.", "192.168.1.50", 300), origin_a());
    clock_type::advance(2s);

    cache.insert(make_a_record("myhost.local.", "192.168.1.60", 0, dns_class::in, true), origin_b());

    CHECK(cache.find("myhost.local.", dns_type::a).size() == 2);

    // Origin B's goodbye expires with its effective one-second TTL
    clock_type::advance(1s);
    auto expired = cache.erase_expired();

    CHECK(expired.size() == 2);
    CHECK(cache.find("myhost.local.", dns_type::a).empty());
}

TEST_CASE("multiple cache-flush from different origins in succession", "[record_cache][cache_flush]")
{
    clock_guard cg;
    record_cache<clock_type> cache;

    cache.insert(make_a_record("myhost.local.", "192.168.1.50", 120), origin_a());
    clock_type::advance(2s);

    cache.insert(make_a_record("myhost.local.", "192.168.1.60", 120, dns_class::in, true), origin_b());

    // Origin B is now past the exemption window too, so it receives a flush deadline as well
    clock_type::advance(1500ms);
    cache.insert(make_a_record("myhost.local.", "192.168.1.70", 120, dns_class::in, true), origin_c());

    clock_type::advance(1s);
    auto expired = cache.erase_expired();

    CHECK(expired.size() == 2);
    REQUIRE(cache.find("myhost.local.", dns_type::a).size() == 1);
    CHECK(std::get<record_a>(cache.find("myhost.local.", dns_type::a)[0].record).address_string == "192.168.1.70");
}
