#include "helpers.h"

TEST_CASE("apply_cache_flush uses configured goodbye_grace", "[record_cache][cache_flush]")
{
    clock_guard cg;
    record_cache<clock_type> cache(cache_options{.goodbye_grace = std::chrono::seconds(3)});

    cache.insert(make_a_record("myhost.local.", "192.168.1.50", 120), origin_a());
    clock_type::advance(2s);

    cache.insert(make_a_record("myhost.local.", "192.168.1.60", 120, dns_class::in, true), origin_b());

    clock_type::advance(2s);
    auto expired = cache.erase_expired();
    CHECK(expired.empty());

    clock_type::advance(1s);
    expired = cache.erase_expired();
    CHECK(expired.size() == 1);
    CHECK(std::get<record_a>(expired[0].record).address_string == "192.168.1.50");
}

TEST_CASE("cache-flush does not affect entries with different name or type", "[record_cache][cache_flush]")
{
    clock_guard cg;
    record_cache<clock_type> cache;

    cache.insert(make_a_record("myhost.local.", "192.168.1.50", 120), origin_a());
    cache.insert(make_ptr_record("myhost.local.", "service._tcp.local."), origin_a());
    cache.insert(make_a_record("other.local.", "10.0.0.1", 120), origin_a());

    clock_type::advance(2s);
    cache.insert(make_a_record("myhost.local.", "192.168.1.60", 120, dns_class::in, true), origin_b());

    clock_type::advance(1s);
    auto expired = cache.erase_expired();

    CHECK(expired.size() == 1);
    CHECK(std::get<record_a>(expired[0].record).address_string == "192.168.1.50");
    CHECK(cache.find("myhost.local.", dns_type::ptr).size() == 1);
    CHECK(cache.find("other.local.", dns_type::a).size() == 1);
}

TEST_CASE("records received within the last second are exempt from cache-flush", "[record_cache][cache_flush]")
{
    clock_guard cg;
    record_cache<clock_type> cache;

    // RFC 6762 section 10.2 marks only records received more than one second ago
    cache.insert(make_a_record("myhost.local.", "192.168.1.50", 120), origin_a());
    clock_type::advance(500ms);
    cache.insert(make_a_record("myhost.local.", "192.168.1.60", 120, dns_class::in, true), origin_b());

    clock_type::advance(5s);
    auto expired = cache.erase_expired();

    CHECK(expired.empty());
    CHECK(cache.find("myhost.local.", dns_type::a).size() == 2);
}

TEST_CASE("on_cache_flush is not fired for exempt young records", "[record_cache][cache_flush]")
{
    clock_guard cg;
    bool called = false;
    record_cache<clock_type> cache(flag_cache_flush(called));

    cache.insert(make_a_record("myhost.local.", "192.168.1.50", 120), origin_a());
    // No advance: the existing record is younger than one second
    cache.insert(make_a_record("myhost.local.", "192.168.1.60", 120, dns_class::in, true), origin_b());

    CHECK_FALSE(called);
}
