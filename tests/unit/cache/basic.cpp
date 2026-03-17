#include "helpers.h"

TEST_CASE("insert and find by name+type", "[record_cache]")
{
    clock_guard cg;
    record_cache<clock_type> cache;
    auto rec = make_a_record("myhost.local.", "192.168.1.50");
    cache.insert(rec, test_origin());

    auto results = cache.find("myhost.local.", dns_type::a);
    REQUIRE(results.size() == 1);
    CHECK(std::get<record_a>(results[0].record).address_string == "192.168.1.50");
    CHECK(results[0].wire_ttl == 120);
    CHECK(results[0].origin == test_origin());
}

TEST_CASE("find with wrong type returns empty", "[record_cache]")
{
    clock_guard cg;
    record_cache<clock_type> cache;
    cache.insert(make_a_record("myhost.local.", "192.168.1.50"), test_origin());

    auto results = cache.find("myhost.local.", dns_type::aaaa);
    CHECK(results.empty());
}

TEST_CASE("find with wrong name returns empty", "[record_cache]")
{
    clock_guard cg;
    record_cache<clock_type> cache;
    cache.insert(make_a_record("myhost.local.", "192.168.1.50"), test_origin());

    auto results = cache.find("other.local.", dns_type::a);
    CHECK(results.empty());
}

TEST_CASE("two records with different rdata coexist", "[record_cache]")
{
    clock_guard cg;
    record_cache<clock_type> cache;
    cache.insert(make_a_record("myhost.local.", "192.168.1.50"), test_origin());
    cache.insert(make_a_record("myhost.local.", "192.168.1.51"), test_origin());

    auto results = cache.find("myhost.local.", dns_type::a);
    REQUIRE(results.size() == 2);
}

TEST_CASE("duplicate insert refreshes TTL", "[record_cache]")
{
    clock_guard cg;
    record_cache<clock_type> cache;
    cache.insert(make_a_record("myhost.local.", "192.168.1.50", 120), test_origin());

    clock_type::advance(60s);
    cache.insert(make_a_record("myhost.local.", "192.168.1.50", 300), test_origin());

    auto results = cache.find("myhost.local.", dns_type::a);
    REQUIRE(results.size() == 1);
    CHECK(results[0].wire_ttl == 300);
    CHECK(results[0].ttl_remaining > 299s);
}

TEST_CASE("snapshot returns all records", "[record_cache]")
{
    clock_guard cg;
    record_cache<clock_type> cache;
    cache.insert(make_a_record("host1.local.", "10.0.0.1"), test_origin());
    cache.insert(make_a_record("host2.local.", "10.0.0.2"), test_origin());
    cache.insert(make_ptr_record("_http._tcp.local.", "myservice._http._tcp.local."), test_origin());

    auto all = cache.snapshot();
    CHECK(all.size() == 3);
}

TEST_CASE("find returns expired records with negative ttl_remaining", "[record_cache]")
{
    clock_guard cg;
    record_cache<clock_type> cache;
    cache.insert(make_a_record("myhost.local.", "192.168.1.50", 60), test_origin());

    clock_type::advance(120s);

    auto results = cache.find("myhost.local.", dns_type::a);
    REQUIRE(results.size() == 1);
    CHECK(results[0].ttl_remaining < 0ns);
}

TEST_CASE("snapshot returns expired records with negative ttl_remaining", "[record_cache]")
{
    clock_guard cg;
    record_cache<clock_type> cache;
    cache.insert(make_a_record("myhost.local.", "192.168.1.50", 60), test_origin());

    clock_type::advance(120s);

    auto all = cache.snapshot();
    REQUIRE(all.size() == 1);
    CHECK(all[0].ttl_remaining < 0ns);
}

TEST_CASE("erase_expired removes expired entries", "[record_cache]")
{
    clock_guard cg;
    record_cache<clock_type> cache;
    cache.insert(make_a_record("myhost.local.", "192.168.1.50", 60), test_origin());

    clock_type::advance(61s);
    auto expired = cache.erase_expired();

    CHECK(expired.size() == 1);
    CHECK(cache.find("myhost.local.", dns_type::a).empty());
}

TEST_CASE("erase_expired does not remove unexpired entries", "[record_cache]")
{
    clock_guard cg;
    record_cache<clock_type> cache;
    cache.insert(make_a_record("myhost.local.", "192.168.1.50", 120), test_origin());

    clock_type::advance(60s);
    auto expired = cache.erase_expired();

    CHECK(expired.empty());
    CHECK(cache.find("myhost.local.", dns_type::a).size() == 1);
}

TEST_CASE("erase_expired fires on_expired callback", "[record_cache]")
{
    clock_guard cg;
    std::vector<cache_entry> callback_entries;
    record_cache<clock_type> cache(cache_options{
        .on_expired = [&](std::vector<cache_entry> entries) {
            callback_entries = std::move(entries);
        },
    });

    cache.insert(make_a_record("myhost.local.", "192.168.1.50", 60), test_origin());

    clock_type::advance(61s);
    cache.erase_expired();

    REQUIRE(callback_entries.size() == 1);
    CHECK(std::get<record_a>(callback_entries[0].record).address_string == "192.168.1.50");
}

TEST_CASE("on_expired callback not fired when nothing expired", "[record_cache]")
{
    clock_guard cg;
    bool called = false;
    record_cache<clock_type> cache(cache_options{
        .on_expired = [&](std::vector<cache_entry>) { called = true; },
    });

    cache.insert(make_a_record("myhost.local.", "192.168.1.50", 120), test_origin());

    clock_type::advance(60s);
    cache.erase_expired();

    CHECK_FALSE(called);
}

TEST_CASE("goodbye record (TTL=0) stored with effective 1s TTL", "[record_cache]")
{
    clock_guard cg;
    record_cache<clock_type> cache;
    cache.insert(make_a_record("myhost.local.", "192.168.1.50", 0), test_origin());

    auto results = cache.find("myhost.local.", dns_type::a);
    REQUIRE(results.size() == 1);
    CHECK(results[0].wire_ttl == 1);
    CHECK(results[0].ttl_remaining > 0ns);
}

TEST_CASE("goodbye record not removed before 1 second", "[record_cache]")
{
    clock_guard cg;
    record_cache<clock_type> cache;
    cache.insert(make_a_record("myhost.local.", "192.168.1.50", 0), test_origin());

    clock_type::advance(500ms);
    auto expired = cache.erase_expired();

    CHECK(expired.empty());
    CHECK(cache.find("myhost.local.", dns_type::a).size() == 1);
}

TEST_CASE("goodbye record removed after 1 second by erase_expired", "[record_cache]")
{
    clock_guard cg;
    std::vector<cache_entry> callback_entries;
    record_cache<clock_type> cache(cache_options{
        .on_expired = [&](std::vector<cache_entry> entries) {
            callback_entries = std::move(entries);
        },
    });

    cache.insert(make_a_record("myhost.local.", "192.168.1.50", 0), test_origin());

    clock_type::advance(1s);
    auto expired = cache.erase_expired();

    CHECK(expired.size() == 1);
    CHECK(cache.find("myhost.local.", dns_type::a).empty());
    REQUIRE(callback_entries.size() == 1);
}
