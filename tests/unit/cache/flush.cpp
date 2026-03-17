#include "helpers.h"

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

// --- Cache-flush semantics (RFC 6762 section 10.2) ---

TEST_CASE("cache-flush sets flush_deadline on other-origin entries", "[record_cache][cache_flush]")
{
    clock_guard cg;
    record_cache<clock_type> cache;

    // Insert from origin A (no cache_flush)
    cache.insert(make_a_record("myhost.local.", "192.168.1.50", 120), origin_a());

    // Insert cache-flush record from origin B
    cache.insert(make_a_record("myhost.local.", "192.168.1.60", 120, dns_class::in, true), origin_b());

    // Origin A entry still visible (within 1s grace period)
    auto results = cache.find("myhost.local.", dns_type::a);
    CHECK(results.size() == 2);

    // After 1 second, erase_expired removes the flushed entry
    clock_type::advance(1s);
    auto expired = cache.erase_expired();

    CHECK(expired.size() == 1);
    CHECK(std::get<record_a>(expired[0].record).address_string == "192.168.1.50");

    // Only the authoritative entry remains
    results = cache.find("myhost.local.", dns_type::a);
    REQUIRE(results.size() == 1);
    CHECK(std::get<record_a>(results[0].record).address_string == "192.168.1.60");
}

TEST_CASE("cache-flush does not affect same-origin entries", "[record_cache][cache_flush]")
{
    clock_guard cg;
    record_cache<clock_type> cache;

    // Insert two records from origin A
    cache.insert(make_a_record("myhost.local.", "192.168.1.50", 120), origin_a());
    cache.insert(make_a_record("myhost.local.", "192.168.1.51", 120), origin_a());

    // Insert cache-flush from SAME origin A
    cache.insert(make_a_record("myhost.local.", "192.168.1.52", 120, dns_class::in, true), origin_a());

    // After 1 second, nothing should be flushed (all same origin)
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

    // Cache-flush from origin B
    cache.insert(make_a_record("myhost.local.", "192.168.1.60", 120, dns_class::in, true), origin_b());

    // At 500ms, origin A entry is still findable
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

    // Cache-flush from origin B
    cache.insert(make_a_record("myhost.local.", "192.168.1.60", 120, dns_class::in, true), origin_b());

    // Callback should have fired
    CHECK(std::get<record_a>(authoritative_entry.record).address_string == "192.168.1.60");
    CHECK(authoritative_entry.cache_flush);
    REQUIRE(flushed_entries.size() == 1);
    CHECK(std::get<record_a>(flushed_entries[0].record).address_string == "192.168.1.50");
}

TEST_CASE("on_cache_flush not fired when no other-origin entries exist", "[record_cache][cache_flush]")
{
    clock_guard cg;
    bool called = false;
    record_cache<clock_type> cache(cache_options{
        .on_cache_flush = [&](const cache_entry &, std::vector<cache_entry>) { called = true; },
    });

    // Cache-flush from origin A with no existing entries from other origins
    cache.insert(make_a_record("myhost.local.", "192.168.1.60", 120, dns_class::in, true), origin_a());

    CHECK_FALSE(called);
}

TEST_CASE("new record from different origin during grace period stored normally", "[record_cache][cache_flush]")
{
    clock_guard cg;
    record_cache<clock_type> cache;

    // Insert from origin A
    cache.insert(make_a_record("myhost.local.", "192.168.1.50", 120), origin_a());

    // Cache-flush from origin B -- origin A gets flush_deadline
    cache.insert(make_a_record("myhost.local.", "192.168.1.60", 120, dns_class::in, true), origin_b());

    // During grace period, origin C inserts a fresh record
    clock_type::advance(500ms);
    cache.insert(make_a_record("myhost.local.", "192.168.1.70", 120), origin_c());

    // All three should be present
    CHECK(cache.find("myhost.local.", dns_type::a).size() == 3);

    // After grace period, only origin A's old entry is flushed
    clock_type::advance(500ms);
    auto expired = cache.erase_expired();

    CHECK(expired.size() == 1);
    CHECK(std::get<record_a>(expired[0].record).address_string == "192.168.1.50");

    // Origin B and C entries survive
    CHECK(cache.find("myhost.local.", dns_type::a).size() == 2);
}

TEST_CASE("goodbye with cache_flush flushes other-origin and self-expires", "[record_cache][cache_flush]")
{
    clock_guard cg;
    record_cache<clock_type> cache;

    // Insert from origin A with long TTL
    cache.insert(make_a_record("myhost.local.", "192.168.1.50", 300), origin_a());

    // Goodbye + cache_flush from origin B (TTL=0 + cache_flush=true)
    cache.insert(make_a_record("myhost.local.", "192.168.1.60", 0, dns_class::in, true), origin_b());

    // Both exist during grace period
    CHECK(cache.find("myhost.local.", dns_type::a).size() == 2);

    // After 1 second: origin A flushed, origin B goodbye also expired (effective 1s TTL)
    clock_type::advance(1s);
    auto expired = cache.erase_expired();

    CHECK(expired.size() == 2);
    CHECK(cache.find("myhost.local.", dns_type::a).empty());
}

TEST_CASE("multiple cache-flush from different origins in succession", "[record_cache][cache_flush]")
{
    clock_guard cg;
    record_cache<clock_type> cache;

    // Insert from origin A
    cache.insert(make_a_record("myhost.local.", "192.168.1.50", 120), origin_a());

    // Cache-flush from origin B -- flush_deadline on origin A
    cache.insert(make_a_record("myhost.local.", "192.168.1.60", 120, dns_class::in, true), origin_b());

    // Cache-flush from origin C -- flush_deadline on origin A AND origin B
    clock_type::advance(200ms);
    cache.insert(make_a_record("myhost.local.", "192.168.1.70", 120, dns_class::in, true), origin_c());

    // After 1 second from origin C's flush, origin A and B should be flushed
    clock_type::advance(1s);
    auto expired = cache.erase_expired();

    CHECK(expired.size() == 2);
    REQUIRE(cache.find("myhost.local.", dns_type::a).size() == 1);
    CHECK(std::get<record_a>(cache.find("myhost.local.", dns_type::a)[0].record).address_string == "192.168.1.70");
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

TEST_CASE("apply_cache_flush uses configured goodbye_grace", "[record_cache][cache_flush]")
{
    clock_guard cg;
    record_cache<clock_type> cache(cache_options{.goodbye_grace = std::chrono::seconds(3)});

    // Insert from origin A
    cache.insert(make_a_record("myhost.local.", "192.168.1.50", 120), origin_a());

    // Cache-flush from origin B -- applies goodbye_grace as the flush deadline
    cache.insert(make_a_record("myhost.local.", "192.168.1.60", 120, dns_class::in, true), origin_b());

    // At 2 seconds (< 3s grace): origin A entry still alive
    clock_type::advance(2s);
    auto expired = cache.erase_expired();
    CHECK(expired.empty());

    // At 3 seconds (== 3s grace): origin A entry flushed
    clock_type::advance(1s);
    expired = cache.erase_expired();
    CHECK(expired.size() == 1);
    CHECK(std::get<record_a>(expired[0].record).address_string == "192.168.1.50");
}

TEST_CASE("cache-flush does not affect entries with different name or type", "[record_cache][cache_flush]")
{
    clock_guard cg;
    record_cache<clock_type> cache;

    // Insert A record from origin A
    cache.insert(make_a_record("myhost.local.", "192.168.1.50", 120), origin_a());

    // Insert PTR record with same name from origin A (different type)
    cache.insert(make_ptr_record("myhost.local.", "service._tcp.local."), origin_a());

    // Insert different-name A record from origin A
    cache.insert(make_a_record("other.local.", "10.0.0.1", 120), origin_a());

    // Cache-flush A record from origin B for "myhost.local."
    cache.insert(make_a_record("myhost.local.", "192.168.1.60", 120, dns_class::in, true), origin_b());

    // After 1 second, only myhost.local. A record from origin A is flushed
    clock_type::advance(1s);
    auto expired = cache.erase_expired();

    CHECK(expired.size() == 1);
    CHECK(std::get<record_a>(expired[0].record).address_string == "192.168.1.50");

    // PTR and other-name records untouched
    CHECK(cache.find("myhost.local.", dns_type::ptr).size() == 1);
    CHECK(cache.find("other.local.", dns_type::a).size() == 1);
}
