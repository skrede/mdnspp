#include "helpers.h"

namespace {

constexpr dns_class class_cs = static_cast<dns_class>(2u);

}

TEST_CASE("cache-flush of class IN leaves a same-name, same-type record of another class", "[record_cache][cache_flush]")
{
    clock_guard cg;
    record_cache<clock_type> cache;

    cache.insert(make_a_record("myhost.local.", "192.168.1.50", 120, class_cs), origin_a());
    cache.insert(make_a_record("myhost.local.", "192.168.1.51", 120), origin_a());

    clock_type::advance(2s);
    cache.insert(make_a_record("myhost.local.", "192.168.1.60", 120, dns_class::in, true), origin_b());

    clock_type::advance(1s);
    auto expired = cache.erase_expired();

    REQUIRE(expired.size() == 1);
    CHECK(std::get<record_a>(expired[0].record).address_string == "192.168.1.51");

    auto other_class = cache.find("myhost.local.", dns_type::a, class_cs);
    REQUIRE(other_class.size() == 1);
    CHECK(std::get<record_a>(other_class[0].record).address_string == "192.168.1.50");
}

TEST_CASE("cache-flush of another class leaves class IN records", "[record_cache][cache_flush]")
{
    clock_guard cg;
    record_cache<clock_type> cache;

    cache.insert(make_a_record("myhost.local.", "192.168.1.51", 120), origin_a());

    clock_type::advance(2s);
    cache.insert(make_a_record("myhost.local.", "192.168.1.60", 120, class_cs, true), origin_b());

    clock_type::advance(1s);
    CHECK(cache.erase_expired().empty());
    CHECK(cache.find("myhost.local.", dns_type::a).size() == 1);
}

TEST_CASE("find without a class returns only class IN records", "[record_cache]")
{
    clock_guard cg;
    record_cache<clock_type> cache;

    cache.insert(make_a_record("myhost.local.", "192.168.1.50", 120, class_cs), origin_a());
    cache.insert(make_a_record("myhost.local.", "192.168.1.51", 120), origin_a());

    auto results = cache.find("myhost.local.", dns_type::a);
    REQUIRE(results.size() == 1);
    CHECK(std::get<record_a>(results[0].record).address_string == "192.168.1.51");
}

TEST_CASE("find with a class returns only records of that class", "[record_cache]")
{
    clock_guard cg;
    record_cache<clock_type> cache;

    cache.insert(make_a_record("myhost.local.", "192.168.1.50", 120, class_cs), origin_a());
    cache.insert(make_a_record("myhost.local.", "192.168.1.51", 120), origin_a());

    auto results = cache.find("myhost.local.", dns_type::a, class_cs);
    REQUIRE(results.size() == 1);
    CHECK(std::get<record_a>(results[0].record).address_string == "192.168.1.50");
    CHECK(std::get<record_a>(results[0].record).rclass == class_cs);
}
