#ifndef HPP_GUARD_MDNSPP_COMPAT_EXPECTED_VOID_CASES_H
#define HPP_GUARD_MDNSPP_COMPAT_EXPECTED_VOID_CASES_H

#include "compat/expected_family.h"

#include <catch2/catch_template_test_macros.hpp>

#include <utility>

using namespace mdnspp::test_support;

TEMPLATE_LIST_TEST_CASE("expected void holds success or an error", "[expected_surface]", expected_families)
{
    result_t<TestType, void> good;
    result_t<TestType, void> bad(TestType::unexpect_tag, "boom");
    REQUIRE(good.has_value());
    REQUIRE_FALSE(bad.has_value());
    REQUIRE(bad.error() == "boom");
    REQUIRE(good.error_or("fallback") == "fallback");
    REQUIRE(bad.error_or("fallback") == "boom");
}

TEMPLATE_LIST_TEST_CASE("expected void value throws a bad access on an error", "[expected_surface]",
                        expected_families)
{
    result_t<TestType, void> good(std::in_place);
    result_t<TestType, void> bad(unexpected_t<TestType>("boom"));
    REQUIRE_NOTHROW(good.value());
    try
    {
        bad.value();
        FAIL("value did not throw");
    }
    catch(const access_t<TestType> &e)
    {
        REQUIRE(e.error() == "boom");
    }
}

TEMPLATE_LIST_TEST_CASE("expected void compares equal by state and error", "[expected_surface]", expected_families)
{
    result_t<TestType, void> good;
    result_t<TestType, void> bad(TestType::unexpect_tag, "boom");
    REQUIRE(good == result_t<TestType, void>());
    REQUIRE(bad == result_t<TestType, void>(TestType::unexpect_tag, "boom"));
    REQUIRE(good != bad);
    REQUIRE(bad == unexpected_t<TestType>("boom"));
}

TEMPLATE_LIST_TEST_CASE("expected void monadic operations follow the value rules", "[expected_surface]",
                        expected_families)
{
    auto make = []() { return result_t<TestType, int>(5); };
    auto recover = [](const std::string &) { return result_t<TestType, void>(); };
    result_t<TestType, void> good;
    result_t<TestType, void> bad(TestType::unexpect_tag, "boom");
    REQUIRE(good.and_then(make) == 5);
    REQUIRE(bad.and_then(make).error() == "boom");
    REQUIRE(good.transform([] { return 3; }) == 3);
    REQUIRE(bad.or_else(recover).has_value());
    REQUIRE(bad.transform_error([](const std::string &e) { return e.size(); }).error() == 4);
}

TEMPLATE_LIST_TEST_CASE("expected void emplace and swap change state", "[expected_surface]", expected_families)
{
    result_t<TestType, void> bad(TestType::unexpect_tag, "boom");
    result_t<TestType, void> good;
    swap(bad, good);
    REQUIRE(good.error() == "boom");
    REQUIRE(bad.has_value());
    good.emplace();
    REQUIRE(good.has_value());
}

#endif
