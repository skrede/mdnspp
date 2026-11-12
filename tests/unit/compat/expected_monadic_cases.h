#ifndef HPP_GUARD_MDNSPP_COMPAT_EXPECTED_MONADIC_CASES_H
#define HPP_GUARD_MDNSPP_COMPAT_EXPECTED_MONADIC_CASES_H

#include "compat/expected_family.h"

#include <catch2/catch_template_test_macros.hpp>

#include <string>
#include <utility>

using namespace mdnspp::test_support;

TEMPLATE_LIST_TEST_CASE("and_then chains on a value and keeps the error", "[expected_surface]", expected_families)
{
    auto stringify = [](int v) { return result_t<TestType, std::string>(std::to_string(v)); };
    result_t<TestType, int> good(42);
    result_t<TestType, int> bad(TestType::unexpect_tag, "boom");
    REQUIRE(good.and_then(stringify) == std::string("42"));
    REQUIRE(std::move(good).and_then(stringify) == std::string("42"));
    REQUIRE(bad.and_then(stringify).error() == "boom");
    REQUIRE(std::as_const(bad).and_then(stringify).error() == "boom");
}

TEMPLATE_LIST_TEST_CASE("transform maps a value and keeps the error", "[expected_surface]", expected_families)
{
    auto twice = [](int v) { return v * 2; };
    result_t<TestType, int> good(21);
    result_t<TestType, int> bad(TestType::unexpect_tag, "boom");
    REQUIRE(good.transform(twice) == 42);
    REQUIRE(bad.transform(twice).error() == "boom");
    REQUIRE(std::move(good).transform(twice) == 42);
}

TEMPLATE_LIST_TEST_CASE("transform to void yields an expected void", "[expected_surface]", expected_families)
{
    int seen = 0;
    auto record = [&seen](int v) { seen = v; };
    result_t<TestType, int> good(7);
    result_t<TestType, int> bad(TestType::unexpect_tag, "boom");
    auto done = good.transform(record);
    static_assert(std::is_void_v<typename decltype(done)::value_type>);
    REQUIRE(done.has_value());
    REQUIRE(seen == 7);
    REQUIRE(bad.transform(record).error() == "boom");
}

TEMPLATE_LIST_TEST_CASE("or_else recovers from an error and keeps a value", "[expected_surface]", expected_families)
{
    auto recover = [](const std::string &) { return result_t<TestType, int>(-1); };
    result_t<TestType, int> good(3);
    result_t<TestType, int> bad(TestType::unexpect_tag, "boom");
    REQUIRE(good.or_else(recover) == 3);
    REQUIRE(bad.or_else(recover) == -1);
    REQUIRE(std::move(bad).or_else(recover) == -1);
}

TEMPLATE_LIST_TEST_CASE("transform_error maps the error and keeps a value", "[expected_surface]", expected_families)
{
    auto length = [](const std::string &e) { return e.size(); };
    result_t<TestType, int> good(3);
    result_t<TestType, int> bad(TestType::unexpect_tag, "boom");
    REQUIRE(good.transform_error(length) == 3);
    REQUIRE(bad.transform_error(length).error() == 4);
    REQUIRE(std::as_const(bad).transform_error(length).error() == 4);
}

#endif
