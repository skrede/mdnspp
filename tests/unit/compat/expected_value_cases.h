#ifndef HPP_GUARD_MDNSPP_COMPAT_EXPECTED_VALUE_CASES_H
#define HPP_GUARD_MDNSPP_COMPAT_EXPECTED_VALUE_CASES_H

#include "compat/expected_family.h"

#include <catch2/catch_template_test_macros.hpp>

#include <memory>
#include <utility>

using namespace mdnspp::test_support;

TEMPLATE_LIST_TEST_CASE("value on an error throws a bad access carrying the error", "[expected_surface]",
                        expected_families)
{
    result_t<TestType, int> bad(TestType::unexpect_tag, "boom");
    try
    {
        static_cast<void>(bad.value());
        FAIL("value did not throw");
    }
    catch(const access_t<TestType> &e)
    {
        REQUIRE(e.error() == "boom");
    }
}

TEMPLATE_LIST_TEST_CASE("value on an rvalue error moves the error into the exception", "[expected_surface]",
                        expected_families)
{
    try
    {
        static_cast<void>(result_t<TestType, int>(TestType::unexpect_tag, "gone").value());
        FAIL("value did not throw");
    }
    catch(const access_t<TestType> &e)
    {
        REQUIRE(e.error() == "gone");
    }
}

TEMPLATE_LIST_TEST_CASE("move-only value and error types are supported", "[expected_surface]", expected_families)
{
    using move_only = typename TestType::template expected<std::unique_ptr<int>, std::unique_ptr<char>>;
    move_only good(std::make_unique<int>(5));
    move_only bad(TestType::unexpect_tag, std::make_unique<char>('x'));
    auto value = *std::move(good);
    auto error = std::move(bad).error();
    REQUIRE(*value == 5);
    REQUIRE(*error == 'x');
}

TEMPLATE_LIST_TEST_CASE("equality compares expecteds, values and unexpecteds", "[expected_surface]",
                        expected_families)
{
    result_t<TestType, int> a(1);
    result_t<TestType, int> bad(TestType::unexpect_tag, "boom");
    REQUIRE(a == result_t<TestType, int>(1));
    REQUIRE(a != result_t<TestType, int>(2));
    REQUIRE(a == 1);
    REQUIRE(bad != 1);
    REQUIRE(bad == unexpected_t<TestType>("boom"));
    REQUIRE(a != unexpected_t<TestType>("boom"));
    REQUIRE(bad != result_t<TestType, int>(1));
}

TEMPLATE_LIST_TEST_CASE("unexpected exposes error in every value category", "[expected_surface]", expected_families)
{
    unexpected_t<TestType> e("boom");
    unexpected_t<TestType> other("other");
    REQUIRE(e.error() == "boom");
    REQUIRE(std::as_const(e).error() == "boom");
    e.swap(other);
    REQUIRE((e.error() == "other" && other.error() == "boom"));
    REQUIRE(std::move(e).error() == "other");
    REQUIRE(e != other);
}

#endif
