#ifndef HPP_GUARD_MDNSPP_COMPAT_EXPECTED_CASES_H
#define HPP_GUARD_MDNSPP_COMPAT_EXPECTED_CASES_H

#include "compat/expected_family.h"

#include <catch2/catch_template_test_macros.hpp>

#include <vector>
#include <utility>

using namespace mdnspp::test_support;

TEMPLATE_LIST_TEST_CASE("value_or returns the held value or the fallback", "[expected_surface]", expected_families)
{
    result_t<TestType, int> good(4);
    result_t<TestType, int> bad(TestType::unexpect_tag, "boom");
    REQUIRE(good.value_or(9) == 4);
    REQUIRE(bad.value_or(9) == 9);
    REQUIRE(result_t<TestType, int>(5).value_or(9) == 5);
    REQUIRE(result_t<TestType, int>(TestType::unexpect_tag, "x").value_or(9) == 9);
}

TEMPLATE_LIST_TEST_CASE("error_or returns the held error or the fallback", "[expected_surface]", expected_families)
{
    result_t<TestType, int> good(4);
    result_t<TestType, int> bad(TestType::unexpect_tag, "boom");
    REQUIRE(good.error_or("fallback") == "fallback");
    REQUIRE(bad.error_or("fallback") == "boom");
    REQUIRE(result_t<TestType, int>(TestType::unexpect_tag, "x").error_or("y") == "x");
}

TEMPLATE_LIST_TEST_CASE("in_place and unexpect tags forward their arguments", "[expected_surface]", expected_families)
{
    result_t<TestType, std::vector<int>> list(std::in_place, std::initializer_list<int>{1, 2, 3});
    result_t<TestType, int> failed(TestType::unexpect_tag, std::initializer_list<char>{'a', 'b'});
    REQUIRE(list->size() == 3);
    REQUIRE_FALSE(failed.has_value());
    REQUIRE(failed.error() == "ab");
}

TEMPLATE_LIST_TEST_CASE("converting construction carries a value or an error", "[expected_surface]", expected_families)
{
    result_t<TestType, int> good(3);
    result_t<TestType, int> bad(TestType::unexpect_tag, "boom");
    typename TestType::template expected<long, std::string> widened_good(good);
    typename TestType::template expected<long, std::string> widened_bad(std::move(bad));
    REQUIRE(*widened_good == 3);
    REQUIRE(widened_bad.error() == "boom");
}

TEMPLATE_LIST_TEST_CASE("assignment switches between a value and an error", "[expected_surface]", expected_families)
{
    result_t<TestType, int> r(1);
    r = unexpected_t<TestType>("failed");
    REQUIRE(r.error() == "failed");
    r = 7;
    REQUIRE(*r == 7);
    r = 8;
    REQUIRE(*r == 8);
}

TEMPLATE_LIST_TEST_CASE("emplace replaces an error with a value", "[expected_surface]", expected_families)
{
    result_t<TestType, std::pair<int, int>> r(TestType::unexpect_tag, "boom");
    r.emplace(3, 5);
    REQUIRE(r.has_value());
    REQUIRE(r->first == 3);
    REQUIRE(r->second == 5);
}

TEMPLATE_LIST_TEST_CASE("swap exchanges every combination of value and error", "[expected_surface]", expected_families)
{
    result_t<TestType, int> a(1);
    result_t<TestType, int> b(2);
    result_t<TestType, int> e(TestType::unexpect_tag, "e");
    a.swap(b);
    REQUIRE((*a == 2 && *b == 1));
    swap(a, e);
    REQUIRE((a.error() == "e" && *e == 2));
    result_t<TestType, int> f(TestType::unexpect_tag, "f");
    swap(a, f);
    REQUIRE((a.error() == "f" && f.error() == "e"));
}

#endif
