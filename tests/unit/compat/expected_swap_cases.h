#ifndef HPP_GUARD_MDNSPP_COMPAT_EXPECTED_SWAP_CASES_H
#define HPP_GUARD_MDNSPP_COMPAT_EXPECTED_SWAP_CASES_H

#include "compat/expected_family.h"

#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_template_test_macros.hpp>

#include <cstdint>
#include <utility>
#include <stdexcept>
#include <type_traits>

namespace mdnspp::test_support {

class move_budget
{
public:
    explicit move_budget(int32_t moves) : m_moves(moves) {}

    // Throws once the budget is spent, so a swap that moves an alternative more than once is caught.
    // NOLINTNEXTLINE(performance-noexcept-move-constructor)
    move_budget(move_budget &&other) : m_moves(other.m_moves - 1)
    {
        if(m_moves < 0)
            throw std::runtime_error("move budget spent");
    }

    move_budget(const move_budget &) = delete;
    move_budget &operator=(move_budget &&) = default;

    int32_t moves_left() const { return m_moves; }

private:
    int32_t m_moves;
};

}

TEMPLATE_LIST_TEST_CASE("swap moves an error that allows one move once", "[expected_surface]", expected_families)
{
    of_t<TestType, int32_t, move_budget> value(5);
    of_t<TestType, int32_t, move_budget> error(TestType::unexpect_tag, 1);
    SECTION("the value side swaps") { REQUIRE_NOTHROW(value.swap(error)); }
    SECTION("the error side swaps") { REQUIRE_NOTHROW(error.swap(value)); }
    REQUIRE(error.has_value());
    REQUIRE(*error == 5);
    REQUIRE_FALSE(value.has_value());
    REQUIRE(value.error().moves_left() == 0);
}

TEMPLATE_LIST_TEST_CASE("swap moves a value that allows one move once", "[expected_surface]", expected_families)
{
    of_t<TestType, move_budget, int32_t> value(std::in_place, 1);
    of_t<TestType, move_budget, int32_t> error(TestType::unexpect_tag, 7);
    SECTION("the value side swaps") { REQUIRE_NOTHROW(value.swap(error)); }
    SECTION("the error side swaps") { REQUIRE_NOTHROW(error.swap(value)); }
    REQUIRE_FALSE(value.has_value());
    REQUIRE(value.error() == 7);
    REQUIRE(error.has_value());
    REQUIRE(error->moves_left() == 0);
}

TEMPLATE_LIST_TEST_CASE("a throwing error move in swap keeps both operands", "[expected_surface]", expected_families)
{
    of_t<TestType, int32_t, move_budget> value(5);
    of_t<TestType, int32_t, move_budget> error(TestType::unexpect_tag, 0);
    SECTION("the value side swaps") { REQUIRE_THROWS_AS(value.swap(error), std::runtime_error); }
    SECTION("the error side swaps") { REQUIRE_THROWS_AS(error.swap(value), std::runtime_error); }
    REQUIRE(value.has_value());
    REQUIRE(*value == 5);
    REQUIRE_FALSE(error.has_value());
    REQUIRE(error.error().moves_left() == 0);
}

TEMPLATE_LIST_TEST_CASE("a throwing value move in swap keeps both operands", "[expected_surface]", expected_families)
{
    of_t<TestType, move_budget, int32_t> value(std::in_place, 0);
    of_t<TestType, move_budget, int32_t> error(TestType::unexpect_tag, 7);
    SECTION("the value side swaps") { REQUIRE_THROWS_AS(value.swap(error), std::runtime_error); }
    SECTION("the error side swaps") { REQUIRE_THROWS_AS(error.swap(value), std::runtime_error); }
    REQUIRE_FALSE(error.has_value());
    REQUIRE(error.error() == 7);
    REQUIRE(value.has_value());
    REQUIRE(value->moves_left() == 0);
}

TEMPLATE_LIST_TEST_CASE("swap moves a void error that allows one move once", "[expected_surface]", expected_families)
{
    of_t<TestType, void, move_budget> value;
    of_t<TestType, void, move_budget> error(TestType::unexpect_tag, 1);
    SECTION("the value side swaps") { REQUIRE_NOTHROW(value.swap(error)); }
    SECTION("the error side swaps") { REQUIRE_NOTHROW(error.swap(value)); }
    REQUIRE(error.has_value());
    REQUIRE_FALSE(value.has_value());
    REQUIRE(value.error().moves_left() == 0);
}

TEMPLATE_LIST_TEST_CASE("a throwing void error move in swap keeps both operands", "[expected_surface]",
                        expected_families)
{
    of_t<TestType, void, move_budget> value;
    of_t<TestType, void, move_budget> error(TestType::unexpect_tag, 0);
    SECTION("the value side swaps") { REQUIRE_THROWS_AS(value.swap(error), std::runtime_error); }
    SECTION("the error side swaps") { REQUIRE_THROWS_AS(error.swap(value), std::runtime_error); }
    REQUIRE(value.has_value());
    REQUIRE_FALSE(error.has_value());
    REQUIRE(error.error().moves_left() == 0);
}

TEMPLATE_LIST_TEST_CASE("swap is constrained and noexcept like std::expected", "[expected_surface]", expected_families)
{
    CHECK_FALSE(std::is_swappable_v<of_t<TestType, move_budget, move_budget>>);
    CHECK(std::is_swappable_v<of_t<TestType, int32_t, move_budget>>);
    CHECK(std::is_swappable_v<of_t<TestType, move_budget, int32_t>>);
    CHECK(std::is_swappable_v<of_t<TestType, void, move_budget>>);
    CHECK(std::is_nothrow_swappable_v<of_t<TestType, int32_t, int32_t>>);
    CHECK(std::is_nothrow_swappable_v<of_t<TestType, void, int32_t>>);
    CHECK_FALSE(std::is_nothrow_swappable_v<of_t<TestType, int32_t, move_budget>>);
    CHECK_FALSE(std::is_nothrow_swappable_v<of_t<TestType, void, move_budget>>);
}

#endif
