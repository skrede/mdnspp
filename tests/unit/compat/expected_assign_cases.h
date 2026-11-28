#ifndef HPP_GUARD_MDNSPP_COMPAT_EXPECTED_ASSIGN_CASES_H
#define HPP_GUARD_MDNSPP_COMPAT_EXPECTED_ASSIGN_CASES_H

#include "compat/expected_family.h"

#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_template_test_macros.hpp>

#include <utility>
#include <stdexcept>
#include <type_traits>

namespace mdnspp::test_support {

class fragile
{
public:
    explicit fragile(bool armed) : m_armed(armed) {}

    fragile(const fragile &other) : m_armed(other.m_armed) { throw_if_armed(); }

    // Deliberately not noexcept, so neither the direct nor the temporary replacement path is nothrow.
    // NOLINTNEXTLINE(performance-noexcept-move-constructor)
    fragile(fragile &&other) : m_armed(other.m_armed) { throw_if_armed(); }

    fragile &operator=(const fragile &) = default;
    fragile &operator=(fragile &&) = default;

private:
    bool m_armed;

    void throw_if_armed() const
    {
        if(m_armed)
            throw std::runtime_error("armed copy");
    }
};

// Trivial assignment for std::expected is LWG 4026, a post-C++23 defect fix that libstdc++ implements from GCC 16;
// libc++, older libstdc++ and other standard libraries are held only to the own expected.
template <typename Family>
inline constexpr bool assignment_propagates_triviality =
#if defined(_GLIBCXX_RELEASE) && _GLIBCXX_RELEASE >= 16
    true;
#else
    std::is_same_v<Family, own_family>;
#endif

}

TEMPLATE_LIST_TEST_CASE("a throwing unexpected assignment keeps the value", "[expected_surface]", expected_families)
{
    of_t<TestType, int, fragile> target(5);
    const typename TestType::template unexpected<fragile> error(true);
    REQUIRE_THROWS_AS(target = error, std::runtime_error);
    REQUIRE(target.has_value());
    REQUIRE(*target == 5);
}

TEMPLATE_LIST_TEST_CASE("a throwing value assignment keeps the error", "[expected_surface]", expected_families)
{
    of_t<TestType, fragile, int> target(TestType::unexpect_tag, 7);
    const fragile armed(true);
    REQUIRE_THROWS_AS(target = armed, std::runtime_error);
    REQUIRE_FALSE(target.has_value());
    REQUIRE(target.error() == 7);
    target = fragile(false);
    REQUIRE(target.has_value());
}

TEMPLATE_LIST_TEST_CASE("a throwing copy assignment keeps the value", "[expected_surface]", expected_families)
{
    of_t<TestType, int, fragile> target(5);
    const of_t<TestType, int, fragile> source(TestType::unexpect_tag, true);
    REQUIRE_THROWS_AS(target = source, std::runtime_error);
    REQUIRE(target.has_value());
    REQUIRE(*target == 5);
}

TEMPLATE_LIST_TEST_CASE("a throwing move assignment keeps the value", "[expected_surface]", expected_families)
{
    of_t<TestType, int, fragile> target(5);
    of_t<TestType, int, fragile> source(TestType::unexpect_tag, true);
    REQUIRE_THROWS_AS(target = std::move(source), std::runtime_error);
    REQUIRE(target.has_value());
    REQUIRE(*target == 5);
}

TEMPLATE_LIST_TEST_CASE("a throwing error assignment keeps a void value", "[expected_surface]", expected_families)
{
    of_t<TestType, void, fragile> target;
    const typename TestType::template unexpected<fragile> error(true);
    REQUIRE_THROWS_AS(target = error, std::runtime_error);
    REQUIRE(target.has_value());
}

TEMPLATE_LIST_TEST_CASE("assignment is constrained and stays trivial where both alternatives are",
                        "[expected_surface]", expected_families)
{
    CHECK_FALSE(std::is_copy_assignable_v<of_t<TestType, fragile, fragile>>);
    CHECK_FALSE(std::is_move_assignable_v<of_t<TestType, fragile, fragile>>);
    CHECK(std::is_copy_assignable_v<of_t<TestType, int, fragile>>);
    CHECK(std::is_nothrow_move_assignable_v<of_t<TestType, int, int>>);
    if constexpr(assignment_propagates_triviality<TestType>)
    {
        CHECK(std::is_trivially_copy_assignable_v<of_t<TestType, int, int>>);
        CHECK(std::is_trivially_move_assignable_v<of_t<TestType, void, int>>);
    }
}

#endif
