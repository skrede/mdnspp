#include "mdnspp/detail/move_only_function.h"

#include "support/alloc_counter.h"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <utility>

namespace {

using mdnspp::detail::move_only_function;
using function_type = move_only_function<int()>;

constexpr std::size_t capacity = function_type::inline_capacity;

template <std::size_t size>
struct sized_callable
{
    std::byte bytes[size];

    int operator()() { return static_cast<int>(size); }
};

struct alignas(2 * alignof(std::max_align_t)) over_aligned_callable
{
    int operator()() { return 1; }
};

struct throwing_move_callable
{
    throwing_move_callable() = default;
    throwing_move_callable(throwing_move_callable &&) noexcept(false) {}

    int operator()() { return 2; }
};

// Publishing each object's address through a volatile pointer stops the
// optimizer from eliding the paired new/delete, which would otherwise read as
// zero allocations in optimized builds.
function_type *volatile escape = nullptr;

template <typename Callable>
uint64_t allocations_when_built_and_moved(int &result)
{
    mdnspp::test_support::reset_allocation_count();
    function_type fn{Callable{}};
    escape = &fn;
    function_type moved(std::move(fn));
    escape = &moved;
    result = moved();
    return mdnspp::test_support::allocation_count();
}

}

static_assert(function_type::stored_inline<sized_callable<capacity>>);
static_assert(!function_type::stored_inline<sized_callable<capacity + 1>>);
static_assert(!function_type::stored_inline<over_aligned_callable>);
static_assert(!function_type::stored_inline<throwing_move_callable>);

TEST_CASE("a callable at the inline capacity is stored without allocation", "[move_only_function][alloc]")
{
    int result = 0;
    const uint64_t count = allocations_when_built_and_moved<sized_callable<capacity>>(result);
    CHECK(result == static_cast<int>(capacity));
    REQUIRE(count == 0);
}

TEST_CASE("a callable one byte over the capacity uses one heap allocation", "[move_only_function][alloc]")
{
    int result = 0;
    const uint64_t count = allocations_when_built_and_moved<sized_callable<capacity + 1>>(result);
    CHECK(result == static_cast<int>(capacity + 1));
    REQUIRE(count == 1);
}

TEST_CASE("an over-aligned callable uses one heap allocation", "[move_only_function][alloc]")
{
    int result = 0;
    const uint64_t count = allocations_when_built_and_moved<over_aligned_callable>(result);
    CHECK(result == 1);
    REQUIRE(count == 1);
}

TEST_CASE("a callable that may throw on move uses one heap allocation", "[move_only_function][alloc]")
{
    int result = 0;
    const uint64_t count = allocations_when_built_and_moved<throwing_move_callable>(result);
    CHECK(result == 2);
    REQUIRE(count == 1);
}

TEST_CASE("an emptied function stays empty without allocating", "[move_only_function][alloc]")
{
    function_type fn{sized_callable<8>{}};
    mdnspp::test_support::reset_allocation_count();
    fn = nullptr;
    function_type other;
    fn = std::move(other);
    REQUIRE(mdnspp::test_support::allocation_count() == 0);
}
