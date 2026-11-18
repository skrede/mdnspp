#include "mdnspp/detail/move_only_function.h"

#include <catch2/catch_template_test_macros.hpp>
#include <catch2/catch_test_macros.hpp>

#include <string>
#include <memory>
#include <cstddef>
#include <utility>

namespace {

using mdnspp::detail::move_only_function;
using signature = int(int);

constexpr std::size_t capacity = move_only_function<signature>::inline_capacity;

template <std::size_t padding>
class tracked
{
public:
    explicit tracked(int &live)
        : m_live(&live)
        , m_padding{}
    {
        ++*m_live;
    }

    tracked(tracked &&other) noexcept
        : m_live(other.m_live)
        , m_padding{}
    {
        ++*m_live;
    }

    tracked(const tracked &) = delete;
    tracked &operator=(const tracked &) = delete;

    ~tracked() { --*m_live; }

    int operator()(int value) { return value + 1 + static_cast<int>(m_padding[0]); }

private:
    int *m_live;
    std::byte m_padding[padding + 1];
};

using small_callable = tracked<0>;
using large_callable = tracked<capacity + 1>;

}

TEMPLATE_TEST_CASE("the callable is destroyed exactly once", "[move_only_function]", small_callable, large_callable)
{
    int live = 0;
    {
        move_only_function<signature> fn{TestType(live)};
        CHECK(live == 1);
        CHECK(fn(1) == 2);
    }
    REQUIRE(live == 0);
}

TEMPLATE_TEST_CASE("moves relocate the callable without duplicating it", "[move_only_function]", small_callable,
                   large_callable)
{
    int live = 0;
    {
        move_only_function<signature> first{TestType(live)};
        move_only_function<signature> second(std::move(first));
        move_only_function<signature> third;
        third = std::move(second);
        CHECK(live == 1);
        CHECK(third(1) == 2);
    }
    REQUIRE(live == 0);
}

TEMPLATE_TEST_CASE("swap exchanges the stored callables", "[move_only_function]", small_callable, large_callable)
{
    int live = 0;
    {
        move_only_function<signature> held{TestType(live)};
        move_only_function<signature> other{[](int value) { return value * 10; }};
        swap(held, other);
        CHECK(held(2) == 20);
        CHECK(other(2) == 3);
        CHECK(live == 1);
    }
    REQUIRE(live == 0);
}

TEMPLATE_TEST_CASE("assigning over a stored callable destroys it once", "[move_only_function]", small_callable,
                   large_callable)
{
    int live = 0;
    move_only_function<signature> fn{TestType(live)};
    fn = [](int value) { return value - 1; };
    CHECK(live == 0);
    REQUIRE(fn(5) == 4);
}

TEMPLATE_TEST_CASE("a moved-from function is empty", "[move_only_function]", small_callable, large_callable)
{
    int live = 0;
    move_only_function<signature> source{TestType(live)};
    move_only_function<signature> target(std::move(source));
    CHECK(source == nullptr);
    CHECK(static_cast<bool>(target));
    REQUIRE(live == 1);
}
