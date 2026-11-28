#include "mdnspp/detail/move_only_function.h"

#include <catch2/catch_test_macros.hpp>

#include <memory>
#include <string>
#include <utility>

namespace {

using mdnspp::detail::move_only_function;

struct counter
{
    int value;

    int next() { return ++value; }
};

int twice(int value)
{
    return value * 2;
}

}

TEST_CASE("a callable capturing a move-only value is accepted and invoked", "[move_only_function]")
{
    auto owned = std::make_unique<int>(41);
    move_only_function<int()> fn{[owned = std::move(owned)] { return *owned + 1; }};
    REQUIRE(fn() == 42);
}

TEST_CASE("move-only arguments are forwarded", "[move_only_function]")
{
    move_only_function<int(std::unique_ptr<int>)> fn{[](std::unique_ptr<int> value) { return *value; }};
    REQUIRE(fn(std::make_unique<int>(9)) == 9);
}

TEST_CASE("reference arguments are forwarded without copies", "[move_only_function]")
{
    move_only_function<void(std::string &)> fn{[](std::string &text) { text += "!"; }};
    std::string text = "hi";
    fn(text);
    REQUIRE(text == "hi!");
}

TEST_CASE("a callable returning a value is accepted for a void signature", "[move_only_function]")
{
    int calls = 0;
    move_only_function<void()> fn{[&calls] { return ++calls; }};
    fn();
    REQUIRE(calls == 1);
}

TEST_CASE("nullptr construction, assignment and comparison", "[move_only_function]")
{
    move_only_function<int()> empty;
    move_only_function<int()> from_null(nullptr);
    CHECK(empty == nullptr);
    CHECK(nullptr == from_null);
    move_only_function<int()> fn{[] { return 1; }};
    CHECK(fn != nullptr);
    fn = nullptr;
    CHECK_FALSE(static_cast<bool>(fn));
    REQUIRE(fn == nullptr);
}

TEST_CASE("a function pointer is stored and invoked", "[move_only_function]")
{
    move_only_function<int(int)> fn{+[](int value) { return value * 2; }};
    REQUIRE(fn(21) == 42);
}

TEST_CASE("a function reference is stored and invoked", "[move_only_function]")
{
    move_only_function<int(int)> fn{twice};
    REQUIRE(fn(21) == 42);
}

TEST_CASE("a null function pointer yields an empty wrapper", "[move_only_function]")
{
    int (*null_fn)(int) = nullptr;
    move_only_function<int(int)> fn{null_fn};
    REQUIRE(fn == nullptr);
    REQUIRE_FALSE(static_cast<bool>(fn));
}

TEST_CASE("a null member pointer yields an empty wrapper", "[move_only_function]")
{
    int (counter::*null_method)() = nullptr;
    int counter::*null_field = nullptr;
    move_only_function<int(counter &)> method{null_method};
    move_only_function<int &(counter &)> field{null_field};
    REQUIRE(method == nullptr);
    REQUIRE(field == nullptr);
}

TEST_CASE("non-null member pointers stay callable", "[move_only_function]")
{
    counter target{4};
    move_only_function<int(counter &)> method{&counter::next};
    move_only_function<int &(counter &)> field{&counter::value};
    REQUIRE(method(target) == 5);
    REQUIRE(field(target) == 5);
}
