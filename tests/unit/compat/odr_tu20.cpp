#include "compat/odr_shared.h"

#include <catch2/catch_test_macros.hpp>

#include <utility>

using namespace mdnspp::test_support;

TEST_CASE("both language standards agree on the expected type identity", "[compat]")
{
    REQUIRE(probe<20>(true).type_name == probe_cxx23(true).type_name);
}

TEST_CASE("both language standards read a success the same way", "[compat]")
{
    auto cxx20 = probe<20>(true);
    auto cxx23 = probe_cxx23(true);
    REQUIRE(cxx23.has_value);
    REQUIRE(cxx23.value == cxx20.value);
}

TEST_CASE("both language standards read an error the same way", "[compat]")
{
    auto cxx20 = probe<20>(false);
    auto cxx23 = probe_cxx23(false);
    REQUIRE_FALSE(cxx23.has_value);
    REQUIRE(cxx23.error == cxx20.error);
}

TEST_CASE("both language standards agree on the move_only_function identity and layout", "[compat]")
{
    auto cxx20 = probe_function_layout<20>();
    auto cxx23 = probe_function_layout_cxx23();
    REQUIRE(cxx23.type_name == cxx20.type_name);
    REQUIRE(cxx23.size == cxx20.size);
}

TEST_CASE("a function built in one language standard is invoked in the other", "[compat]")
{
    auto built_in_20 = make_probe_function(5);
    auto built_in_23 = make_function_cxx23(7);
    REQUIRE(call_in_cxx23(built_in_20, 10) == 15);
    REQUIRE(built_in_23(10) == 17);
}

TEST_CASE("a function moved across language standards still invokes", "[compat]")
{
    auto moved = make_function_cxx23(3);
    probe_function target(std::move(moved));
    REQUIRE_FALSE(moved);
    REQUIRE(call_in_cxx23(target, 4) == 7);
}
