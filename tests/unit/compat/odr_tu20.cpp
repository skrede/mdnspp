#include "compat/odr_shared.h"

#include <catch2/catch_test_macros.hpp>

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
