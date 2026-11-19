#include "fuzz/fuzz_input.h"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstdint>

using mdnspp::fuzz::input_reader;

TEST_CASE("input_reader decodes two bytes high byte first", "[fuzz][input_reader]")
{
    constexpr std::array<uint8_t, 2> bytes{0x12, 0x34};
    input_reader reader{bytes.data(), bytes.size()};

    REQUIRE(reader.u16() == 0x1234);
    REQUIRE(reader.left() == 0);
}

TEST_CASE("input_reader decodes four bytes high byte first", "[fuzz][input_reader]")
{
    constexpr std::array<uint8_t, 4> bytes{0x12, 0x34, 0x56, 0x78};
    input_reader reader{bytes.data(), bytes.size()};

    REQUIRE(reader.u32() == 0x12345678u);
    REQUIRE(reader.left() == 0);
}

TEST_CASE("input_reader yields zero past the end of the input", "[fuzz][input_reader]")
{
    constexpr std::array<uint8_t, 1> bytes{0xab};
    input_reader reader{bytes.data(), bytes.size()};

    REQUIRE(reader.u8() == 0xab);
    REQUIRE(reader.left() == 0);
    REQUIRE(reader.u8() == 0);
    REQUIRE(reader.u16() == 0);
    REQUIRE(reader.u32() == 0);
    REQUIRE(reader.left() == 0);
}
