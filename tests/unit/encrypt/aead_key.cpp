#include "aead_helpers.h"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <utility>
#include <system_error>

namespace {

mdnspp::encrypt::encrypt_options valid_options()
{
    auto raw = make_raw_key();
    mdnspp::encrypt::encrypt_options opts;
    opts.psk       = mdnspp::encrypt::secure_key{raw};
    opts.sender_id = 1;
    return opts;
}

std::error_code invalid_argument()
{
    return std::make_error_code(std::errc::invalid_argument);
}

}

TEST_CASE("secure_key move constructor zeroes source bytes", "[secure_key][move]")
{
    auto raw = make_raw_key(0x42);
    mdnspp::encrypt::secure_key src{raw};

    for(auto b : src.bytes())
        REQUIRE(b == std::byte{0x42});

    mdnspp::encrypt::secure_key dst{std::move(src)};

    for(auto b : src.bytes())  // NOLINT(bugprone-use-after-move) — intentional verification
        REQUIRE(b == std::byte{0});

    for(auto b : dst.bytes())
        REQUIRE(b == std::byte{0x42});
}

TEST_CASE("secure_key move-assign zeroes source and previous destination bytes", "[secure_key][move]")
{
    auto raw_a = make_raw_key(0x42);
    auto raw_b = make_raw_key(0xBB);

    mdnspp::encrypt::secure_key a{raw_a};
    mdnspp::encrypt::secure_key b{raw_b};

    b = std::move(a);

    for(auto byte : a.bytes())  // NOLINT(bugprone-use-after-move)
        REQUIRE(byte == std::byte{0});

    for(auto byte : b.bytes())
        REQUIRE(byte == std::byte{0x42});
}

TEST_CASE("encrypt_options validate succeeds with non-zero sender_id", "[encrypt_options][validate]")
{
    REQUIRE_FALSE(valid_options().validate());
}

TEST_CASE("encrypt_options validate rejects zero sender_id", "[encrypt_options][validate]")
{
    auto opts = valid_options();
    opts.sender_id = 0;
    REQUIRE(opts.validate() == invalid_argument());
}

TEST_CASE("encrypt_options validate rejects all-zero PSK", "[encrypt_options][validate]")
{
    mdnspp::encrypt::encrypt_options opts;
    opts.sender_id = 1;
    REQUIRE(opts.validate() == invalid_argument());
}

TEST_CASE("encrypt_options validate rejects zero replay_window_size", "[encrypt_options][validate]")
{
    auto opts = valid_options();
    opts.replay_window_size = 0;
    REQUIRE(opts.validate() == invalid_argument());
}

TEST_CASE("encrypt_options validate rejects zero max_senders", "[encrypt_options][validate]")
{
    auto opts = valid_options();
    opts.max_senders = 0;
    REQUIRE(opts.validate() == invalid_argument());
    opts.max_senders = 1;
    REQUIRE_FALSE(opts.validate());
}
