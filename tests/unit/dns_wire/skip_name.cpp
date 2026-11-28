#include "helpers.h"

using mdnspp::detail::skip_dns_name;

SCENARIO("skip_dns_name with pointer where second byte is at end of buffer", "[dns_read][skip_dns_name]")
{
    GIVEN("a 1-byte buffer containing only the pointer tag 0xC0")
    {
        auto buf = bytes({0xC0});
        std::size_t offset = 0;

        WHEN("skip_dns_name is called")
        {
            bool ok = skip_dns_name(std::span<const std::byte>(buf), offset);

            THEN("it returns false because pointer needs 2 bytes")
            {
                REQUIRE_FALSE(ok);
            }
        }
    }
}

SCENARIO("skip_dns_name where label extends past end of buffer", "[dns_read][skip_dns_name]")
{
    GIVEN("a buffer where a label claims 10 bytes but only 3 follow")
    {
        auto buf = bytes({0x0A, 'a', 'b', 'c'});
        std::size_t offset = 0;

        WHEN("skip_dns_name is called")
        {
            bool ok = skip_dns_name(std::span<const std::byte>(buf), offset);

            THEN("it returns false because label overflows buffer")
            {
                REQUIRE_FALSE(ok);
            }
        }
    }
}

SCENARIO("skip_dns_name rejects reserved label tags exactly like read_dns_name",
         "[dns_read][skip_dns_name][safety]")
{
    using mdnspp::detail::read_dns_name;

    GIVEN("a buffer whose first byte carries the reserved 01 tag (0x40)")
    {
        auto buf = bytes({0x40, 'a', 0x00});
        std::size_t offset = 0;
        THEN("skip and read agree on rejection")
        {
            REQUIRE_FALSE(skip_dns_name(std::span<const std::byte>(buf), offset));
            REQUIRE_FALSE(read_dns_name(std::span<const std::byte>(buf), 0).has_value());
        }
    }

    GIVEN("a buffer whose first byte carries the reserved 10 tag (0x80)")
    {
        auto buf = bytes({0x80, 'a', 0x00});
        std::size_t offset = 0;
        THEN("skip and read agree on rejection")
        {
            REQUIRE_FALSE(skip_dns_name(std::span<const std::byte>(buf), offset));
            REQUIRE_FALSE(read_dns_name(std::span<const std::byte>(buf), 0).has_value());
        }
    }
}
