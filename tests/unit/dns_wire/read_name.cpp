#include "helpers.h"

using mdnspp::detail::read_dns_name;

namespace {

void check_presentation(const char *given, const std::vector<std::byte> &buf, const char *then,
                        const std::string &expected)
{
    GIVEN(given)
    {
        WHEN("read_dns_name decodes it")
        {
            auto result = read_dns_name(std::span<const std::byte>(buf), 0);
            THEN(then)
            {
                REQUIRE(result.has_value());
                REQUIRE(*result == expected);
            }
        }
    }
}

}

SCENARIO("read_dns_name decodes a simple uncompressed DNS name", "[dns_wire][read_dns_name]")
{
    GIVEN("a buffer containing _http._tcp.local in DNS wire label format")
    {
        auto buf = bytes({0x05, '_', 'h', 't', 't', 'p', 0x04, '_', 't', 'c', 'p',
                          0x05, 'l', 'o', 'c', 'a', 'l', 0x00});

        WHEN("read_dns_name is called at offset 0")
        {
            auto result = read_dns_name(std::span<const std::byte>(buf), 0);

            THEN("it returns _http._tcp.local. as FQDN")
            {
                REQUIRE(result.has_value());
                REQUIRE(*result == "_http._tcp.local.");
            }
        }
    }
}

SCENARIO("read_dns_name returns empty string for the root-only name", "[dns_wire][read_dns_name]")
{
    GIVEN("a buffer containing only the root label \\x00")
    {
        auto buf = bytes({0x00});

        WHEN("read_dns_name is called at offset 0")
        {
            auto result = read_dns_name(std::span<const std::byte>(buf), 0);

            THEN("it returns an empty string")
            {
                REQUIRE(result.has_value());
                REQUIRE((*result).empty());
            }
        }
    }
}

SCENARIO("read_dns_name decodes a single-label name", "[dns_wire][read_dns_name]")
{
    GIVEN("a buffer containing the label 'host' followed by root")
    {
        auto buf = bytes({0x04, 'h', 'o', 's', 't', 0x00});

        WHEN("read_dns_name is called at offset 0")
        {
            auto result = read_dns_name(std::span<const std::byte>(buf), 0);

            THEN("it returns host. as FQDN")
            {
                REQUIRE(result.has_value());
                REQUIRE(*result == "host.");
            }
        }
    }
}

SCENARIO("read_dns_name follows a backward compression pointer", "[dns_wire][read_dns_name]")
{
    GIVEN("a buffer where offset 0 has 'local\\x00' and offset 7 has a pointer to offset 0")
    {
        auto buf = bytes({
            0x05, 'l', 'o', 'c', 'a', 'l', 0x00, // offset 0
            0x04, 'h', 'o', 's', 't', 0xC0, 0x00 // offset 7: label, then a pointer to offset 0
        });

        WHEN("read_dns_name is called at offset 7")
        {
            auto result = read_dns_name(std::span<const std::byte>(buf), 7);

            THEN("it follows the pointer and assembles host.local.")
            {
                REQUIRE(result.has_value());
                REQUIRE(*result == "host.local.");
            }
        }
    }
}

SCENARIO("read_dns_name starts directly at a compression pointer", "[dns_wire][read_dns_name]")
{
    GIVEN("a buffer where offset 0 has 'local\\x00' and offset 7 is a bare pointer to offset 0")
    {
        auto buf = bytes({0x05, 'l', 'o', 'c', 'a', 'l', 0x00, 0xC0, 0x00});

        WHEN("read_dns_name is called at the pointer offset 7")
        {
            auto result = read_dns_name(std::span<const std::byte>(buf), 7);

            THEN("it follows the pointer and returns local.")
            {
                REQUIRE(result.has_value());
                REQUIRE(*result == "local.");
            }
        }
    }
}

SCENARIO("read_dns_name escapes special bytes in the presentation form", "[dns_wire][read_dns_name][escaping]")
{
    check_presentation("a wire label containing a dot and a backslash",
                       bytes({0x04, 'a', '.', 'b', '\\', 0x05, 'l', 'o', 'c', 'a', 'l', 0x00}),
                       "the dot and backslash are escaped per RFC 1035 section 5.1", "a\\.b\\\\.local.");
    check_presentation("a wire label containing a non-printable byte", bytes({0x02, 'a', 0x09, 0x00}),
                       "the byte is rendered as a three-digit decimal escape", "a\\009.");
    check_presentation("a wire label containing UTF-8 bytes above 0x7F", bytes({0x03, 'C', 0xC3, 0xA9, 0x00}),
                       "the UTF-8 bytes pass through verbatim", "C\xc3\xa9.");
}
