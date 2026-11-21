#include "helpers.h"

using mdnspp::detail::read_dns_name;
using mdnspp::detail::encode_dns_name;

namespace {

using encoded_name = mdnspp::detail::expected<std::vector<std::byte>, mdnspp::mdns_error>;

void check_round_trip(const std::string &presentation, const encoded_name &encoded)
{
    THEN("decoding restores the escaped presentation form exactly")
    {
        REQUIRE(encoded.has_value());
        auto decoded = read_dns_name(std::span<const std::byte>(*encoded), 0);
        REQUIRE(decoded.has_value());
        REQUIRE(*decoded == presentation);
    }

    THEN("the escaped form encodes three labels, not four")
    {
        auto unescaped = encode_dns_name("Dr. Smith._http._tcp.local.");
        REQUIRE(encoded.has_value());
        REQUIRE(unescaped.has_value());
        REQUIRE(*encoded != *unescaped);
    }
}

}

SCENARIO("encode_dns_name and read_dns_name round-trip an instance label containing a dot",
         "[dns_read][encode_dns_name][escaping]")
{
    GIVEN("the RFC 6763 section 4.3 instance name Dr\\. Smith._http._tcp.local.")
    {
        const std::string presentation = "Dr\\. Smith._http._tcp.local.";
        auto encoded = encode_dns_name(presentation);

        THEN("the first label is the 9 unescaped bytes 'Dr. Smith'")
        {
            REQUIRE(encoded.has_value());
            REQUIRE(static_cast<uint8_t>((*encoded)[0]) == 9);
            std::string label;
            for(std::size_t i = 1; i <= 9; ++i)
                label += static_cast<char>(static_cast<uint8_t>((*encoded)[i]));
            REQUIRE(label == "Dr. Smith");
        }

        check_round_trip(presentation, encoded);
    }
}

SCENARIO("encode_dns_name preserves original byte case", "[dns_read][encode_dns_name][case]")
{
    GIVEN("a mixed-case instance name")
    {
        auto encoded = encode_dns_name("MyPrinter._ipp._tcp.local.");
        THEN("the wire bytes carry the original case (RFC 6763 section 4.1)")
        {
            REQUIRE(encoded.has_value());
            auto decoded = read_dns_name(std::span<const std::byte>(*encoded), 0);
            REQUIRE(decoded.has_value());
            REQUIRE(*decoded == "MyPrinter._ipp._tcp.local.");
        }
    }
}

SCENARIO("encode_dns_name rejects empty labels", "[dns_read][encode_dns_name][escaping]")
{
    GIVEN("the name a..b.local with an embedded empty label")
    {
        auto result = encode_dns_name("a..b.local");
        THEN("it returns invalid_name instead of emitting a zero-length label")
        {
            REQUIRE_FALSE(result.has_value());
            REQUIRE(result.error() == mdnspp::mdns_error::invalid_name);
        }
    }

    GIVEN("a name with a leading dot")
    {
        auto result = encode_dns_name(".a.local");
        THEN("it returns invalid_name") { REQUIRE_FALSE(result.has_value()); }
    }
}

SCENARIO("encode_dns_name parses backslash-DDD decimal escapes", "[dns_read][encode_dns_name][escaping]")
{
    GIVEN("the escape \\009 (horizontal tab) inside a label")
    {
        auto result = encode_dns_name("a\\009b.local.");
        THEN("the label contains the raw byte 0x09")
        {
            REQUIRE(result.has_value());
            REQUIRE(static_cast<uint8_t>((*result)[0]) == 3);
            REQUIRE(static_cast<uint8_t>((*result)[2]) == 0x09);
        }
    }

    GIVEN("malformed decimal escapes")
    {
        THEN("a truncated escape is rejected") { REQUIRE_FALSE(encode_dns_name("a\\09.local").has_value()); }
        THEN("a value above 255 is rejected") { REQUIRE_FALSE(encode_dns_name("a\\999.local").has_value()); }
        THEN("a dangling backslash is rejected") { REQUIRE_FALSE(encode_dns_name("a.local\\").has_value()); }
    }
}
