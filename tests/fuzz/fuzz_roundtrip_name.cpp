#include "mdnspp/dns_name.h"

#include "mdnspp/detail/dns_read.h"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    std::string_view input(reinterpret_cast<const char *>(data), size);

    auto encoded = mdnspp::detail::encode_dns_name(input);
    if(!encoded.has_value())
    {
        // Invalid presentation input must also normalize to the empty name
        assert(mdnspp::dns_name(input).empty());
        return 0;
    }

    // decode(encode(x)) is the canonical escaped presentation of x with
    // original case preserved — identical to dns_name's normalization
    auto encoded_span = std::span<const std::byte>(*encoded);
    auto decoded = mdnspp::detail::read_dns_name(encoded_span, 0);
    assert(decoded.has_value());
    assert(*decoded == mdnspp::dns_name(input).str());

    // encode(decode(wire)) reproduces the wire bytes exactly
    auto re_encoded = mdnspp::detail::encode_dns_name(*decoded);
    assert(re_encoded.has_value());
    assert(*re_encoded == *encoded);

    return 0;
}
