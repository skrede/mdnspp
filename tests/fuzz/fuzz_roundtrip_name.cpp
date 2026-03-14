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
    if(encoded.empty())
        return 0;

    auto encoded_span = std::span<const std::byte>(encoded);
    auto decoded = mdnspp::detail::read_dns_name(encoded_span, 0);
    if(!decoded.has_value())
        return 0;

    // Re-encode and re-decode to verify idempotency
    auto re_encoded = mdnspp::detail::encode_dns_name(*decoded);
    auto re_encoded_span = std::span<const std::byte>(re_encoded);
    auto re_decoded = mdnspp::detail::read_dns_name(re_encoded_span, 0);
    if(re_decoded.has_value())
        assert(*decoded == *re_decoded);

    return 0;
}
