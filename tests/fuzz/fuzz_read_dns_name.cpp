#include "mdnspp/detail/dns_read.h"

#include <fuzzer/FuzzedDataProvider.h>

#include <span>
#include <string>
#include <cassert>
#include <cstddef>
#include <cstdint>

static void check_decoded(const std::string &decoded)
{
    // Escaped presentation form: empty (root) or trailing dot
    assert(decoded.empty() || decoded.back() == '.');

    // The decoded form is valid presentation input and survives the wire
    // round trip byte-exactly (case preserved both ways)
    auto encoded = mdnspp::detail::encode_dns_name(decoded);
    assert(encoded.has_value());
    assert(encoded->size() <= 255);

    auto redecoded = mdnspp::detail::read_dns_name(std::span<const std::byte>(*encoded), 0);
    assert(redecoded.has_value());
    assert(*redecoded == decoded);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    auto buf = std::span<const std::byte>(reinterpret_cast<const std::byte *>(data), size);

    // A pointer cannot be the first label, and skip_dns_name accepts any name read_dns_name accepts.
    auto result = mdnspp::detail::read_dns_name(buf, 0);
    if(result.has_value())
    {
        check_decoded(*result);
        size_t offset = 0;
        const bool skipped = mdnspp::detail::skip_dns_name(buf, offset);
        assert(skipped);
    }

    if(size > 0)
    {
        FuzzedDataProvider fdp(data, size);
        size_t offset = fdp.ConsumeIntegralInRange<size_t>(0, size);
        auto result2 = mdnspp::detail::read_dns_name(buf, offset);
        if(result2.has_value())
            check_decoded(*result2);
    }

    return 0;
}
