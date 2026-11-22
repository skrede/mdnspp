#include "mdnspp/detail/dns_read.h"

#include <span>
#include <cassert>
#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    auto buf = std::span<const std::byte>(reinterpret_cast<const std::byte *>(data), size);

    size_t offset = 0;
    bool skipped = mdnspp::detail::skip_dns_name(buf, offset);
    if(skipped)
        assert(offset <= buf.size());

    // A pointer cannot be the first label, and skip_dns_name accepts any name read_dns_name accepts.
    auto decoded = mdnspp::detail::read_dns_name(buf, 0);
    if(decoded.has_value())
        assert(skipped);

    return 0;
}
