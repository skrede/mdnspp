#include "mdnspp/detail/dns_read.h"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    auto buf = std::span<const std::byte>(reinterpret_cast<const std::byte *>(data), size);

    size_t offset = 0;
    bool skipped = mdnspp::detail::skip_dns_name(buf, offset);
    if(skipped)
        assert(offset <= buf.size());

    // skip and read must never disagree on record boundaries: whenever
    // read_dns_name succeeds at offset 0 (necessarily pointer-free, since a
    // pointer at offset 0 cannot be backward), skip_dns_name must succeed too
    auto decoded = mdnspp::detail::read_dns_name(buf, 0);
    if(decoded.has_value())
        assert(skipped);

    return 0;
}
