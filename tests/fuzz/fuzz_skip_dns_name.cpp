#include "mdnspp/detail/dns_read.h"

#include <cstddef>
#include <cstdint>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    auto buf = std::span<const std::byte>(reinterpret_cast<const std::byte *>(data), size);
    size_t offset = 0;
    (void)mdnspp::detail::skip_dns_name(buf, offset);
    return 0;
}
