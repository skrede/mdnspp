#include "mdnspp/detail/dns_read.h"

#include <fuzzer/FuzzedDataProvider.h>

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    auto buf = std::span<const std::byte>(reinterpret_cast<const std::byte *>(data), size);

    // Test from offset 0
    auto result = mdnspp::detail::read_dns_name(buf, 0);
    if(result.has_value())
    {
        assert(result->empty() || result->back() == '.');
        assert(result->size() <= 255);
    }

    // Test from a random offset within the buffer
    if(size > 0)
    {
        FuzzedDataProvider fdp(data, size);
        size_t offset = fdp.ConsumeIntegralInRange<size_t>(0, size);
        auto result2 = mdnspp::detail::read_dns_name(buf, offset);
        if(result2.has_value())
        {
            assert(result2->empty() || result2->back() == '.');
            assert(result2->size() <= 255);
        }
    }

    return 0;
}
