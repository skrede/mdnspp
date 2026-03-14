#include "mdnspp/dns_name.h"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <string_view>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    std::string_view input(reinterpret_cast<const char *>(data), size);

    try
    {
        mdnspp::dns_name name(input);
        mdnspp::dns_name name2(name.str());

        // Idempotency: applying normalization twice yields the same result
        assert(name.str() == name2.str());
    }
    catch(...)
    {
        // dns_name may throw on invalid input — that is correct behavior
    }

    return 0;
}
