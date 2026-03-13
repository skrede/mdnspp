#include "mdnspp/detail/dns_read.h"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <string_view>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    std::string_view input(reinterpret_cast<const char *>(data), size);
    auto result = mdnspp::detail::encode_dns_name(input);
    if(!result.empty())
        assert(result.back() == std::byte{0x00});
    return 0;
}
