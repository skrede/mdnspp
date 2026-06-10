#include "mdnspp/dns_name.h"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <string_view>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    std::string_view input(reinterpret_cast<const char *>(data), size);

    mdnspp::dns_name name(input);
    mdnspp::dns_name name2(name.str());

    // Idempotency: normalizing the canonical form yields the same bytes
    assert(name.str() == name2.str());
    assert(name == name2);
    assert(std::hash<mdnspp::dns_name>{}(name) == std::hash<mdnspp::dns_name>{}(name2));

    return 0;
}
