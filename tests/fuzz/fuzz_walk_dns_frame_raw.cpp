#include "mdnspp/endpoint.h"
#include "mdnspp/detail/dns_frame.h"

#include <cstddef>
#include <cstdint>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    auto buf = std::span<const std::byte>(reinterpret_cast<const std::byte *>(data), size);
    mdnspp::endpoint sender{};
    mdnspp::detail::walk_dns_frame(buf, sender, [](auto &&) {});
    return 0;
}
