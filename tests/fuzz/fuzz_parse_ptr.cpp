#include "mdnspp/parse.h"

#include <fuzzer/FuzzedDataProvider.h>

#include <cstddef>
#include <cstdint>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    mdnspp::record_metadata meta;
    meta.ttl = fdp.ConsumeIntegral<uint32_t>();
    meta.name_offset = fdp.ConsumeIntegralInRange<size_t>(0, 16);
    meta.record_offset = fdp.ConsumeIntegralInRange<size_t>(0, 64);
    meta.record_length = fdp.ConsumeIntegralInRange<size_t>(0, 128);
    meta.rtype = mdnspp::dns_type::ptr;
    meta.rclass = mdnspp::dns_class::in;

    auto bytes = fdp.ConsumeRemainingBytes<uint8_t>();
    auto buf = std::span<const std::byte>(reinterpret_cast<const std::byte *>(bytes.data()), bytes.size());

    auto result = mdnspp::parse::ptr(buf, meta);
    (void)result;

    return 0;
}
