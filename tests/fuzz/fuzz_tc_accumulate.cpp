#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"

#include "mdnspp/detail/dns_frame.h"
#include "mdnspp/detail/tc_accumulator.h"

#include <fuzzer/FuzzedDataProvider.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace {

// Deterministic clock: time advances only when the harness advances it, so
// the deadline and cap logic is reproducible from the fuzz input alone.
struct fuzz_clock
{
    using rep = std::chrono::milliseconds::rep;
    using period = std::chrono::milliseconds::period;
    using duration = std::chrono::milliseconds;
    using time_point = std::chrono::time_point<fuzz_clock>;
    static constexpr bool is_steady = true;

    static time_point now() noexcept { return time_point{duration{current_ms}}; }

    static inline rep current_ms{0};
};

using accumulator = mdnspp::detail::tc_accumulator<fuzz_clock>;

// The endpoint index range exceeds max_pending_sources (64), so the drop-oldest cap path is exercised.
void accumulate_packet(FuzzedDataProvider &fdp, accumulator &acc)
{
    auto idx = fdp.ConsumeIntegralInRange<uint16_t>(0, 127);
    mdnspp::endpoint source{"10.0.0." + std::to_string(idx),
                            static_cast<uint16_t>(5353 + idx)};
    auto wait = std::chrono::milliseconds{
        fdp.ConsumeIntegralInRange<int64_t>(0, 1000)};
    auto packet = fdp.ConsumeBytes<uint8_t>(
        fdp.ConsumeIntegralInRange<size_t>(0, 160));
    auto buf = std::span<const std::byte>(
        reinterpret_cast<const std::byte *>(packet.data()), packet.size());
    std::vector<mdnspp::mdns_record_variant> records;
    mdnspp::detail::walk_dns_frame(buf, source,
        [&](mdnspp::mdns_record_variant rv) { records.push_back(std::move(rv)); });
    acc.accumulate(source, std::move(records), wait);
}

void advance_and_expire(FuzzedDataProvider &fdp, accumulator &acc)
{
    fuzz_clock::current_ms += fdp.ConsumeIntegralInRange<int64_t>(0, 2000);
    auto expired = acc.take_expired(fuzz_clock::now());
    (void)expired;
}

void inspect(const accumulator &acc)
{
    (void)acc.next_deadline();
    (void)acc.size();
    (void)acc.empty();
}

void apply_operation(FuzzedDataProvider &fdp, accumulator &acc)
{
    switch(fdp.ConsumeIntegralInRange<uint8_t>(0, 3))
    {
    case 0:
        accumulate_packet(fdp, acc);
        break;
    case 1:
        advance_and_expire(fdp, acc);
        break;
    case 2:
        inspect(acc);
        break;
    case 3:
        acc.clear();
        break;
    }
}

}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    fuzz_clock::current_ms = 0;
    accumulator acc;

    FuzzedDataProvider fdp(data, size);

    // Bound the operation count so large inputs stay fast.
    for(uint32_t op = 0; op < 128 && fdp.remaining_bytes() > 0; ++op)
        apply_operation(fdp, acc);

    return 0;
}
