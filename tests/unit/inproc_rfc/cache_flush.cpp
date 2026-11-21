#include "helpers.h"

#include "mdnspp/cache_options.h"

#include "mdnspp/detail/dns_response.h"

#include <catch2/generators/catch_generators.hpp>
#include <catch2/catch_test_macros.hpp>

#include <vector>
#include <optional>

namespace {

cache_options count_flushes(int32_t &flushes)
{
    cache_options opts;
    opts.on_cache_flush = [&flushes](const cache_entry &, std::vector<cache_entry> flushed)
    {
        if(!flushed.empty())
            ++flushes;
    };
    return opts;
}

// RFC 6762 section 9: the injected stale A record (our hostname, different rdata) is a conflict; keeping the name
// makes the server re-probe and then re-announce the authoritative records.
service_options keep_name_on_conflict(std::chrono::milliseconds probe_delay)
{
    service_options opts;
    opts.respond_to_meta_queries = false;
    opts.probe_initial_delay_max = probe_delay;
    opts.on_conflict = [](std::string_view name, uint32_t, conflict_type) -> std::optional<std::string>
    {
        return std::string(name);
    };
    return opts;
}

service_info flush_service(std::string_view ipv4 = "192.168.1.1")
{
    return make_service("FlushServer._http._tcp.local.", "_http._tcp.local.", "flushserver.local.", 9300, ipv4);
}

struct flush_fixture
{
    inproc_harness h;
    int32_t found_a;
    int32_t found_b;
    int32_t flush_a;
    int32_t flush_b;
    live_server live;
    inproc_monitor monitor_a;
    inproc_monitor monitor_b;

    explicit flush_fixture(std::chrono::milliseconds probe_delay)
        : h{}
        , found_a{0}
        , found_b{0}
        , flush_a{0}
        , flush_b{0}
        , live{h, flush_service(), keep_name_on_conflict(probe_delay), fast_response_opts()}
        , monitor_a{h.make_monitor(count_found(found_a), {}, fast_scheduler_opts(), count_flushes(flush_a))}
        , monitor_b{h.make_monitor(count_found(found_b), {}, fast_scheduler_opts(), count_flushes(flush_b))}
    {
    }

    void discover()
    {
        monitor_a.watch("_http._tcp.local.");
        monitor_b.watch("_http._tcp.local.");
        monitor_a.async_start();
        monitor_b.async_start();
        h.executor.drain();
        h.advance(200ms);
        h.advance(10ms);
    }

    // The injector's endpoint is a different origin than the server's.
    void inject_stale_address()
    {
        auto packet = detail::build_dns_response(flush_service("10.0.0.99"), dns_type::a, service_options{});
        inject(h, std::span<const std::byte>(packet));
        h.executor.drain();
    }

    // RFC 6762 section 10.2 exempts records received within the last second from a cache flush; with a 0 ms re-probe
    // delay the first re-announcement lands inside that window and only the second one evicts the stale A record.
    void advance_until_flushed()
    {
        for(int32_t step = 0; step < 12 && (flush_a < 1 || flush_b < 1); ++step)
            h.advance(250ms);
    }
};

}

TEST_CASE("Cache-flush propagation across monitors", "[inproc][rfc]")
{
    auto probe_delay = GENERATE(0ms, service_options{}.probe_initial_delay_max);
    INFO("re-probe delay " << probe_delay.count() << " ms");
    flush_fixture f{probe_delay};

    f.discover();
    REQUIRE(f.found_a >= 1);
    REQUIRE(f.found_b >= 1);

    f.inject_stale_address();
    f.advance_until_flushed();

    CHECK(f.flush_a >= 1);
    CHECK(f.flush_b >= 1);
    // The cache flush refreshed the record rather than removing the still-live service.
    CHECK(f.found_a >= 1);
    CHECK(f.found_b >= 1);
}
