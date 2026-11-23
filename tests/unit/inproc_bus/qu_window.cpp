#include "inproc_bus/helpers.h"

#include "gate/qu_packets.h"

#include "mdnspp/records.h"
#include "mdnspp/basic_querier.h"
#include "mdnspp/query_options.h"
#include "mdnspp/basic_service_discovery.h"

#include "mdnspp/detail/ip_address_ops.h"

#include <catch2/catch_test_macros.hpp>

#include <span>
#include <vector>
#include <cstddef>
#include <algorithm>
#include <string_view>
#include <system_error>

namespace {

using inproc_querier = basic_querier<inproc_test_policy>;

void ignore_results(std::error_code, std::vector<mdns_record_variant>)
{
}

std::size_t pointers_to(const std::vector<mdns_record_variant> &records, std::string_view instance)
{
    return static_cast<std::size_t>(std::ranges::count_if(records, [instance](const mdns_record_variant &rec)
    {
        const auto *ptr = std::get_if<record_ptr>(&rec);
        return ptr != nullptr && ptr->ptr_name.find(instance) != dns_name::npos;
    }));
}

struct querier_session
{
    querier_session(inproc_harness &h, response_mode mode)
        : querier{h.make_querier(query_options{.silence_timeout = 10s})}
    {
        querier.async_query("_http._tcp.local.", dns_type::ptr, ignore_results, mode);
        h.executor.drain();
    }

    void deliver_unicast(std::string_view target)
    {
        const std::vector<std::byte> response = answer_packet({{"_http._tcp.local.", ptr_type, in_class, target}});
        const recv_metadata meta{.sender = endpoint{"127.0.0.200", 5353}, .ttl = uint8_t{255}, .recv_ifindex = 0,
                                 .destination = detail::parse_ip_address(querier.socket().assigned_endpoint().address)};
        querier.socket().deliver(meta, std::span<const std::byte>(response));
    }

    std::size_t reported(std::string_view instance) const { return pointers_to(querier.results(), instance); }

    inproc_querier querier;
};

}

TEST_CASE("an in-process QU querier receives the server's unicast reply", "[inproc][qu-window]")
{
    inproc_harness h;
    live_server srv{h, make_service("Replied._http._tcp.local.", "_http._tcp.local.", "replied.local.", 8080)};
    querier_session session{h, response_mode::unicast};
    h.advance(200ms);

    CHECK(session.reported("Replied") == 1);
}

TEST_CASE("an in-process QU discovery receives the server's unicast reply", "[inproc][qu-window]")
{
    inproc_harness h;
    live_server srv{h, make_service("Found._http._tcp.local.", "_http._tcp.local.", "found.local.", 8080)};
    basic_service_discovery<inproc_test_policy> discovery{h.executor, query_options{.silence_timeout = 10s}};
    discovery.async_discover("_http._tcp.local.", ignore_results, response_mode::unicast);
    h.advance(200ms);

    CHECK(pointers_to(discovery.results(), "Found") == 1);
}

TEST_CASE("an in-process QU querier ignores a unicast answer that arrives after the window", "[inproc][qu-window]")
{
    inproc_harness h;
    querier_session session{h, response_mode::unicast};
    session.deliver_unicast("Early._http._tcp.local.");
    h.advance(2500ms);
    session.deliver_unicast("Late._http._tcp.local.");
    h.executor.drain();

    CHECK(session.reported("Early") == 1);
    CHECK(session.reported("Late") == 0);
}

TEST_CASE("an in-process QM querier ignores a unicast answer to its question", "[inproc][qu-window]")
{
    inproc_harness h;
    querier_session session{h, response_mode::multicast};
    session.deliver_unicast("Unasked._http._tcp.local.");
    h.executor.drain();

    CHECK(session.reported("Unasked") == 0);
}
