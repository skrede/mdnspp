#include "helpers.h"

#include "mdnspp/detail/dns_query.h"

#include <catch2/catch_test_macros.hpp>

#include <vector>
#include <string_view>

namespace {

service_options track_tc_continuation(bool &fired, std::size_t &merged)
{
    service_options opts;
    opts.respond_to_meta_queries = false;
    opts.suppress_known_answers = true;
    opts.on_tc_continuation = [&fired, &merged](const endpoint &, std::size_t count)
    {
        fired = true;
        merged = count;
    };
    return opts;
}

mdns_options fixed_tc_wait()
{
    mdns_options opts;
    opts.response_delay_min = 1ms;
    opts.response_delay_max = 1ms;
    opts.tc_wait_min = 400ms;
    opts.tc_wait_max = 400ms;
    return opts;
}

// The TC bit (RFC 1035 section 4.1.1) on both packets makes the server accumulate the second one instead of treating
// it as a fresh query.
std::vector<std::byte> truncated_query(std::span<const mdns_record_variant> known_answers)
{
    auto packet = detail::build_dns_query("_http._tcp.local.", dns_type::ptr, known_answers);
    packet[2] = static_cast<std::byte>(std::to_integer<uint8_t>(packet[2]) | 0x02u);
    return packet;
}

template <typename Record>
Record known_answer(std::string_view name)
{
    Record record;
    record.name = name;
    record.ttl = 4500;
    record.rclass = dns_class::in;
    return record;
}

std::vector<std::byte> instance_records_query()
{
    auto ptr = known_answer<record_ptr>("_http._tcp.local.");
    ptr.ptr_name = "tcserver._http._tcp.local.";
    auto srv = known_answer<record_srv>("tcserver._http._tcp.local.");
    srv.srv_name = "tcserver.local.";
    srv.port = 9200;
    auto txt = known_answer<record_txt>("tcserver._http._tcp.local.");
    const std::vector<mdns_record_variant> known_answers{ptr, srv, txt};
    return truncated_query(known_answers);
}

std::vector<std::byte> address_record_query()
{
    auto a = known_answer<record_a>("tcserver.local.");
    a.sender_address = "192.168.1.1";
    a.address_string = "192.168.1.1";
    const std::vector<mdns_record_variant> known_answers{a};
    return truncated_query(known_answers);
}

struct tc_fixture
{
    inproc_harness h;
    std::size_t tc_merged;
    bool tc_fired;
    int32_t ptrs;
    live_server live;
    inproc_observer observer;

    tc_fixture()
        : h{}
        , tc_merged{0}
        , tc_fired{false}
        , ptrs{0}
        , live{h, make_service("TcServer._http._tcp.local.", "_http._tcp.local.", "tcserver.local.", 9200),
               track_tc_continuation(tc_fired, tc_merged), fixed_tc_wait()}
        , observer{h.make_observer(count_service_ptrs(ptrs))}
    {
        observer.async_observe();
        h.executor.drain();
    }
};

}

// RFC 6762 section 6: a responder defers a TC=1 query and merges the known-answer sections of every TC=1 packet
// from the same sender, then answers the merged query when the TC wait expires. Together the two packets cover every
// record the server would send, so it stays silent.
TEST_CASE("TC bit multi-packet accumulation", "[inproc][rfc]")
{
    tc_fixture f;
    const auto first = instance_records_query();
    const auto continuation = address_record_query();
    {
        // The accumulator keys on the sender, so both packets must leave the same socket.
        inproc_socket<test_clock> injector{f.h.executor};
        injector.send(mdns_multicast_ep(), std::span<const std::byte>(first));
        f.h.executor.drain();
        f.h.advance(200ms);
        CHECK_FALSE(f.tc_fired);
        injector.send(mdns_multicast_ep(), std::span<const std::byte>(continuation));
        f.h.executor.drain();
    }
    f.h.advance(250ms);

    CHECK(f.tc_fired);
    CHECK(f.tc_merged == 4);
    // Only the first packet's answer section carries a PTR; a server response would add a second.
    CHECK(f.ptrs == 1);
}
