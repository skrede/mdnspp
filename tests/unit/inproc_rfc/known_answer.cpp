#include "helpers.h"

#include "mdnspp/detail/dns_query.h"

#include <catch2/catch_test_macros.hpp>

#include <vector>

namespace {

service_options count_queries(int32_t &queries)
{
    service_options opts;
    opts.respond_to_meta_queries = false;
    opts.suppress_known_answers = true;
    opts.on_query = [&queries](const endpoint &, dns_type, response_mode) { ++queries; };
    return opts;
}

// Without loopback the server's own multicast announcements cannot feed duplicate-answer suppression and silence its
// response to the plain query.
inproc::inproc_socket_options no_loopback()
{
    inproc::inproc_socket_options opts;
    opts.multicast_loopback = loopback_mode::disabled;
    return opts;
}

// A 4500 s TTL stays above the RFC 6762 section 7.1 threshold of half the server's 4500 s PTR TTL.
std::vector<std::byte> query_with_fresh_known_answer()
{
    record_ptr known;
    known.name = "_http._tcp.local.";
    known.ttl = 4500;
    known.rclass = dns_class::in;
    known.ptr_name = "knownserver._http._tcp.local.";
    std::vector<mdns_record_variant> known_answers{known};
    return detail::build_dns_query("_http._tcp.local.", dns_type::ptr, known_answers);
}

struct known_answer_fixture
{
    inproc_harness h;
    int32_t queries;
    int32_t ptrs;
    live_server live;
    inproc_observer observer;

    known_answer_fixture()
        : h{}
        , queries{0}
        , ptrs{0}
        , live{h, make_service("KnownServer._http._tcp.local.", "_http._tcp.local.", "knownserver.local.", 9000),
               count_queries(queries), fast_response_opts(), no_loopback()}
        , observer{h.make_observer(count_service_ptrs(ptrs))}
    {
        observer.async_observe();
        h.executor.drain();
    }
};

}

// RFC 6762 section 7.1: a responder must not answer when the querier's known-answer list holds that answer with at
// least half its TTL remaining. The observer never queries; it counts the PTR records crossing the bus.
TEST_CASE("Known-answer suppression", "[inproc][rfc]")
{
    known_answer_fixture f;

    auto with_known_answer = query_with_fresh_known_answer();
    inject(f.h, std::span<const std::byte>(with_known_answer));
    f.h.advance(10ms);
    CHECK(f.queries == 1);
    // The query's own answer section carries one PTR; the suppressed server adds none.
    const int32_t after_known_answer = f.ptrs;
    CHECK(after_known_answer == 1);

    auto plain = detail::build_dns_query("_http._tcp.local.", dns_type::ptr);
    inject(f.h, std::span<const std::byte>(plain));
    f.h.advance(2ms);
    f.h.advance(5ms);
    CHECK(f.queries == 2);
    CHECK(f.ptrs > after_known_answer);
}
