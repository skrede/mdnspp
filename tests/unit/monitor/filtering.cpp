#include "fixture.h"

#include <catch2/catch_test_macros.hpp>

#include <vector>
#include <cstddef>

namespace {

std::vector<std::byte> clear_flags(std::vector<std::byte> pkt)
{
    pkt[2] = std::byte{0x00}; // flags: QR=0
    pkt[3] = std::byte{0x00};
    return pkt;
}

std::vector<std::byte> answer_to_authority(std::vector<std::byte> pkt)
{
    pkt[7] = std::byte{0x00}; // ancount: 1 -> 0
    pkt[9] = std::byte{0x01}; // nscount: 0 -> 1
    return pkt;
}

}

TEST_CASE("scoped filtering: PTR for non-watched type is silently dropped", "[monitor][MON-07]")
{
    bool found_called{false};
    monitor_fixture f{flag_found(found_called)};
    f.watch_and_start({"_http._tcp.local"});

    f.inject(make_ptr_packet("_ftp._tcp.local", "FtpServer._ftp._tcp.local", "ftpserver.local", "10.0.0.1"));

    CHECK_FALSE(found_called);
}

TEST_CASE("scoped filtering: PTR for watched type seeds resolution", "[monitor][MON-07]")
{
    bool found_called{false};
    monitor_fixture f{flag_found(found_called)};
    f.watch_and_start({"_http._tcp.local"});

    f.inject(make_ptr_packet("_http._tcp.local", "MyServer._http._tcp.local", "myserver.local", "192.168.1.1"));

    CHECK(found_called);
}

TEST_CASE("QR filtering: known-answer records in query packets are not consumed",
          "[monitor][qr-flag][MON-07]")
{
    bool found_called{false};
    monitor_fixture f{flag_found(found_called)};
    f.watch_and_start({"_http._tcp.local"});

    // With QR/AA cleared the response record set is another querier's known-answer list (RFC 6762 section 7.1).
    f.inject(clear_flags(make_ptr_packet("_http._tcp.local", "KaSvc._http._tcp.local", "kasvc.local", "10.9.9.9")));

    CHECK_FALSE(found_called);
    CHECK(f.mon.services().empty());
}

TEST_CASE("QR filtering: Authority-section probe proposals are never cached",
          "[monitor][qr-flag][MON-07]")
{
    bool found_called{false};
    monitor_fixture f{flag_found(found_called)};
    f.watch_and_start({"_http._tcp.local"});
    // A live partial instance lets SRV records for it pass the relevance filter.
    f.inject(make_ptr_packet("_http._tcp.local", "ProbeSvc._http._tcp.local", "probesvc.local", "10.8.8.8"));
    REQUIRE(found_called);

    // RFC 6762 section 8.2: probe proposals are unconfirmed and MUST NOT be cached; this one advertises another port.
    f.inject(clear_flags(answer_to_authority(make_srv_packet("ProbeSvc._http._tcp.local", "probesvc.local", 9999))));
    auto snap = f.mon.services();
    REQUIRE(snap.size() == 1);
    CHECK(snap[0].port == 8080);

    // Responses carry answers in the Answer and Additional sections only, so Authority records are ignored there too.
    f.inject(answer_to_authority(make_srv_packet("ProbeSvc._http._tcp.local", "probesvc.local", 7777)));
    snap = f.mon.services();
    REQUIRE(snap.size() == 1);
    CHECK(snap[0].port == 8080);
}
