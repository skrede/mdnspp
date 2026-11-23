#include "fixture.h"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>
#include <cstddef>
#include <utility>
#include <string_view>

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

std::vector<std::byte> with_question(std::vector<std::byte> pkt, std::string_view qname)
{
    std::vector<std::byte> question = *mdnspp::detail::encode_dns_name(qname);
    mdnspp::detail::push_u16_be(question, mdnspp::detail::to_underlying(mdnspp::dns_type::ptr));
    mdnspp::detail::push_u16_be(question, 0x0001);
    pkt.insert(pkt.begin() + 12, question.begin(), question.end());
    pkt[5] = std::byte{0x01}; // qdcount: 0 -> 1
    return pkt;
}

}

TEST_CASE("scoped filtering: PTR for non-watched type is silently dropped", "[monitor]")
{
    bool found_called{false};
    monitor_fixture f{flag_found(found_called)};
    f.watch_and_start({"_http._tcp.local"});

    f.inject(make_ptr_packet("_ftp._tcp.local", "FtpServer._ftp._tcp.local", "ftpserver.local", "10.0.0.1"));

    CHECK_FALSE(found_called);
}

TEST_CASE("scoped filtering: PTR for watched type seeds resolution", "[monitor]")
{
    bool found_called{false};
    monitor_fixture f{flag_found(found_called)};
    f.watch_and_start({"_http._tcp.local"});

    f.inject(make_ptr_packet("_http._tcp.local", "MyServer._http._tcp.local", "myserver.local", "192.168.1.1"));

    CHECK(found_called);
}

TEST_CASE("QR filtering: known-answer records in query packets are not consumed",
          "[monitor][qr-flag]")
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
          "[monitor][qr-flag]")
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

TEST_CASE("QR filtering: a response that carries a question still has its answers resolved", "[monitor][qr-flag]")
{
    bool found_called{false};
    monitor_fixture f{flag_found(found_called)};
    f.watch_and_start({"_http._tcp.local"});

    auto response = make_ptr_packet("_http._tcp.local", "AskSvc._http._tcp.local", "asksvc.local", "10.7.7.7");
    f.inject(with_question(std::move(response), "_http._tcp.local."));

    CHECK(found_called);
    auto snap = f.mon.services();
    REQUIRE(snap.size() == 1);
    CHECK(snap[0].port == 8080);
    CHECK(snap[0].ipv4_addresses == std::vector<std::string>{"10.7.7.7"});
}
