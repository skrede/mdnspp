#include "fixture.h"

#include "mdnspp/dns_name.h"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>
#include <cstddef>
#include <string_view>

namespace {

constexpr std::string_view instance{"Staged._http._tcp.local."};
constexpr std::string_view host{"staged.local."};

mdnspp::monitor_options record_found(std::vector<mdnspp::resolved_service> &found)
{
    mdnspp::monitor_options opts;
    opts.on_found = [&found](const mdnspp::resolved_service &svc) { found.push_back(svc); };
    return opts;
}

std::vector<std::byte> ptr_only()
{
    return make_single_record_packet("_http._tcp.local.", mdnspp::dns_type::ptr,
                                     *mdnspp::detail::encode_dns_name(instance));
}

std::vector<std::byte> srv_only()
{
    auto target = *mdnspp::detail::encode_dns_name(host);
    return make_single_record_packet(instance, mdnspp::dns_type::srv,
                                     mdnspp::detail::encode_srv_rdata(0, 0, 8080, target));
}

std::vector<std::byte> txt_only()
{
    return make_single_record_packet(instance, mdnspp::dns_type::txt,
                                     mdnspp::detail::encode_txt_records({{"path", "/staged"}}));
}

std::vector<std::byte> a_only()
{
    return make_single_record_packet(host, mdnspp::dns_type::a, *mdnspp::detail::encode_ipv4("10.9.8.7"));
}

void check_resolved(const std::vector<mdnspp::resolved_service> &found)
{
    REQUIRE(found.size() == 1);
    CHECK(found[0].instance_name == mdnspp::dns_name{instance});
    CHECK(found[0].hostname == mdnspp::dns_name{host});
    CHECK(found[0].port == 8080);
    CHECK(found[0].ipv4_addresses == std::vector<std::string>{"10.9.8.7"});
}

}

TEST_CASE("staged resolution: PTR, SRV and A in separate packets fire on_found once, after the A", "[monitor]")
{
    std::vector<mdnspp::resolved_service> found;
    monitor_fixture f{record_found(found)};
    f.watch_and_start({"_http._tcp.local"});

    f.inject(ptr_only());
    CHECK(found.empty());
    f.inject(srv_only());
    CHECK(found.empty());
    f.inject(a_only());
    check_resolved(found);

    f.inject(a_only());
    CHECK(found.size() == 1);
}

TEST_CASE("staged resolution: SRV and TXT before the A keep on_found pending until the A", "[monitor]")
{
    std::vector<mdnspp::resolved_service> found;
    monitor_fixture f{record_found(found)};
    f.watch_and_start({"_http._tcp.local"});

    f.inject(ptr_only());
    f.inject(srv_only());
    CHECK(found.empty());
    f.inject(txt_only());
    CHECK(found.empty());
    f.inject(a_only());
    check_resolved(found);
    REQUIRE(found[0].txt_entries.size() == 1);
    CHECK(found[0].txt_entries[0].key == "path");
    CHECK(found[0].txt_entries[0].value == "/staged");
}
