#include "mdnspp/detail/sockaddr_text.h"
#include "mdnspp/detail/native_sockaddr.h"

#include "mdnspp/endpoint.h"

#include "mdnspp/default/default_socket.h"

#include "support/construct_or_skip.h"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <string>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <system_error>

using namespace mdnspp::detail;
using mdnspp::test_support::construct_or_skip;

namespace {

const std::array<std::byte, 4> payload{};
const mdnspp::endpoint unparsable{"not-an-address", 5353};

sockaddr_storage make_v6(const std::string &text, uint32_t scope)
{
    sockaddr_storage storage{};
    auto &sa = reinterpret_cast<sockaddr_in6 &>(storage);
    sa.sin6_family = AF_INET6;
    sa.sin6_port = htons(5353);
    sa.sin6_scope_id = scope;
    ::inet_pton(AF_INET6, text.c_str(), &sa.sin6_addr);
    return storage;
}

std::string render(const std::string &text, uint32_t scope)
{
    mdnspp::endpoint ep{};
    assign_endpoint(make_v6(text, scope), ep);
    return ep.address;
}

}

TEST_CASE("a link-local IPv6 sender carries its scope id as a numeric zone", "[sockaddr_text]")
{
    REQUIRE(render("fe80::1", 3) == "fe80::1%3");
    REQUIRE(render("febf::1", 4294967295u) == "febf::1%4294967295");
}

TEST_CASE("a global, site-local or unscoped IPv6 sender carries no zone", "[sockaddr_text]")
{
    REQUIRE(render("2001:db8::1", 3) == "2001:db8::1");
    REQUIRE(render("fec0::1", 3) == "fec0::1");
    REQUIRE(render("fe80::1", 0) == "fe80::1");
}

TEST_CASE("default_socket reports an unparsable destination as invalid_argument", "[sockaddr_text][native]")
{
    mdnspp::default_context ctx;
    std::optional<mdnspp::default_socket> sock;
    construct_or_skip("default_socket", [&] { sock.emplace(ctx); });

    std::error_code ec;
    sock->send(unparsable, payload, ec);
    REQUIRE(ec == std::errc::invalid_argument);
}

TEST_CASE("default_socket throwing send throws the code of its error_code overload", "[sockaddr_text][native]")
{
    mdnspp::default_context ctx;
    std::optional<mdnspp::default_socket> sock;
    construct_or_skip("default_socket", [&] { sock.emplace(ctx); });

    std::error_code thrown;
    try
    {
        sock->send(unparsable, payload);
    }
    catch(const std::system_error &e)
    {
        thrown = e.code();
    }
    REQUIRE(thrown == std::errc::invalid_argument);
}

TEST_CASE("a numeric zone sets the scope id of the destination", "[sockaddr_text]")
{
    sockaddr_in6 addr{};
    REQUIRE(parse_ipv6("fe80::1%3", addr));
    REQUIRE(addr.sin6_scope_id == 3);
}

#ifndef _WIN32
TEST_CASE("an interface-name zone resolves to the index of that interface", "[sockaddr_text]")
{
    char name[IF_NAMESIZE]{};
    REQUIRE(::if_indextoname(1, name) != nullptr);

    sockaddr_in6 addr{};
    REQUIRE(parse_ipv6(std::string{"fe80::1%"} + name, addr));
    REQUIRE(addr.sin6_scope_id == 1);
}
#endif

TEST_CASE("an empty, unknown, malformed or over-long destination is rejected", "[sockaddr_text]")
{
    sockaddr_in6 addr6{};
    REQUIRE_FALSE(parse_ipv6("fe80::1%", addr6));
    REQUIRE_FALSE(parse_ipv6("fe80::1%nosuchif0", addr6));
    REQUIRE_FALSE(parse_ipv6("fe80::1%3x", addr6));
    REQUIRE_FALSE(parse_ipv6("fe80::1%" + std::string(300, 'a'), addr6));
    REQUIRE_FALSE(parse_ipv6(std::string(300, 'f'), addr6));
    REQUIRE_FALSE(parse_ipv6(std::string_view{"fe80::1\0x", 9}, addr6));

    sockaddr_in addr4{};
    REQUIRE_FALSE(parse_ipv4("192.0.2.1x", addr4));
    REQUIRE_FALSE(parse_ipv4(std::string(300, '1'), addr4));
    REQUIRE_FALSE(build_sockaddr(unparsable).has_value());
}

TEST_CASE("a rendered link-local sender parses back to its scope id and port", "[sockaddr_text]")
{
    mdnspp::endpoint ep{};
    assign_endpoint(make_v6("fe80::1", 3), ep);

    const std::optional<sockaddr_result> result = build_sockaddr(ep);
    REQUIRE(result.has_value());
    const auto &sa6 = reinterpret_cast<const sockaddr_in6 &>(result->ss);
    REQUIRE(sa6.sin6_family == AF_INET6);
    REQUIRE(sa6.sin6_scope_id == 3);
    REQUIRE(ntohs(sa6.sin6_port) == 5353);
}

TEST_CASE("an IPv4 destination builds an IPv4 socket address", "[sockaddr_text]")
{
    const std::optional<sockaddr_result> result = build_sockaddr(mdnspp::endpoint{"192.0.2.1", 5353});
    REQUIRE(result.has_value());
    REQUIRE(result->len == sizeof(sockaddr_in));
    REQUIRE(reinterpret_cast<const sockaddr_in &>(result->ss).sin_family == AF_INET);
}
