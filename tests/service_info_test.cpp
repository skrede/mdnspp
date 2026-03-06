// tests/service_info_test.cpp

#include "mdnspp/service_info.h"

#include "mdnspp/detail/dns_wire.h"

#include "mdnspp/testing/mock_policy.h"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>
#include <cstddef>
#include <optional>

using namespace mdnspp;
using namespace mdnspp::testing;
using namespace mdnspp::detail;

TEST_CASE("service_info struct has all required fields", "[service_info]")
{
    service_info info;
    info.service_name = "MyService._http._tcp.local.";
    info.service_type = "_http._tcp.local.";
    info.hostname = "myhost.local.";
    info.port = 8080;
    info.priority = 0;
    info.weight = 0;
    info.address_ipv4 = "192.168.1.10";
    info.address_ipv6 = std::nullopt;
    info.txt_records = {service_txt{"path", "/api"}};

    REQUIRE(info.service_name == "MyService._http._tcp.local.");
    REQUIRE(info.service_type == "_http._tcp.local.");
    REQUIRE(info.hostname == "myhost.local.");
    REQUIRE(info.port == 8080);
    REQUIRE(info.priority == 0);
    REQUIRE(info.weight == 0);
    REQUIRE(info.address_ipv4.has_value());
    REQUIRE(*info.address_ipv4 == "192.168.1.10");
    REQUIRE_FALSE(info.address_ipv6.has_value());
    REQUIRE(info.txt_records.size() == 1);
    REQUIRE(info.txt_records[0].key == "path");
    REQUIRE(info.txt_records[0].value.has_value());
    REQUIRE(*info.txt_records[0].value == "/api");
}

TEST_CASE("MockSocket::enqueue(packet, endpoint) stores sender and delivers to handler", "[mock_socket][enqueue_with_endpoint]")
{
    mock_executor ex;
    MockSocket sock{ex};

    std::vector<std::byte> pkt = {std::byte{0xAB}, std::byte{0xCD}};
    endpoint sender{"192.168.1.5", 5353};

    sock.enqueue(pkt, sender);

    endpoint received_from;
    std::vector<std::byte> received_data;

    sock.async_receive([&](std::span<std::byte> data, endpoint from)
    {
        received_from = from;
        received_data.assign(data.begin(), data.end());
    });

    REQUIRE(received_from.address == "192.168.1.5");
    REQUIRE(received_from.port == 5353);
    REQUIRE(received_data.size() == 2);
    REQUIRE(received_data[0] == std::byte{0xAB});
    REQUIRE(received_data[1] == std::byte{0xCD});
}

TEST_CASE("MockSocket::enqueue(packet) delivers endpoint{}", "[mock_socket][enqueue_default_endpoint]")
{
    mock_executor ex;
    MockSocket sock{ex};

    std::vector<std::byte> pkt = {std::byte{0x01}};
    sock.enqueue(pkt);

    endpoint received_from{"nonzero", 9999}; // will be overwritten
    sock.async_receive([&](std::span<std::byte>, endpoint from)
    {
        received_from = from;
    });

    REQUIRE(received_from.address == "");
    REQUIRE(received_from.port == 0);
}

TEST_CASE("push_u16_be appends 2 bytes big-endian", "[dns_wire][push_u16_be]")
{
    std::vector<std::byte> buf;
    push_u16_be(buf, 0x1234);

    REQUIRE(buf.size() == 2);
    REQUIRE(static_cast<uint8_t>(buf[0]) == 0x12);
    REQUIRE(static_cast<uint8_t>(buf[1]) == 0x34);
}

TEST_CASE("push_u32_be appends 4 bytes big-endian", "[dns_wire][push_u32_be]")
{
    std::vector<std::byte> buf;
    push_u32_be(buf, 0x12345678);

    REQUIRE(buf.size() == 4);
    REQUIRE(static_cast<uint8_t>(buf[0]) == 0x12);
    REQUIRE(static_cast<uint8_t>(buf[1]) == 0x34);
    REQUIRE(static_cast<uint8_t>(buf[2]) == 0x56);
    REQUIRE(static_cast<uint8_t>(buf[3]) == 0x78);
}
