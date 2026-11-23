#include "interfaces.h"

#include "mdnspp/policy.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/mdns_options.h"

#include "mdnspp/detail/dns_frame.h"
#include "mdnspp/detail/gate_rules.h"
#include "mdnspp/detail/packet_gate.h"

#include "mdnspp/testing/mock_policy.h"

#include <catch2/catch_test_macros.hpp>

#include <span>
#include <array>
#include <vector>
#include <cstddef>
#include <cstdint>

using mdnspp::detail::dns_frame_header;

namespace {

// AA, TC, RD, RA, Z, AD and CD one at a time, then all of them (RFC 6762 sections 18.4 to 18.10).
constexpr std::array<uint16_t, 9> ignored_bits{0x0000, 0x0400, 0x0200, 0x0100, 0x0080, 0x0040, 0x0020, 0x0010, 0x07F0};

dns_frame_header header_with(uint16_t flags)
{
    dns_frame_header header;
    header.flags = flags;
    return header;
}

void collect_misclassified(uint16_t qr, uint16_t opcode, std::vector<uint16_t> &wrong)
{
    for(uint16_t rcode = 0; rcode < 16; ++rcode)
    {
        for(uint16_t bits : ignored_bits)
        {
            const auto flags = static_cast<uint16_t>(qr | (opcode << 11) | bits | rcode);
            if(mdnspp::detail::header_accepted(header_with(flags)) != (opcode == 0 && rcode == 0))
                wrong.push_back(flags);
        }
    }
}

mdnspp::recv_metadata from_group_port()
{
    mdnspp::recv_metadata meta;
    meta.sender = mdnspp::endpoint{"192.0.2.10", 5353};
    return meta;
}

}

TEST_CASE("dns_frame_header reads OPCODE and RCODE from the flags", "[gate][header]")
{
    CHECK(header_with(0x8400).opcode() == 0);
    CHECK(header_with(0x8400).rcode() == 0);
    CHECK(header_with(0x2805).opcode() == 5);
    CHECK(header_with(0x2805).rcode() == 5);
    CHECK(header_with(0xFFFF).opcode() == 15);
    CHECK(header_with(0xFFFF).rcode() == 15);
}

TEST_CASE("only OPCODE 0 with RCODE 0 passes the header rules, whatever QR and the ignored bits", "[gate][header]")
{
    std::vector<uint16_t> wrong;
    for(uint16_t qr : {uint16_t{0x0000}, uint16_t{0x8000}})
    {
        for(uint16_t opcode = 0; opcode < 16; ++opcode)
            collect_misclassified(qr, opcode, wrong);
    }
    CHECK(wrong.empty());
}

TEST_CASE("packet_gate drops data shorter than a DNS header", "[gate][header]")
{
    mdnspp::detail::packet_gate<mdnspp::testing::mock_policy> gate{5353, 255, mdnspp::ttl_unknown_policy::accept,
                                                                   0, no_interfaces};
    const std::vector<std::byte> header(12, std::byte{0});
    for(std::size_t size = 0; size < header.size(); ++size)
        CHECK_FALSE(gate.admit(from_group_port(), std::span(header).first(size)));
    CHECK(gate.admit(from_group_port(), header));
}

TEST_CASE("packet_gate drops a response with a nonzero RCODE and admits a query with the ignored bits set",
          "[gate][header]")
{
    mdnspp::detail::packet_gate<mdnspp::testing::mock_policy> gate{5353, 255, mdnspp::ttl_unknown_policy::accept,
                                                                   0, no_interfaces};
    std::vector<std::byte> packet(12, std::byte{0});
    packet[2] = std::byte{0x84};
    packet[3] = std::byte{0x03};
    CHECK_FALSE(gate.admit(from_group_port(), packet));
    packet[2] = std::byte{0x07};
    packet[3] = std::byte{0xF0};
    CHECK(gate.admit(from_group_port(), packet));
}
