#ifndef HPP_GUARD_MDNSPP_NIC_GROUP_SNIFFER_H
#define HPP_GUARD_MDNSPP_NIC_GROUP_SNIFFER_H

#include "mdnspp/inproc/inproc_socket.h"
#include "mdnspp/inproc/inproc_executor.h"
#include "mdnspp/inproc/inproc_socket_options.h"

#include "mdnspp/detail/dns_frame.h"
#include "mdnspp/detail/server_question_section.h"

#include "mdnspp/policy.h"
#include "mdnspp/endpoint.h"

#include "mdnspp/testing/test_clock.h"

#include <span>
#include <string>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <system_error>

inline constexpr const char *ipv4_group = "224.0.0.251";
inline constexpr const char *ipv6_group = "ff02::fb";

inline mdnspp::inproc::inproc_socket_options sniffer_options(std::string group)
{
    mdnspp::inproc::inproc_socket_options opts;
    opts.multicast_group = mdnspp::endpoint{std::move(group), 5353};
    return opts;
}

struct group_sniffer
{
    group_sniffer(mdnspp::inproc::inproc_executor<mdnspp::testing::test_clock> &ex, std::string group)
        : queries(0)
        , responses(0)
        , unicast_questions(0)
        , multicast_questions(0)
        , socket(ex, sniffer_options(std::move(group)))
    {
        arm();
    }

    void arm()
    {
        socket.async_receive([this](std::error_code, const mdnspp::recv_metadata &, std::span<std::byte> data)
        {
            // RFC 1035 section 4.1.1: the QR bit separates queries from responses.
            if(data.size() >= 3)
                ++((std::to_integer<uint8_t>(data[2]) & 0x80u) == 0 ? queries : responses);
            count_questions(data);
            arm();
        });
    }

    void count_questions(std::span<const std::byte> data)
    {
        if(data.size() < mdnspp::detail::dns_frame_header_size || (std::to_integer<uint8_t>(data[2]) & 0x80u) != 0)
            return;
        const uint16_t qdcount = mdnspp::detail::read_frame_header(data).qdcount;
        std::size_t offset = mdnspp::detail::dns_frame_header_size;
        for(uint16_t i = 0; i < qdcount; ++i)
        {
            const auto question = mdnspp::detail::read_question(data, offset);
            if(!question)
                return;
            ++((question->qclass & 0x8000u) != 0 ? unicast_questions : multicast_questions);
        }
    }

    int32_t queries;
    int32_t responses;
    int32_t unicast_questions;
    int32_t multicast_questions;
    mdnspp::inproc::inproc_socket<mdnspp::testing::test_clock> socket;
};

struct family_traffic
{
    explicit family_traffic(mdnspp::inproc::inproc_executor<mdnspp::testing::test_clock> &ex)
        : ipv4{ex, ipv4_group}
        , ipv6{ex, ipv6_group}
    {
    }

    group_sniffer ipv4;
    group_sniffer ipv6;
};

#endif
