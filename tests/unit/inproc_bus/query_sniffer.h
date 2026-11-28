#ifndef HPP_GUARD_MDNSPP_INPROC_BUS_QUERY_SNIFFER_H
#define HPP_GUARD_MDNSPP_INPROC_BUS_QUERY_SNIFFER_H

#include "inproc_bus/helpers.h"

#include "mdnspp/inproc/inproc_socket.h"

#include "mdnspp/policy.h"

#include <span>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <system_error>

struct query_sniffer
{
    explicit query_sniffer(inproc_harness &h)
        : packets{}
        , times{}
        , socket{h.executor}
    {
        arm();
    }

    void arm()
    {
        socket.async_receive([this](std::error_code, const recv_metadata &, std::span<std::byte> data)
        {
            // RFC 1035 section 4.1.1: a clear QR bit marks a query.
            if(data.size() >= 3 && (std::to_integer<uint8_t>(data[2]) & 0x80u) == 0)
            {
                packets.push_back(std::vector<std::byte>(data.begin(), data.end()));
                times.push_back(test_clock::now());
            }
            arm();
        });
    }

    // Declared first so the packets outlive the socket and its pending receive handler.
    std::vector<std::vector<std::byte>> packets;
    std::vector<test_clock::time_point> times;
    mdnspp::inproc::inproc_socket<test_clock> socket;
};

#endif
