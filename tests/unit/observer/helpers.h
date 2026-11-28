#ifndef HPP_GUARD_MDNSPP_OBSERVER_HELPERS_H
#define HPP_GUARD_MDNSPP_OBSERVER_HELPERS_H

#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/basic_observer.h"
#include "mdnspp/callback_types.h"
#include "mdnspp/socket_options.h"
#include "mdnspp/observer_options.h"

#include "mdnspp/testing/mock_policy.h"

#include "support/wire_bytes.h"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <system_error>

using namespace mdnspp;
using namespace mdnspp::testing;
using namespace std::chrono_literals;
using mdnspp::test_support::bytes;
using mdnspp::test_support::push_u16_be;
using mdnspp::test_support::push_u32_be;
using mdnspp::test_support::encode_name;

inline std::vector<std::byte> make_ptr_response(std::string_view owner,
                                                std::string_view target)
{
    std::vector<std::byte> pkt;

    push_u16_be(pkt, 0x0000);
    push_u16_be(pkt, 0x8400);
    push_u16_be(pkt, 0x0000);
    push_u16_be(pkt, 0x0001);
    push_u16_be(pkt, 0x0000);
    push_u16_be(pkt, 0x0000);

    auto owner_enc = encode_name(owner);
    auto target_enc = encode_name(target);

    pkt.insert(pkt.end(), owner_enc.begin(), owner_enc.end());
    push_u16_be(pkt, 12);
    push_u16_be(pkt, 0x0001);
    push_u32_be(pkt, 4500);
    push_u16_be(pkt, static_cast<uint16_t>(target_enc.size()));
    pkt.insert(pkt.end(), target_enc.begin(), target_enc.end());

    return pkt;
}

inline std::vector<std::byte> make_a_response(std::string_view owner,
                                              uint8_t a, uint8_t b,
                                              uint8_t c, uint8_t d)
{
    std::vector<std::byte> pkt;

    push_u16_be(pkt, 0x0000);
    push_u16_be(pkt, 0x8400);
    push_u16_be(pkt, 0x0000);
    push_u16_be(pkt, 0x0001);
    push_u16_be(pkt, 0x0000);
    push_u16_be(pkt, 0x0000);

    auto owner_enc = encode_name(owner);
    pkt.insert(pkt.end(), owner_enc.begin(), owner_enc.end());
    push_u16_be(pkt, 1);
    push_u16_be(pkt, 0x0001);
    push_u32_be(pkt, 120);
    push_u16_be(pkt, 4);
    pkt.push_back(static_cast<std::byte>(a));
    pkt.push_back(static_cast<std::byte>(b));
    pkt.push_back(static_cast<std::byte>(c));
    pkt.push_back(static_cast<std::byte>(d));

    return pkt;
}

inline observer_options ignore_records()
{
    return observer_options{.on_record = [](const endpoint &, const mdns_record_variant &) {}};
}

inline observer_options count_records(uint32_t &count)
{
    return observer_options{.on_record = [&count](const endpoint &, const mdns_record_variant &) { ++count; }};
}

struct observation_outcome
{
    observation_outcome()
        : ec{}
        , fired{false}
    {
    }

    std::error_code ec;
    bool fired;
};

inline observer_completion_handler record_into(observation_outcome &out)
{
    return [&out](std::error_code ec)
    {
        out.fired = true;
        out.ec = ec;
    };
}

struct observer_fixture
{
    observer_fixture()
        : ex{}
        , records{}
        , senders{}
        , obs{ex, observer_options{.on_record = [this](const endpoint &ep, const mdns_record_variant &rec)
          {
              records.push_back(rec);
              senders.push_back(ep);
          }}}
    {
    }

    mock_executor ex;
    std::vector<mdns_record_variant> records;
    std::vector<endpoint> senders;
    basic_observer<mock_policy> obs;
};

#endif
