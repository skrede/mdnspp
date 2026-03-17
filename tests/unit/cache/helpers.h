#ifndef HPP_GUARD_MDNSPP_CACHE_HELPERS_H
#define HPP_GUARD_MDNSPP_CACHE_HELPERS_H

#include "mdnspp/record_cache.h"

#include "mdnspp/testing/test_clock.h"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <vector>

using namespace mdnspp;
using namespace std::chrono_literals;
using clock_type = mdnspp::testing::test_clock;

namespace {

struct clock_guard
{
    clock_guard() { clock_type::reset(); }
    ~clock_guard() { clock_type::reset(); }
};

inline record_a make_a_record(std::string name, std::string address, uint32_t ttl = 120,
                              dns_class rclass = dns_class::in, bool cache_flush = false)
{
    return record_a{
        .name = std::move(name),
        .ttl = ttl,
        .rclass = rclass,
        .sender_address = "192.168.1.100",
        .cache_flush = cache_flush,
        .address_string = std::move(address),
    };
}

inline record_ptr make_ptr_record(std::string name, std::string ptr_name, uint32_t ttl = 120)
{
    return record_ptr{
        .name = std::move(name),
        .ttl = ttl,
        .rclass = dns_class::in,
        .sender_address = "192.168.1.100",
        .ptr_name = std::move(ptr_name),
    };
}

inline endpoint origin_a()
{
    return endpoint{.address = "192.168.1.100", .port = 5353};
}

inline endpoint origin_b()
{
    return endpoint{.address = "192.168.1.200", .port = 5353};
}

inline endpoint origin_c()
{
    return endpoint{.address = "10.0.0.50", .port = 5353};
}

inline endpoint test_origin()
{
    return origin_a();
}

}

#endif
