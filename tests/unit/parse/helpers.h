#ifndef HPP_GUARD_MDNSPP_PARSE_HELPERS_H
#define HPP_GUARD_MDNSPP_PARSE_HELPERS_H

#include "mdnspp/parse.h"
#include "mdnspp/records.h"

#include "mdnspp/detail/dns_frame.h"

#include <catch2/catch_test_macros.hpp>

#include <span>
#include <vector>
#include <cstddef>

using namespace mdnspp;
using mdnspp::dns_type;
using mdnspp::dns_class;

inline std::vector<std::byte> bytes(std::initializer_list<unsigned char> vals)
{
    std::vector<std::byte> v;
    v.reserve(vals.size());
    for (auto b : vals)
        v.push_back(static_cast<std::byte>(b));
    return v;
}

#endif
