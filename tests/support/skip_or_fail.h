#ifndef HPP_GUARD_MDNSPP_SUPPORT_SKIP_OR_FAIL_H
#define HPP_GUARD_MDNSPP_SUPPORT_SKIP_OR_FAIL_H

#include <catch2/catch_test_macros.hpp>

#include <cstdlib>
#include <string_view>

namespace mdnspp::test_support {

// CI sets MDNSPP_REQUIRE_NETWORK so an unavailable network fails the run instead of silently skipping.
inline void skip_or_fail(std::string_view reason)
{
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4996)
#endif
    const char *required = std::getenv("MDNSPP_REQUIRE_NETWORK");
#ifdef _MSC_VER
#pragma warning(pop)
#endif
    if(required != nullptr && *required != '\0')
        FAIL(reason);
    SKIP(reason);
}

}

#endif
