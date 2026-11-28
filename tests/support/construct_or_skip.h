#ifndef HPP_GUARD_MDNSPP_SUPPORT_CONSTRUCT_OR_SKIP_H
#define HPP_GUARD_MDNSPP_SUPPORT_CONSTRUCT_OR_SKIP_H

#include "support/skip_or_fail.h"

#include <string>
#include <exception>
#include <string_view>

namespace mdnspp::test_support {

template <typename Construct>
void construct_or_skip(std::string_view what, Construct &&construct)
{
    try
    {
        construct();
    }
    catch(const std::exception &e)
    {
        skip_or_fail(std::string{what} + " construction failed: " + e.what());
    }
}

}

#endif
