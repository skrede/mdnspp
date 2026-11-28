#ifndef HPP_GUARD_MDNSPP_COMPAT_EXPECTED_FAMILY_H
#define HPP_GUARD_MDNSPP_COMPAT_EXPECTED_FAMILY_H

#include "mdnspp/detail/compat.h"

#include <tuple>
#include <string>
#include <version>

#if defined(__cpp_lib_expected)
#include <expected>
#endif

namespace mdnspp::test_support {

struct own_family
{
    template <typename T, typename E>
    using expected = mdnspp::expected<T, E>;

    template <typename E>
    using unexpected = mdnspp::unexpected<E>;

    template <typename E>
    using bad_access = mdnspp::bad_expected_access<E>;

    static constexpr auto unexpect_tag = mdnspp::unexpect;
};

#if defined(__cpp_lib_expected)
struct std_family
{
    template <typename T, typename E>
    using expected = std::expected<T, E>;

    template <typename E>
    using unexpected = std::unexpected<E>;

    template <typename E>
    using bad_access = std::bad_expected_access<E>;

    static constexpr auto unexpect_tag = std::unexpect;
};

using expected_families = std::tuple<own_family, std_family>;
#else
using expected_families = std::tuple<own_family>;
#endif

template <typename Family, typename T, typename E>
using of_t = typename Family::template expected<T, E>;

template <typename Family, typename T>
using result_t = typename Family::template expected<T, std::string>;

template <typename Family>
using unexpected_t = typename Family::template unexpected<std::string>;

template <typename Family>
using access_t = typename Family::template bad_access<std::string>;

}

#endif
