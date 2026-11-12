#ifndef HPP_GUARD_MDNSPP_COMPAT_ODR_SHARED_H
#define HPP_GUARD_MDNSPP_COMPAT_ODR_SHARED_H

#include "mdnspp/detail/compat.h"

#include <string>
#include <cstdint>
#include <typeinfo>

namespace mdnspp::test_support {

struct odr_report
{
    std::string type_name;
    bool has_value;
    std::string value;
    int32_t error;
};

inline expected<std::string, int32_t> make_probe(bool succeed)
{
    if(succeed)
        return std::string("a value long enough to leave the small string buffer");
    return unexpected(int32_t{7});
}

template <int32_t standard>
odr_report probe(bool succeed)
{
    auto result = make_probe(succeed);
    if(result.has_value())
        return {typeid(result).name(), true, *result, 0};
    return {typeid(result).name(), false, std::string(), result.error()};
}

odr_report probe_cxx23(bool succeed);

}

#endif
