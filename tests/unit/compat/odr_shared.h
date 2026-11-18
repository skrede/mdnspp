#ifndef HPP_GUARD_MDNSPP_COMPAT_ODR_SHARED_H
#define HPP_GUARD_MDNSPP_COMPAT_ODR_SHARED_H

#include "mdnspp/detail/compat.h"

#include <string>
#include <cstddef>
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

using probe_function = move_only_function<int32_t(int32_t)>;

struct function_report
{
    std::string type_name;
    std::size_t size;
};

inline probe_function make_probe_function(int32_t addend)
{
    return [addend](int32_t value) { return value + addend; };
}

template <int32_t standard>
function_report probe_function_layout()
{
    return {typeid(probe_function).name(), sizeof(probe_function)};
}

function_report probe_function_layout_cxx23();

probe_function make_function_cxx23(int32_t addend);

int32_t call_in_cxx23(probe_function &fn, int32_t value);

}

#endif
