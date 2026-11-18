#include "compat/odr_shared.h"

namespace mdnspp::test_support {

odr_report probe_cxx23(bool succeed)
{
    return probe<23>(succeed);
}

function_report probe_function_layout_cxx23()
{
    return probe_function_layout<23>();
}

probe_function make_function_cxx23(int32_t addend)
{
    return make_probe_function(addend);
}

int32_t call_in_cxx23(probe_function &fn, int32_t value)
{
    return fn(value);
}

}
