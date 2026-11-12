#include "compat/odr_shared.h"

namespace mdnspp::test_support {

odr_report probe_cxx23(bool succeed)
{
    return probe<23>(succeed);
}

}
