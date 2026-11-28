#ifndef HPP_GUARD_MDNSPP_SUPPORT_ALLOC_COUNTER_H
#define HPP_GUARD_MDNSPP_SUPPORT_ALLOC_COUNTER_H

#include <cstdint>

namespace mdnspp::test_support {

uint64_t allocation_count() noexcept;

void reset_allocation_count() noexcept;

}

#endif
