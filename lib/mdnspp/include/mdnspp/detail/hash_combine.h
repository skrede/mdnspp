#ifndef HPP_GUARD_MDNSPP_DETAIL_HASH_COMBINE_H
#define HPP_GUARD_MDNSPP_DETAIL_HASH_COMBINE_H

#include <cstddef>

namespace mdnspp::detail {

// Boost-style hash combining: the golden-ratio constant plus shift mixing
// spreads both operands across all bits, unlike a plain xor/shift which
// collides structurally for small enum-valued fields.
[[nodiscard]] constexpr std::size_t hash_combine(std::size_t seed, std::size_t value) noexcept
{
    return seed ^ (value + static_cast<std::size_t>(0x9e3779b97f4a7c15ULL) + (seed << 6) + (seed >> 2));
}

}

#endif
