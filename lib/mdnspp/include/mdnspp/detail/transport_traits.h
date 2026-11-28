#ifndef HPP_GUARD_MDNSPP_DETAIL_TRANSPORT_TRAITS_H
#define HPP_GUARD_MDNSPP_DETAIL_TRANSPORT_TRAITS_H

#include <cstdint>
#include <concepts>

namespace mdnspp::detail {

// Only a socket type can declare itself in-process, so nothing a packet carries can grant the exemptions this enables.
template <typename S>
inline constexpr bool is_in_process_v = requires { requires S::in_process_transport; };

template <typename S>
concept reports_interface_index = requires(const S &socket) {
    { socket.interface_index() } -> std::convertible_to<uint32_t>;
};

template <typename S>
uint32_t bound_interface_index(const S &socket) noexcept
{
    if constexpr(reports_interface_index<S>)
        return socket.interface_index();
    else
        return 0;
}

}

#endif
