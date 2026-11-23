#ifndef HPP_GUARD_MDNSPP_DETAIL_TRANSPORT_TRAITS_H
#define HPP_GUARD_MDNSPP_DETAIL_TRANSPORT_TRAITS_H

namespace mdnspp::detail {

// Only a socket type can declare itself in-process, so nothing a packet carries can grant the exemptions this enables.
template <typename S>
inline constexpr bool is_in_process_v = requires { requires S::in_process_transport; };

}

#endif
