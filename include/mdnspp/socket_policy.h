#ifndef MDNSPP_SOCKET_POLICY_H
#define MDNSPP_SOCKET_POLICY_H

#include <span>
#include <cstddef>
#include <functional>
#include "mdnspp/endpoint.h"

namespace mdnspp {

template<typename S>
concept SocketPolicy =
    requires(S& s,
             endpoint ep,
             std::span<const std::byte> send_data,
             std::function<void(std::span<std::byte>, endpoint)> handler)
    {
        { s.async_receive(handler) } -> std::same_as<void>;
        { s.send(ep, send_data) }   -> std::same_as<void>;
        { s.close() }               -> std::same_as<void>;
    };

} // namespace mdnspp

#endif // MDNSPP_SOCKET_POLICY_H
