#ifndef HPP_GUARD_MDNSPP_ASIO_RECEIVE_HELPERS_H
#define HPP_GUARD_MDNSPP_ASIO_RECEIVE_HELPERS_H

#include "default_conformance/receive_helpers.h"

#include "support/skip_or_fail.h"

#include "mdnspp/policy.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/socket_options.h"

#include "mdnspp/asio/asio_socket.h"

#include <asio.hpp>

#include <span>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <system_error>

template <typename Send>
std::optional<mdnspp::recv_metadata> asio_receive_with(const mdnspp::socket_options &opts, Send send)
{
    asio::io_context io;
    std::error_code ec;
    std::optional<mdnspp::recv_metadata> received;
    mdnspp::asio_socket socket{io, opts, ec};
    if(ec)
        mdnspp::test_support::skip_or_fail("asio_socket construction failed: " + ec.message());
    socket.async_receive([&](std::error_code result, const mdnspp::recv_metadata &meta, std::span<std::byte>)
    {
        if(!result)
            received = meta;
    });
    send(socket, bound_port(socket.native_handle()));
    const std::chrono::steady_clock::time_point until = std::chrono::steady_clock::now() + receive_deadline;
    while(!received && io.run_one_until(until) > 0)
        continue;
    return received;
}

inline std::optional<mdnspp::recv_metadata> asio_receive_from_self(const mdnspp::socket_options &opts, const char *to)
{
    return asio_receive_with(opts, [to](mdnspp::asio_socket &socket, uint16_t port)
    {
        socket.send(mdnspp::endpoint{to, port}, probe_payload);
    });
}

#endif
