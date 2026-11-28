#ifndef HPP_GUARD_MDNSPP_SUPPORT_SOCKET_REF_H
#define HPP_GUARD_MDNSPP_SUPPORT_SOCKET_REF_H

#include "mdnspp/policy.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/socket_options.h"

#include <span>
#include <cstddef>
#include <utility>
#include <system_error>

namespace mdnspp::test_support {

template <socket_like Target>
class socket_ref
{
public:
    explicit socket_ref(Target &target)
        : m_target(target)
    {
    }

    socket_ref(Target &target, const socket_options &)
        : m_target(target)
    {
    }

    void async_receive(move_only_function<void(std::error_code, const recv_metadata &, std::span<std::byte>)> handler)
    {
        m_target.async_receive(std::move(handler));
    }

    void send(const endpoint &dest, std::span<const std::byte> data)
    {
        m_target.send(dest, data);
    }

    void send(const endpoint &dest, std::span<const std::byte> data, std::error_code &ec)
    {
        m_target.send(dest, data, ec);
    }

    void close()
    {
        m_target.close();
    }

private:
    Target &m_target;
};

}

#endif
