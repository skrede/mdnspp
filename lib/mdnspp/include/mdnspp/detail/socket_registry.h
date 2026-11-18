#ifndef HPP_GUARD_MDNSPP_DETAIL_SOCKET_REGISTRY_H
#define HPP_GUARD_MDNSPP_DETAIL_SOCKET_REGISTRY_H

#include "mdnspp/policy.h"

#include "mdnspp/detail/compat.h"
#include "mdnspp/detail/native_socket.h"

#include <span>
#include <vector>
#include <cstddef>
#include <utility>
#include <algorithm>
#include <system_error>

namespace mdnspp::detail {

using receive_handler = move_only_function<void(std::error_code, const recv_metadata &, std::span<std::byte>)>;

class socket_registry
{
    struct entry
    {
        native_socket_t fd;
        receive_handler handler;
#ifdef _WIN32
        LPFN_WSARECVMSG fn_wsarecvmsg;
#endif
    };

public:
    void add(native_socket_t fd)
    {
        if(contains(fd))
            return;
#ifdef _WIN32
        m_entries.push_back({fd, receive_handler{}, nullptr});
#else
        m_entries.push_back({fd, receive_handler{}});
#endif
    }

#ifdef _WIN32
    void add(native_socket_t fd, LPFN_WSARECVMSG fn_wsarecvmsg)
    {
        add(fd);
        find(fd)->fn_wsarecvmsg = fn_wsarecvmsg;
    }

    LPFN_WSARECVMSG wsarecvmsg(native_socket_t fd) const
    {
        const auto it = find(fd);
        return it == m_entries.end() ? nullptr : it->fn_wsarecvmsg;
    }
#endif

    void remove(native_socket_t fd)
    {
        std::erase_if(m_entries, [fd](const entry &e) { return e.fd == fd; });
    }

    void arm(native_socket_t fd, receive_handler handler)
    {
        if(const auto it = find(fd); it != m_entries.end())
            it->handler = std::move(handler);
    }

    receive_handler take_handler(native_socket_t fd)
    {
        const auto it = find(fd);
        if(it == m_entries.end())
            return receive_handler{};
        return std::exchange(it->handler, nullptr);
    }

    bool contains(native_socket_t fd) const
    {
        return find(fd) != m_entries.end();
    }

    bool armed(native_socket_t fd) const
    {
        const auto it = find(fd);
        return it != m_entries.end() && static_cast<bool>(it->handler);
    }

    void build_pollfds(std::vector<pollfd> &out) const
    {
        for(const entry &e : m_entries)
            if(e.handler)
                out.push_back({e.fd, POLLIN, 0});
    }

private:
    std::vector<entry> m_entries;

    std::vector<entry>::const_iterator find(native_socket_t fd) const
    {
        return std::ranges::find(m_entries, fd, &entry::fd);
    }

    std::vector<entry>::iterator find(native_socket_t fd)
    {
        return std::ranges::find(m_entries, fd, &entry::fd);
    }
};

}

#endif
