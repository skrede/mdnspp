#ifndef HPP_GUARD_MDNSPP_SUPPORT_CONTROL_BUFFER_H
#define HPP_GUARD_MDNSPP_SUPPORT_CONTROL_BUFFER_H

#ifndef _WIN32

#include "mdnspp/detail/native_socket.h"

#include <span>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace mdnspp::test_support {

class control_buffer
{
public:
    control_buffer()
        : m_storage{}
        , m_msg{}
        , m_used{0}
    {
        m_msg.msg_control = m_storage.data();
    }

    template <typename T>
    void add(int32_t level, int32_t type, const T &value)
    {
        add_raw(level, type, std::as_bytes(std::span<const T, 1>{&value, 1}));
    }

    void add_raw(int32_t level, int32_t type, std::span<const std::byte> payload)
    {
        auto *cmsg = reinterpret_cast<cmsghdr *>(m_storage.data() + m_used);
        cmsg->cmsg_level = level;
        cmsg->cmsg_type = type;
        cmsg->cmsg_len = static_cast<decltype(cmsg->cmsg_len)>(CMSG_LEN(payload.size()));
        std::memcpy(CMSG_DATA(cmsg), payload.data(), payload.size());
        m_used += CMSG_SPACE(payload.size());
        m_msg.msg_controllen = static_cast<decltype(m_msg.msg_controllen)>(m_used);
    }

    void set_flags(int32_t flags)
    {
        m_msg.msg_flags = flags;
    }

    msghdr &message()
    {
        return m_msg;
    }

private:
    alignas(cmsghdr) std::array<std::byte, 256> m_storage;
    msghdr m_msg;
    std::size_t m_used;
};

}

#endif

#endif
