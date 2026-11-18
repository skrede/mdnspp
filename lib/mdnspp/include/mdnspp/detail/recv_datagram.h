#ifndef HPP_GUARD_MDNSPP_DETAIL_RECV_DATAGRAM_H
#define HPP_GUARD_MDNSPP_DETAIL_RECV_DATAGRAM_H

#include "mdnspp/detail/native_socket.h"
#include "mdnspp/detail/recv_ancillary.h"

#include "mdnspp/policy.h"

#include <span>
#include <array>
#include <cerrno>
#include <cstddef>
#include <system_error>

namespace mdnspp::detail {

struct datagram_result
{
    std::error_code ec;
    std::size_t size;
    bool truncated;
    bool would_block;
    recv_metadata meta;
};

inline datagram_result truncated_datagram()
{
    datagram_result result{};
    result.truncated = true;
    return result;
}

inline datagram_result datagram_with_metadata(std::size_t size, const sockaddr_storage &sender,
                                              const ancillary_data &ancillary)
{
    datagram_result result{};
    result.size = size;
    result.meta = recv_metadata{
        .sender = endpoint_from_sockaddr(sender),
        .ttl = ancillary.ttl,
        .recv_ifindex = ancillary.ifindex,
    };
    return result;
}

#ifdef _WIN32

inline datagram_result classify_wsa_error(int err)
{
    datagram_result result{};
    result.would_block = err == WSAEWOULDBLOCK;
    result.truncated = err == WSAEMSGSIZE;
    if(!result.would_block && !result.truncated)
        result.ec = std::error_code(err, std::system_category());
    return result;
}

inline datagram_result recv_with_wsarecvmsg(native_socket_t fd, std::span<std::byte> buf,
                                            LPFN_WSARECVMSG fn_wsarecvmsg)
{
    sockaddr_storage sender{};
    WSABUF data_buf{static_cast<ULONG>(buf.size()), reinterpret_cast<char *>(buf.data())};
    alignas(WSACMSGHDR) std::array<std::byte, 64> ctrl_buf{};

    WSAMSG wmsg{};
    wmsg.name = reinterpret_cast<LPSOCKADDR>(&sender);
    wmsg.namelen = sizeof(sender);
    wmsg.lpBuffers = &data_buf;
    wmsg.dwBufferCount = 1;
    wmsg.Control.buf = reinterpret_cast<char *>(ctrl_buf.data());
    wmsg.Control.len = static_cast<ULONG>(ctrl_buf.size());

    DWORD received = 0;
    if(fn_wsarecvmsg(fd, &wmsg, &received, nullptr, nullptr) == SOCKET_ERROR)
        return classify_wsa_error(::WSAGetLastError());
    if(wmsg.dwFlags & MSG_PARTIAL)
        return truncated_datagram();
    return datagram_with_metadata(received, sender, parse_ancillary(wmsg));
}

inline datagram_result recv_with_recvfrom(native_socket_t fd, std::span<std::byte> buf)
{
    sockaddr_storage sender{};
    int sender_len = sizeof(sender);
    const int received = ::recvfrom(fd, reinterpret_cast<char *>(buf.data()),
                                    static_cast<int>(buf.size()), 0,
                                    reinterpret_cast<sockaddr *>(&sender), &sender_len);
    if(received == SOCKET_ERROR)
        return classify_wsa_error(::WSAGetLastError());
    return datagram_with_metadata(static_cast<std::size_t>(received), sender, ancillary_data{});
}

inline datagram_result recv_datagram(native_socket_t fd, std::span<std::byte> buf,
                                     LPFN_WSARECVMSG fn_wsarecvmsg)
{
    if(fn_wsarecvmsg)
        return recv_with_wsarecvmsg(fd, buf, fn_wsarecvmsg);
    return recv_with_recvfrom(fd, buf);
}

#else

inline datagram_result classify_recv_error(int err)
{
    datagram_result result{};
    result.would_block = err == EAGAIN || err == EWOULDBLOCK || err == EINTR;
    if(!result.would_block)
        result.ec = std::error_code(err, std::generic_category());
    return result;
}

inline datagram_result recv_datagram(native_socket_t fd, std::span<std::byte> buf)
{
    sockaddr_storage sender{};
    iovec iov{buf.data(), buf.size()};
    alignas(cmsghdr) std::array<std::byte, 64> ctrl_buf{};

    msghdr msg{};
    msg.msg_name = &sender;
    msg.msg_namelen = sizeof(sender);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = ctrl_buf.data();
    msg.msg_controllen = ctrl_buf.size();

    const ssize_t received = ::recvmsg(fd, &msg, 0);
    if(received < 0)
        return classify_recv_error(errno);
#ifdef MSG_TRUNC
    if(msg.msg_flags & MSG_TRUNC)
        return truncated_datagram();
#endif
    return datagram_with_metadata(static_cast<std::size_t>(received), sender, parse_ancillary(msg));
}

#endif

}

#endif
