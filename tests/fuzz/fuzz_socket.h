#ifndef HPP_GUARD_MDNSPP_FUZZ_FUZZ_SOCKET_H
#define HPP_GUARD_MDNSPP_FUZZ_FUZZ_SOCKET_H

#include "mdnspp/policy.h"

#include <span>
#include <queue>
#include <vector>
#include <cstddef>
#include <utility>
#include <system_error>

namespace mdnspp::fuzz {

struct fuzz_executor
{
};

class fuzz_socket
{
public:
    explicit fuzz_socket(fuzz_executor &)
    {
    }

    explicit fuzz_socket(fuzz_executor &, std::error_code &)
    {
    }

    explicit fuzz_socket(fuzz_executor &, const mdnspp::socket_options &)
    {
    }

    explicit fuzz_socket(fuzz_executor &, const mdnspp::socket_options &, std::error_code &)
    {
    }

    void send(const mdnspp::endpoint &, std::span<const std::byte> data)
    {
        m_sent.emplace_back(data.begin(), data.end());
    }

    void send(const mdnspp::endpoint &, std::span<const std::byte> data, std::error_code &)
    {
        m_sent.emplace_back(data.begin(), data.end());
    }

    void async_receive(
        mdnspp::move_only_function<void(std::error_code, const mdnspp::recv_metadata &, std::span<std::byte>)> handler)
    {
        if(m_queue.empty())
            return;
        auto packet = std::move(m_queue.front());
        m_queue.pop();
        handler(std::error_code{}, mdnspp::recv_metadata{}, std::span<std::byte>(packet));
    }

    void close()
    {
    }

    void enqueue(std::vector<std::byte> packet)
    {
        m_queue.push(std::move(packet));
    }

    std::vector<std::vector<std::byte>> &sent() noexcept
    {
        return m_sent;
    }

private:
    std::vector<std::vector<std::byte>> m_sent;
    std::queue<std::vector<std::byte>> m_queue;
};

static_assert(mdnspp::socket_like<fuzz_socket>, "fuzz_socket must satisfy socket_like");

}

#endif
