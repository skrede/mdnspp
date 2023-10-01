#ifndef MDNSPP_MDNS_BASE_H
#define MDNSPP_MDNS_BASE_H

#include "mdnspp/log.h"
#include "mdnspp/logger.h"
#include "mdnspp/mdns_util.h"
#include "mdnspp/message_buffer.h"

#include <atomic>
#include <chrono>
#include <functional>

namespace mdnspp {

typedef int index_t;
typedef int socket_t;

class mdns_base
{
public:
    mdns_base(size_t buffer_capacity = 2048u);
    explicit mdns_base(std::shared_ptr<log_sink> sink, size_t buffer_capacity = 2048u);

    ~mdns_base();

    virtual void stop();

    size_t socket_count() const;

    bool has_address_ipv4() const;
    bool has_address_ipv6() const;

    const std::optional<sockaddr_in> &address_ipv4() const;
    const std::optional<sockaddr_in6> &address_ipv6() const;

protected:
    void open_client_sockets(uint16_t port = 0u);
    void open_service_sockets();

    void close_sockets();

    void send(const std::function<void(index_t soc_idx, socket_t socket, void *buffer, size_t capacity)> &send_cb);

    void listen_until_silence(const std::function<size_t(index_t soc_idx, socket_t socket, void *buffer, size_t capacity, mdns_record_callback_fn callback, void *user_data)> &listen_func, std::chrono::milliseconds timeout);

    template<size_t (*mdns_recv_func)(socket_t socket, void *buffer, size_t capacity, mdns_record_callback_fn callback, void *user_data)>
    void listen_until_silence(std::chrono::milliseconds timeout)
    {
        listen_until_silence(
            [](index_t soc_idx, socket_t socket, void *buffer, size_t capacity, mdns_record_callback_fn callback, void *user_data)
            {
                return mdns_recv_func(socket, buffer, capacity, callback, user_data);
            }, timeout
        );
    }

    template<size_t (*mdns_recv_func)(socket_t socket, void *buffer, size_t capacity, mdns_record_callback_fn callback, void *user_data)>
    void listen_while(const std::function<bool()> &listen, std::chrono::milliseconds timeout)
    {
        auto buffer = std::make_unique<char[]>(m_buffer_capacity);

        auto sec = std::chrono::duration_cast<std::chrono::seconds>(timeout);
        auto usec = std::chrono::duration_cast<std::chrono::microseconds>(timeout) - std::chrono::duration_cast<std::chrono::microseconds>(sec);
        while(listen() && !m_stop)
        {
            int nfds = 0;
            fd_set readfs;
            FD_ZERO(&readfs);
            for(index_t soc_idx = 0; soc_idx < m_socket_count; ++soc_idx)
            {
                if(m_sockets[soc_idx] >= nfds)
                    nfds = m_sockets[soc_idx] + 1;
                FD_SET(m_sockets[soc_idx], &readfs);
            }

#ifdef WIN32
            timeval time_out{
                static_cast<long>(sec.count()),
                static_cast<long>(usec.count())
            };
#else
            timeval time_out{
                sec.count(),
                usec.count()
            };
#endif

            if(select(nfds, &readfs, nullptr, nullptr, &time_out) >= 0)
                for(index_t soc_idx = 0; soc_idx < m_socket_count; ++soc_idx)
                {
                    if(FD_ISSET(m_sockets[soc_idx], &readfs))
                        mdns_recv_func(m_sockets[soc_idx], buffer.get(), m_buffer_capacity, mdns_base::mdns_callback, this);
                    FD_SET(m_sockets[soc_idx], &readfs);
                }
            else
                break;
        }
    }

    logger<log_level::trace> trace();
    logger<log_level::debug> debug();
    logger<log_level::info> info();
    logger<log_level::warn> warn();
    logger<log_level::err> error();

    logger<log_level::trace> trace(const std::string &label);
    logger<log_level::debug> debug(const std::string &label);
    logger<log_level::info> info(const std::string &label);
    logger<log_level::warn> warn(const std::string &label);
    logger<log_level::err> error(const std::string &label);

private:
    int m_sockets[32];
    int m_socket_count;
    size_t m_buffer_capacity;
    std::atomic<bool> m_stop;
    std::optional<sockaddr_in> m_address_ipv4;
    std::optional<sockaddr_in6> m_address_ipv6;
    std::shared_ptr<log_sink> m_sink;

    static int mdns_callback(socket_t socket, const sockaddr *from, size_t addrlen, mdns_entry_type_t entry,
                             uint16_t query_id, uint16_t rtype, uint16_t rclass, uint32_t ttl, const void *data,
                             size_t size, size_t name_offset, size_t name_length, size_t record_offset,
                             size_t record_length, void *user_data);

    virtual void callback(socket_t socket, message_buffer &buffer) = 0;

// Open sockets for sending one-shot multicast queries from an ephemeral port
    int open_client_sockets(int *sockets, int max_sockets, int port, sockaddr_in &service_address_ipv4, sockaddr_in6 &service_address_ipv6);

    int open_service_sockets(int *sockets, int max_sockets, sockaddr_in &service_address_ipv4, sockaddr_in6 &service_address_ipv6);

};

}

#endif
