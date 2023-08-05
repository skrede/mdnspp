#ifndef MDNSPP_MDNS_BASE_H
#define MDNSPP_MDNS_BASE_H

#include "mdnspp/log.h"
#include "mdnspp/mdns_util.h"

#include <chrono>
#include <functional>

#include <signal.h>

namespace mdnspp {

typedef int index_t;
typedef int socket_t;

int mdnsbase_callback(socket_t socket, const struct sockaddr *from, size_t addrlen, mdns_entry_type_t entry,
                      uint16_t query_id, uint16_t rtype, uint16_t rclass, uint32_t ttl, const void *data,
                      size_t size, size_t name_offset, size_t name_length, size_t record_offset,
                      size_t record_length, void *user_data);

class mdns_base
{
public:
    mdns_base();
    ~mdns_base();

    size_t socket_count();

    bool has_address_ipv4();
    bool has_address_ipv6();

    const sockaddr_in &address_ipv4();
    const sockaddr_in6 &address_ipv6();

    virtual int callback(socket_t socket, const struct sockaddr *from, size_t addrlen, mdns_entry_type_t entry, uint16_t query_id, uint16_t rtype, uint16_t rclass, uint32_t ttl, const void *data, size_t size, size_t name_offset, size_t name_length, size_t record_offset, size_t record_length) = 0;

protected:
    void open_client_sockets(uint16_t port = 0u);
    void open_service_sockets();

    void close_sockets();

    void send(std::function<void(index_t soc_idx, socket_t socket, void *buffer, size_t capacity)> send_cb)
    {
        char buffer[2048];
        size_t capacity = 2048;
        for(index_t soc_idx = 0; soc_idx < m_socket_count; ++soc_idx)
            send_cb(soc_idx, m_sockets[soc_idx], buffer, capacity);
    }

    template<size_t (*mdns_recv_func)(socket_t socket, void *buffer, size_t capacity, mdns_record_callback_fn callback, void *user_data)>
    void listen_until_silence(std::chrono::milliseconds timeout = std::chrono::milliseconds(5000))
    {
        listen_until_silence(
            [](index_t soc_idx, socket_t socket, void *buffer, size_t capacity, mdns_record_callback_fn callback, void *user_data)
            {
                return mdns_recv_func(socket, buffer, capacity, callback, user_data);
            }, timeout
        );
    }

    void listen_until_silence(std::function<size_t(index_t soc_idx, socket_t socket, void *buffer, size_t capacity, mdns_record_callback_fn callback, void *user_data)> listen_func,
                              std::chrono::milliseconds timeout = std::chrono::milliseconds(5000))
    {
        char buffer[2048];
        size_t capacity = 2048;

        size_t records = 0u;
        int ready_descriptors;
        do
        {
            struct timeval time_out;
            time_out.tv_sec = 0;
            time_out.tv_usec = timeout.count() * 1000;

            int nfds = 0;
            fd_set readfs;
            FD_ZERO(&readfs);
            for(index_t soc_idx = 0; soc_idx < m_socket_count; ++soc_idx)
            {
                if(m_sockets[soc_idx] >= nfds)
                    nfds = m_sockets[soc_idx] + 1;
                FD_SET(m_sockets[soc_idx], &readfs);
            }

            records = 0u;
            ready_descriptors = select(nfds, &readfs, 0, 0, &time_out);
            if(ready_descriptors > 0)
                for(index_t soc_idx = 0; soc_idx < m_socket_count; ++soc_idx)
                    if(FD_ISSET(m_sockets[soc_idx], &readfs))
                        records += listen_func(soc_idx, m_sockets[soc_idx], buffer, capacity, mdnspp::mdnsbase_callback, this);
        } while(ready_descriptors > 0);
    }

    template<size_t (*mdns_recv_func)(socket_t socket, void *buffer, size_t capacity, mdns_record_callback_fn callback, void *user_data)>
    void listen_while(std::function<bool()> listen, std::chrono::milliseconds timeout = std::chrono::milliseconds(10000))
    {
        char buffer[2048];
        size_t capacity = 2048;

        while(listen())
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

            struct timeval time_out;
            time_out.tv_sec = 0;
            time_out.tv_usec = timeout.count() * 1000;

            if(select(nfds, &readfs, 0, 0, &time_out) >= 0)
                for(index_t soc_idx = 0; soc_idx < m_socket_count; ++soc_idx)
                {
                    if(FD_ISSET(m_sockets[soc_idx], &readfs))
                        mdns_recv_func(m_sockets[soc_idx], buffer, capacity, mdnspp::mdnsbase_callback, this);
                    FD_SET(m_sockets[soc_idx], &readfs);
                }
            else
                break;
        }
    }

private:
    int m_sockets[32];
    int m_socket_count;
    sockaddr_in m_address_ipv4;
    sockaddr_in6 m_address_ipv6;
};

}

#endif
