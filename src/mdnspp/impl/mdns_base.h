#ifndef MDNSPP_MDNS_BASE_H
#define MDNSPP_MDNS_BASE_H

#include "mdnspp/log.h"
#include "mdnspp/mdns_util.h"

#include <chrono>
#include <functional>

#include <signal.h>

namespace mdnspp {

int mdnsbase_callback(int sock, const struct sockaddr *from, size_t addrlen, mdns_entry_type_t entry,
                      uint16_t query_id, uint16_t rtype, uint16_t rclass, uint32_t ttl, const void *data,
                      size_t size, size_t name_offset, size_t name_length, size_t record_offset,
                      size_t record_length, void *user_data);

class mdns_base
{
public:
    mdns_base();
    ~mdns_base();

    virtual int callback(int sock, const struct sockaddr *from, size_t addrlen, mdns_entry_type_t entry, uint16_t query_id, uint16_t rtype, uint16_t rclass, uint32_t ttl, const void *data, size_t size, size_t name_offset, size_t name_length, size_t record_offset, size_t record_length) = 0;

protected:
    int sockets[32];
    int num_sockets;

    sockaddr_in service_address_ipv4;
    sockaddr_in6 service_address_ipv6;

    void open_client_sockets(uint16_t port = 0u);
    void open_service_sockets();

    void close_sockets();

    template<size_t (*mdns_recv_func)(int sock, void *buffer, size_t capacity, mdns_record_callback_fn callback, void *user_data)>
    void listen_until_silence(std::chrono::milliseconds timeout = std::chrono::milliseconds(5000))
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
            for(int isock = 0; isock < num_sockets; ++isock)
            {
                if(sockets[isock] >= nfds)
                    nfds = sockets[isock] + 1;
                FD_SET(sockets[isock], &readfs);
            }

            records = 0u;
            ready_descriptors = select(nfds, &readfs, 0, 0, &time_out);
            if(ready_descriptors > 0)
                for(int isock = 0; isock < num_sockets; ++isock)
                    if(FD_ISSET(sockets[isock], &readfs))
                        records += mdns_recv_func(sockets[isock], buffer, capacity, mdnspp::mdnsbase_callback, this);
        } while(ready_descriptors > 0);
    }

    template<size_t (*mdns_recv_func)(int sock, void *buffer, size_t capacity, mdns_record_callback_fn callback, void *user_data), typename ...Args>
    void listen_until_silence(Args &&... args, std::chrono::milliseconds timeout = std::chrono::milliseconds(5000))
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
            for(int isock = 0; isock < num_sockets; ++isock)
            {
                if(sockets[isock] >= nfds)
                    nfds = sockets[isock] + 1;
                FD_SET(sockets[isock], &readfs);
            }

            records = 0u;
            ready_descriptors = select(nfds, &readfs, 0, 0, &time_out);
            if(ready_descriptors > 0)
                for(int isock = 0; isock < num_sockets; ++isock)
                    if(FD_ISSET(sockets[isock], &readfs))
                        records += std::invoke(std::forward<mdns_recv_func>(sockets[isock], buffer, capacity, mdnspp::mdnsbase_callback, this, std::forward<Args>(args)...));
        } while(ready_descriptors > 0);
    }

    template<size_t (*mdns_recv_func)(int sock, void *buffer, size_t capacity, mdns_record_callback_fn callback, void *user_data)>
    void listen_while(std::function<bool()> listen, std::chrono::milliseconds timeout = std::chrono::milliseconds(10000))
    {
        char buffer[2048];
        size_t capacity = 2048;

        while(listen())
        {
            int nfds = 0;
            fd_set readfs;
            FD_ZERO(&readfs);
            for(int isock = 0; isock < num_sockets; ++isock)
            {
                if(sockets[isock] >= nfds)
                    nfds = sockets[isock] + 1;
                FD_SET(sockets[isock], &readfs);
            }

            struct timeval time_out;
            time_out.tv_sec = 0;
            time_out.tv_usec = timeout.count() * 1000;

            if(select(nfds, &readfs, 0, 0, &time_out) >= 0)
                for(int isock = 0; isock < num_sockets; ++isock)
                {
                    if(FD_ISSET(sockets[isock], &readfs))
                        mdns_recv_func(sockets[isock], buffer, capacity, mdnspp::mdnsbase_callback, this);
                    FD_SET(sockets[isock], &readfs);
                }
            else
                break;
        }
    }
};

}

#endif
