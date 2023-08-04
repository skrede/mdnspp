#include "mdnspp/impl/observer_impl.h"

#include "mdnspp/log.h"

using namespace mdnspp;

observer::impl::impl()
    : m_running{false}
{

}

void observer::impl::observe()
{
    open_service_sockets();
    auto sockets = this->sockets();

    m_running = true;

    while(m_running)
    {
        int nfds = 0;
        fd_set readfs;
        FD_ZERO(&readfs);
        for(int idx = 0; idx < socket_count(); ++idx)
        {
            if(sockets[idx] >= nfds)
                nfds = sockets[idx] + 1;
            FD_SET(sockets[idx], &readfs);
        }

        struct timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 100000;

        if(select(nfds, &readfs, 0, 0, &timeout) >= 0)
        {
            for(int idx = 0; idx < socket_count(); ++idx)
            {
                if(FD_ISSET(sockets[idx], &readfs))
                    mdns_socket_listen(sockets[idx], &m_buffer[0], m_buffer.size(), mdnspp::mdnsbase_callback, this);
                FD_SET(sockets[idx], &readfs);
            }
        }
        else
            break;
    }

    close_sockets();
}

void observer::impl::observe_async()
{

}

void observer::impl::stop()
{
    m_running = false;
}

int observer::impl::callback(int sock, const struct sockaddr *from, size_t addrlen, mdns_entry_type_t entry, uint16_t query_id, uint16_t rtype, uint16_t rclass, uint32_t ttl, const void *data, size_t size, size_t name_offset, size_t name_length, size_t record_offset, size_t record_length)
{
    char addr_buffer[64];
    char name_buffer[256];

    mdns_string_t from_addr_string = ip_address_to_string(addr_buffer, sizeof(addr_buffer), from, addrlen);

    size_t offset = name_offset;
    mdns_string_t name = mdns_string_extract(data, size, &offset, name_buffer, sizeof(name_buffer));

    const char *record_name;
    if(rtype == MDNS_RECORDTYPE_PTR)
        record_name = "PTR";
    else if(rtype == MDNS_RECORDTYPE_SRV)
        record_name = "SRV";
    else if(rtype == MDNS_RECORDTYPE_A)
        record_name = "A";
    else if(rtype == MDNS_RECORDTYPE_AAAA)
        record_name = "AAAA";
    else if(rtype == MDNS_RECORDTYPE_TXT)
        record_name = "TXT";
    else if(rtype == MDNS_RECORDTYPE_ANY)
        record_name = "ANY";
    else
        record_name = "<UNKNOWN>";

    const char *entry_type = "Question";
    if(entry == MDNS_ENTRYTYPE_ANSWER)
        entry_type = "Answer";
    else if(entry == MDNS_ENTRYTYPE_AUTHORITY)
        entry_type = "Authority";
    else if(entry == MDNS_ENTRYTYPE_ADDITIONAL)
        entry_type = "Additional";

    printf("%.*s: %s %s %.*s rclass 0x%x ttl %u\n", MDNS_STRING_FORMAT(from_addr_string), entry_type,
           record_name, MDNS_STRING_FORMAT(name), (unsigned int) rclass, ttl);

    return 0;
}