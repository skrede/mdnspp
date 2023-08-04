#include "mdnspp/impl/query_impl.h"

#include "mdnspp/log.h"

using namespace mdnspp;

void query::impl::send_query(mdns_query_t *query, size_t count)
{
    const auto &sockets = this->sockets();
    std::vector<int> query_id(32);
    open_client_sockets(0);

    debug() << "Sending mDNS query";
    for(size_t iq = 0; iq < count; ++iq)
    {
        const char *record_name = "PTR";
        if(query[iq].type == MDNS_RECORDTYPE_SRV)
            record_name = "SRV";
        else if(query[iq].type == MDNS_RECORDTYPE_A)
            record_name = "A";
        else if(query[iq].type == MDNS_RECORDTYPE_AAAA)
            record_name = "AAAA";
        else
            query[iq].type = MDNS_RECORDTYPE_PTR;
        printf(" : %s %s", query[iq].name, record_name);
    }
    printf("\n");

    for(int idx = 0; idx < socket_count(); ++idx)
    {
        query_id[idx] = mdns_multiquery_send(sockets[idx], query, count, &m_buffer[0], m_buffer.size(), 0);
        if(query_id[idx] < 0)
            error() << "Failed to send mDNS query: " << strerror(errno);
    }

    // This is a simple implementation that loops for 5 seconds or as long as we get replies
    int res;
    debug() << "Reading mDNS query replies";
    int records = 0;

    do
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
        timeout.tv_sec = 10;
        timeout.tv_usec = 0;

        res = select(nfds, &readfs, 0, 0, &timeout);
        if(res > 0)
            for(int idx = 0; idx < socket_count(); ++idx)
            {
                if(FD_ISSET(sockets[idx], &readfs))
                {
                    size_t rec = mdns_query_recv(sockets[idx], &m_buffer[0], m_buffer.size(), mdnspp::mdnsbase_callback, this, query_id[idx]);
                    if(rec > 0)
                        records += rec;
                }
                FD_SET(sockets[idx], &readfs);
            }
    } while(res > 0);

    info() << "Read " << records << " records" << (records == 1 ? "" : "s");

    close_sockets();
}

int query::impl::callback(int sock, const struct sockaddr *from, size_t addrlen, mdns_entry_type_t entry, uint16_t query_id, uint16_t rtype, uint16_t rclass, uint32_t ttl, const void *data, size_t size, size_t name_offset, size_t name_length, size_t record_offset, size_t record_length)
{
    char addrbuffer[64];
    char entrybuffer[256];
    char namebuffer[256];
    mdns_record_txt_t txtbuffer[128];

    mdns_string_t fromaddrstr = ip_address_to_string(addrbuffer, sizeof(addrbuffer), from, addrlen);
    const char *entrytype = (entry == MDNS_ENTRYTYPE_ANSWER) ?
                            "answer" :
                            ((entry == MDNS_ENTRYTYPE_AUTHORITY) ? "authority" : "additional");
    mdns_string_t entrystr =
        mdns_string_extract(data, size, &name_offset, entrybuffer, sizeof(entrybuffer));
    if(rtype == MDNS_RECORDTYPE_PTR)
    {
        mdns_string_t namestr = mdns_record_parse_ptr(data, size, record_offset, record_length,
                                                      namebuffer, sizeof(namebuffer));
        printf("%.*s : %s %.*s PTR %.*s rclass 0x%x ttl %u length %d\n",
               MDNS_STRING_FORMAT(fromaddrstr), entrytype, MDNS_STRING_FORMAT(entrystr),
               MDNS_STRING_FORMAT(namestr), rclass, ttl, (int) record_length);
    }
    else if(rtype == MDNS_RECORDTYPE_SRV)
    {
        mdns_record_srv_t srv = mdns_record_parse_srv(data, size, record_offset, record_length,
                                                      namebuffer, sizeof(namebuffer));
        printf("%.*s : %s %.*s SRV %.*s priority %d weight %d port %d\n",
               MDNS_STRING_FORMAT(fromaddrstr), entrytype, MDNS_STRING_FORMAT(entrystr),
               MDNS_STRING_FORMAT(srv.name), srv.priority, srv.weight, srv.port);
    }
    else if(rtype == MDNS_RECORDTYPE_A)
    {
        struct sockaddr_in addr;
        mdns_record_parse_a(data, size, record_offset, record_length, &addr);
        mdns_string_t addrstr =
            ipv4_address_to_string(namebuffer, sizeof(namebuffer), &addr, sizeof(addr));
        printf("%.*s : %s %.*s A %.*s\n", MDNS_STRING_FORMAT(fromaddrstr), entrytype,
               MDNS_STRING_FORMAT(entrystr), MDNS_STRING_FORMAT(addrstr));
    }
    else if(rtype == MDNS_RECORDTYPE_AAAA)
    {
        struct sockaddr_in6 addr;
        mdns_record_parse_aaaa(data, size, record_offset, record_length, &addr);
        mdns_string_t addrstr =
            ipv6_address_to_string(namebuffer, sizeof(namebuffer), &addr, sizeof(addr));
        printf("%.*s : %s %.*s AAAA %.*s\n", MDNS_STRING_FORMAT(fromaddrstr), entrytype,
               MDNS_STRING_FORMAT(entrystr), MDNS_STRING_FORMAT(addrstr));
    }
    else if(rtype == MDNS_RECORDTYPE_TXT)
    {
        size_t parsed = mdns_record_parse_txt(data, size, record_offset, record_length, txtbuffer,
                                              sizeof(txtbuffer) / sizeof(mdns_record_txt_t));
        for(size_t itxt = 0; itxt < parsed; ++itxt)
        {
            if(txtbuffer[itxt].value.length)
            {
                printf("%.*s : %s %.*s TXT %.*s = %.*s\n", MDNS_STRING_FORMAT(fromaddrstr),
                       entrytype, MDNS_STRING_FORMAT(entrystr),
                       MDNS_STRING_FORMAT(txtbuffer[itxt].key),
                       MDNS_STRING_FORMAT(txtbuffer[itxt].value));
            }
            else
            {
                printf("%.*s : %s %.*s TXT %.*s\n", MDNS_STRING_FORMAT(fromaddrstr), entrytype,
                       MDNS_STRING_FORMAT(entrystr), MDNS_STRING_FORMAT(txtbuffer[itxt].key));
            }
        }
    }
    else
    {
        printf("%.*s : %s %.*s type %u rclass 0x%x ttl %u length %d\n",
               MDNS_STRING_FORMAT(fromaddrstr), entrytype, MDNS_STRING_FORMAT(entrystr), rtype,
               rclass, ttl, (int) record_length);
    }
    return 0;
}
