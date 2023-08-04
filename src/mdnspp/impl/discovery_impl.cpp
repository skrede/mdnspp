#include "mdnspp/impl/discovery_impl.h"

using namespace mdnspp;

void discovery::impl::discover()
{
    int sockets[32];
    int num_sockets = mdnspp::open_client_sockets(sockets, sizeof(sockets) / sizeof(sockets[0]), 0, service_address_ipv4, service_address_ipv6);
    if(num_sockets <= 0)
        mdnspp::exception() << "Failed to open any client sockets";
    mdnspp::debug() << "Opened " << num_sockets << " client socket" << (num_sockets == 1 ? "" : "s") << " for DNS-SD";

    mdnspp::debug() << "Sending DNS-SD discovery";
    for(int isock = 0; isock < num_sockets; ++isock)
    {
        if(mdns_discovery_send(sockets[isock]))
            mdnspp::error() << "Failed to send DNS-DS discovery: " << strerror(errno);
    }

    size_t capacity = 2048;
    void *buffer = malloc(capacity);
    size_t records;

    // This is a simple implementation that loops for 5 seconds or as long as we get replies
    int res;
    mdnspp::debug() << "Reading DNS-SD replies";
    do
    {
        struct timeval timeout;
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;

        int nfds = 0;
        fd_set readfs;
        FD_ZERO(&readfs);
        for(int isock = 0; isock < num_sockets; ++isock)
        {
            if(sockets[isock] >= nfds)
                nfds = sockets[isock] + 1;
            FD_SET(sockets[isock], &readfs);
        }

        records = 0;
        res = select(nfds, &readfs, 0, 0, &timeout);
        if(res > 0)
        {
            for(int isock = 0; isock < num_sockets; ++isock)
            {
                if(FD_ISSET(sockets[isock], &readfs))
                {
                    records += mdns_discovery_recv(sockets[isock], buffer, capacity, mdnspp::mdnsbase_callback, this);
                }
            }
        }
    } while(res > 0);

    free(buffer);

    for(int isock = 0; isock < num_sockets; ++isock)
        mdns_socket_close(sockets[isock]);
    mdnspp::debug() << "Closed " << num_sockets << " service socket" << (num_sockets == 1 ? "" : "s") << " for DNS-SD";
}

void discovery::impl::stop()
{

}

int discovery::impl::callback(int sock, const struct sockaddr *from, size_t addrlen, mdns_entry_type_t entry, uint16_t query_id, uint16_t rtype, uint16_t rclass, uint32_t ttl, const void *data, size_t size, size_t name_offset, size_t name_length, size_t record_offset, size_t record_length)
{
    char addr_buffer[64];
    char entry_buffer[256];
    char name_buffer[256];
    mdns_record_txt_t txt_buffer[128];

    (void) sizeof(sock);
    (void) sizeof(query_id);
    (void) sizeof(name_length);

    mdns_string_t from_addr_str = ip_address_to_string(addr_buffer, sizeof(addr_buffer), from, addrlen);
    const char *entry_type = (entry == MDNS_ENTRYTYPE_ANSWER) ? "answer" : ((entry == MDNS_ENTRYTYPE_AUTHORITY) ? "authority" : "additional");

    mdns_string_t entry_str = mdns_string_extract(data, size, &name_offset, entry_buffer, sizeof(entry_buffer));

    if(rtype == MDNS_RECORDTYPE_PTR)
    {
        mdns_string_t namestr = mdns_record_parse_ptr(data, size, record_offset, record_length,
                                                      name_buffer, sizeof(name_buffer));
        printf("%.*s : %s %.*s PTR %.*s rclass 0x%x ttl %u length %d\n",
               MDNS_STRING_FORMAT(from_addr_str), entry_type, MDNS_STRING_FORMAT(entry_str),
               MDNS_STRING_FORMAT(namestr), rclass, ttl, (int) record_length);
    }
    else if(rtype == MDNS_RECORDTYPE_SRV)
    {
        mdns_record_srv_t srv = mdns_record_parse_srv(data, size, record_offset, record_length,
                                                      name_buffer, sizeof(name_buffer));
        printf("%.*s : %s %.*s SRV %.*s priority %d weight %d port %d\n",
               MDNS_STRING_FORMAT(from_addr_str), entry_type, MDNS_STRING_FORMAT(entry_str),
               MDNS_STRING_FORMAT(srv.name), srv.priority, srv.weight, srv.port);
    }
    else if(rtype == MDNS_RECORDTYPE_A)
    {
        struct sockaddr_in addr;
        mdns_record_parse_a(data, size, record_offset, record_length, &addr);
        mdns_string_t addrstr =
            ipv4_address_to_string(name_buffer, sizeof(name_buffer), &addr, sizeof(addr));
        printf("%.*s : %s %.*s A %.*s\n", MDNS_STRING_FORMAT(from_addr_str), entry_type,
               MDNS_STRING_FORMAT(entry_str), MDNS_STRING_FORMAT(addrstr));
    }
    else if(rtype == MDNS_RECORDTYPE_AAAA)
    {
        struct sockaddr_in6 addr;
        mdns_record_parse_aaaa(data, size, record_offset, record_length, &addr);
        mdns_string_t addrstr =
            ipv6_address_to_string(name_buffer, sizeof(name_buffer), &addr, sizeof(addr));
        printf("%.*s : %s %.*s AAAA %.*s\n", MDNS_STRING_FORMAT(from_addr_str), entry_type,
               MDNS_STRING_FORMAT(entry_str), MDNS_STRING_FORMAT(addrstr));
    }
    else if(rtype == MDNS_RECORDTYPE_TXT)
    {
        size_t parsed = mdns_record_parse_txt(data, size, record_offset, record_length, txt_buffer,
                                              sizeof(txt_buffer) / sizeof(mdns_record_txt_t));
        for(size_t itxt = 0; itxt < parsed; ++itxt)
        {
            if(txt_buffer[itxt].value.length)
            {
                printf("%.*s : %s %.*s TXT %.*s = %.*s\n", MDNS_STRING_FORMAT(from_addr_str),
                       entry_type, MDNS_STRING_FORMAT(entry_str),
                       MDNS_STRING_FORMAT(txt_buffer[itxt].key),
                       MDNS_STRING_FORMAT(txt_buffer[itxt].value));
            }
            else
            {
                printf("%.*s : %s %.*s TXT %.*s\n", MDNS_STRING_FORMAT(from_addr_str), entry_type,
                       MDNS_STRING_FORMAT(entry_str), MDNS_STRING_FORMAT(txt_buffer[itxt].key));
            }
        }
    }
    else
    {
        printf("%.*s : %s %.*s type %u rclass 0x%x ttl %u length %d\n",
               MDNS_STRING_FORMAT(from_addr_str), entry_type, MDNS_STRING_FORMAT(entry_str), rtype,
               rclass, ttl, (int) record_length);
    }
    return 0;
}
