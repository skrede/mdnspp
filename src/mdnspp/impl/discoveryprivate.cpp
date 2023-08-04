#include "discoveryprivate.h"

using namespace mdnspp;

// Callback handling parsing answers to queries sent
int mdnspp::discovery_callback(int sock, const struct sockaddr *from, size_t addrlen, mdns_entry_type_t entry,
                               uint16_t query_id, uint16_t rtype, uint16_t rclass, uint32_t ttl, const void *data,
                               size_t size, size_t name_offset, size_t name_length, size_t record_offset,
                               size_t record_length, void *user_data)
{
    static char addrbuffer[64];
    static char entrybuffer[256];
    static char namebuffer[256];
    static mdns_record_txt_t txtbuffer[128];

    (void) sizeof(sock);
    (void) sizeof(query_id);
    (void) sizeof(name_length);
    (void) sizeof(user_data);
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

// Send a DNS-SD query
int DiscoveryPrivate::send_dns_sd()
{
    int sockets[32];
    int num_sockets = mdnspp::open_client_sockets(sockets, sizeof(sockets) / sizeof(sockets[0]), 0, service_address_ipv4, service_address_ipv6);
    if(num_sockets <= 0)
    {
        printf("Failed to open any client sockets\n");
        return -1;
    }
    printf("Opened %d socket%s for DNS-SD\n", num_sockets, num_sockets > 1 ? "s" : "");

    printf("Sending DNS-SD discovery\n");
    for(int isock = 0; isock < num_sockets; ++isock)
    {
        if(mdns_discovery_send(sockets[isock]))
            printf("Failed to send DNS-DS discovery: %s\n", strerror(errno));
    }

    size_t capacity = 2048;
    void *buffer = malloc(capacity);
    void *user_data = 0;
    size_t records;

    // This is a simple implementation that loops for 5 seconds or as long as we get replies
    int res;
    printf("Reading DNS-SD replies\n");
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
                    records += mdns_discovery_recv(sockets[isock], buffer, capacity, mdnspp::discovery_callback,
                                                   user_data);
                }
            }
        }
    } while(res > 0);

    free(buffer);

    for(int isock = 0; isock < num_sockets; ++isock)
        mdns_socket_close(sockets[isock]);
    printf("Closed socket%s\n", num_sockets ? "s" : "");

    return 0;
}

void DiscoveryPrivate::stop()
{

}

