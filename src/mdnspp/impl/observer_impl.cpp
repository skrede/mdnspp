#include "mdnspp/impl/observer_impl.h"

using namespace mdnspp;

int observer::impl::observe()
{
    int sockets[32];
    int num_sockets = mdnspp::open_service_sockets(sockets, sizeof(sockets) / sizeof(sockets[0]), service_address_ipv4, service_address_ipv6);
    if(num_sockets <= 0)
    {
        printf("Failed to open any client sockets\n");
        return -1;
    }
    printf("Opened %d socket%s for mDNS dump\n", num_sockets, num_sockets ? "s" : "");

    size_t capacity = 2048;
    void *buffer = malloc(capacity);

    // This is a crude implementation that checks for incoming queries and answers
    while(running)
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

        struct timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 100000;

        if(select(nfds, &readfs, 0, 0, &timeout) >= 0)
        {
            for(int isock = 0; isock < num_sockets; ++isock)
            {
                if(FD_ISSET(sockets[isock], &readfs))
                {
                    mdns_socket_listen(sockets[isock], buffer, capacity, mdnspp::mdnsbase_callback, this);
                }
                FD_SET(sockets[isock], &readfs);
            }
        }
        else
        {
            break;
        }
    }

    free(buffer);

    for(int isock = 0; isock < num_sockets; ++isock)
        mdns_socket_close(sockets[isock]);
    printf("Closed socket%s\n", num_sockets ? "s" : "");

    return 0;
}

void observer::impl::stop()
{
    running = false;
}

int observer::impl::callback(int sock, const struct sockaddr *from, size_t addrlen, mdns_entry_type_t entry, uint16_t query_id, uint16_t rtype, uint16_t rclass, uint32_t ttl, const void *data, size_t size, size_t name_offset, size_t name_length, size_t record_offset, size_t record_length)
{
    static char addrbuffer[64];
    static char namebuffer[256];
    mdns_string_t fromaddrstr = ip_address_to_string(addrbuffer, sizeof(addrbuffer), from, addrlen);

    size_t offset = name_offset;
    mdns_string_t name = mdns_string_extract(data, size, &offset, namebuffer, sizeof(namebuffer));

    const char *record_name = 0;
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

    printf("%.*s: %s %s %.*s rclass 0x%x ttl %u\n", MDNS_STRING_FORMAT(fromaddrstr), entry_type,
           record_name, MDNS_STRING_FORMAT(name), (unsigned int) rclass, ttl);

    return 0;
}
