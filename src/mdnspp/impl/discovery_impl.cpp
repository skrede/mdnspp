#include "mdnspp/impl/discovery_impl.h"

#include "mdnspp/impl/message_buffer.h"

using namespace mdnspp;

void discovery::impl::discover()
{
    open_client_sockets();

    mdnspp::debug() << "Sending DNS-SD discovery";
    send(
        [](index_t soc_idx, socket_t socket, void *buffer, size_t capacity)
        {
            if(mdns_discovery_send(socket))
                mdnspp::error() << "Failed to send DNS-DS discovery: " << strerror(errno);
        }
    );

    listen_until_silence<mdns_discovery_recv>();

    close_sockets();
}

void discovery::impl::stop()
{
}

void discovery::impl::callback(socket_t socket, const message_buffer &buffer)
{
    char addr_buffer[64];
    char entry_buffer[256];
    char name_buffer[256];
    mdns_record_txt_t txt_buffer[128];

    auto entry_type = buffer.entry_type_name();
    auto from_addr_str = buffer.sender_address();
    auto entry_str = buffer.name();

    if(buffer.entry_type() == MDNS_RECORDTYPE_PTR)
    {
        mdns_string_t namestr = mdns_record_parse_ptr(data, size, record_offset, record_length, name_buffer, sizeof(name_buffer));
        printf("%.*s : %s %.*s PTR %.*s rclass 0x%x ttl %u length %d\n", MDNS_STRING_FORMAT(from_addr_str), entry_type, MDNS_STRING_FORMAT(entry_str), MDNS_STRING_FORMAT(namestr), rclass, ttl, (int) record_length);
    }
    else if(buffer.entry_type() == MDNS_RECORDTYPE_SRV)
    {
        mdns_record_srv_t srv = mdns_record_parse_srv(data, size, record_offset, record_length, name_buffer, sizeof(name_buffer));
        printf("%.*s : %s %.*s SRV %.*s priority %d weight %d port %d\n", MDNS_STRING_FORMAT(from_addr_str), entry_type, MDNS_STRING_FORMAT(entry_str), MDNS_STRING_FORMAT(srv.name), srv.priority, srv.weight, srv.port);
    }
    else if(buffer.entry_type() == MDNS_RECORDTYPE_A)
    {
        struct sockaddr_in addr;
        mdns_record_parse_a(data, size, record_offset, record_length, &addr);
        mdns_string_t addrstr = ipv4_address_to_string(name_buffer, sizeof(name_buffer), &addr, sizeof(addr));
        printf("%.*s : %s %.*s A %.*s\n", MDNS_STRING_FORMAT(from_addr_str), entry_type, MDNS_STRING_FORMAT(entry_str), MDNS_STRING_FORMAT(addrstr));
    }
    else if(buffer.entry_type() == MDNS_RECORDTYPE_AAAA)
    {
        struct sockaddr_in6 addr;
        mdns_record_parse_aaaa(data, size, record_offset, record_length, &addr);
        mdns_string_t addrstr = ipv6_address_to_string(name_buffer, sizeof(name_buffer), &addr, sizeof(addr));
        printf("%.*s : %s %.*s AAAA %.*s\n", MDNS_STRING_FORMAT(from_addr_str), entry_type, MDNS_STRING_FORMAT(entry_str), MDNS_STRING_FORMAT(addrstr));
    }
    else if(buffer.entry_type() == MDNS_RECORDTYPE_TXT)
    {
        size_t parsed = mdns_record_parse_txt(data, size, record_offset, record_length, txt_buffer, sizeof(txt_buffer) / sizeof(mdns_record_txt_t));
        for(size_t itxt = 0; itxt < parsed; ++itxt)
        {
            if(txt_buffer[itxt].value.length)
                printf("%.*s : %s %.*s TXT %.*s = %.*s\n", MDNS_STRING_FORMAT(from_addr_str), entry_type, MDNS_STRING_FORMAT(entry_str), MDNS_STRING_FORMAT(txt_buffer[itxt].key), MDNS_STRING_FORMAT(txt_buffer[itxt].value));
            else
                printf("%.*s : %s %.*s TXT %.*s\n", MDNS_STRING_FORMAT(from_addr_str), entry_type, MDNS_STRING_FORMAT(entry_str), MDNS_STRING_FORMAT(txt_buffer[itxt].key));
        }
    }
    else
        printf("%.*s : %s %.*s type %u rclass 0x%x ttl %u length %d\n", MDNS_STRING_FORMAT(from_addr_str), entry_type, MDNS_STRING_FORMAT(entry_str), rtype, rclass, ttl, (int) record_length);
}
