#include "mdnspp/impl/query_impl.h"

using namespace mdnspp;

// Send a mDNS query
void query::impl::send_query(mdns_query_t *query, size_t count)
{
    int query_id[32];
    open_client_sockets();

    mdnspp::debug() << "Sending mDNS query";
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
        mdnspp::debug() << " : " << query[iq].name << " " << record_name;
    }
    send(
        [&](index_t soc_idx, socket_t socket, void *buffer, size_t capacity)
        {
            query_id[soc_idx] =
                mdns_multiquery_send(socket, query, count, buffer, capacity, 0);
            if(query_id[soc_idx] < 0)
                mdnspp::error() << "Failed to send mDNS query: " << strerror(errno);
        }
    );

    mdnspp::debug() << "Reading mDNS query replies";
    listen_until_silence(
        [query_id](index_t soc_idx, socket_t socket, void *buffer, size_t capacity, mdns_record_callback_fn callback, void *user_data)
            -> size_t
        {
            return mdns_query_recv(socket, buffer, capacity, callback, user_data, query_id[soc_idx]);
        }
    );

    close_sockets();
}

void query::impl::callback(socket_t socket, message_buffer &buffer)
{

    char addr_buffer[64];
    char entry_buffer[256];
    char name_buffer[256];

    mdns_record_txt_t txt_buffer[128];

    auto &name_offset = buffer.m_name_offset;
    auto &ttl = buffer.m_ttl;
    auto &size = buffer.m_size;
    auto &data = buffer.m_data;
    auto &rtype = buffer.m_rtype;
    auto &entry = buffer.m_entry;
    auto &record_length = buffer.m_record_length;
    auto &record_offset = buffer.m_record_offset;
    auto &rclass = buffer.m_rclass;
    auto &addrlen = buffer.m_addrlen;
    auto from = &buffer.m_sender;

    mdns_string_t from_addr_str = ip_address_to_string(addr_buffer, sizeof(addr_buffer), from, addrlen);
    const char *entry_type = (entry == MDNS_ENTRYTYPE_ANSWER) ? "answer" : ((entry == MDNS_ENTRYTYPE_AUTHORITY) ? "authority" : "additional");
    mdns_string_t entry_str = mdns_string_extract(data, size, &name_offset, entry_buffer, sizeof(entry_buffer));

    if(rtype == MDNS_RECORDTYPE_PTR)
    {
        mdns_string_t namestr = mdns_record_parse_ptr(data, size, record_offset, record_length, name_buffer, sizeof(name_buffer));
        printf("%.*s : %s %.*s PTR %.*s rclass 0x%x ttl %u length %d\n", MDNS_STRING_FORMAT(from_addr_str), entry_type, MDNS_STRING_FORMAT(entry_str), MDNS_STRING_FORMAT(namestr), rclass, ttl, (int) record_length);
    }
    else if(rtype == MDNS_RECORDTYPE_SRV)
    {
        mdns_record_srv_t srv = mdns_record_parse_srv(data, size, record_offset, record_length, name_buffer, sizeof(name_buffer));
        printf("%.*s : %s %.*s SRV %.*s priority %d weight %d port %d\n", MDNS_STRING_FORMAT(from_addr_str), entry_type, MDNS_STRING_FORMAT(entry_str), MDNS_STRING_FORMAT(srv.name), srv.priority, srv.weight, srv.port);
    }
    else if(rtype == MDNS_RECORDTYPE_A)
    {
        struct sockaddr_in addr;
        mdns_record_parse_a(data, size, record_offset, record_length, &addr);
        mdns_string_t addrstr = ipv4_address_to_string(name_buffer, sizeof(name_buffer), &addr, sizeof(addr));
        printf("%.*s : %s %.*s A %.*s\n", MDNS_STRING_FORMAT(from_addr_str), entry_type, MDNS_STRING_FORMAT(entry_str), MDNS_STRING_FORMAT(addrstr));
    }
    else if(rtype == MDNS_RECORDTYPE_AAAA)
    {
        struct sockaddr_in6 addr;
        mdns_record_parse_aaaa(data, size, record_offset, record_length, &addr);
        mdns_string_t addrstr = ipv6_address_to_string(name_buffer, sizeof(name_buffer), &addr, sizeof(addr));
        printf("%.*s : %s %.*s AAAA %.*s\n", MDNS_STRING_FORMAT(from_addr_str), entry_type, MDNS_STRING_FORMAT(entry_str), MDNS_STRING_FORMAT(addrstr));
    }
    else if(rtype == MDNS_RECORDTYPE_TXT)
    {
        size_t parsed = mdns_record_parse_txt(data, size, record_offset, record_length, txt_buffer, sizeof(txt_buffer) / sizeof(mdns_record_txt_t));
        for(size_t itxt = 0; itxt < parsed; ++itxt)
        {
            if(txt_buffer[itxt].value.length)
            {
                printf("%.*s : %s %.*s TXT %.*s = %.*s\n", MDNS_STRING_FORMAT(from_addr_str), entry_type, MDNS_STRING_FORMAT(entry_str), MDNS_STRING_FORMAT(txt_buffer[itxt].key), MDNS_STRING_FORMAT(txt_buffer[itxt].value));
            }
            else
            {
                printf("%.*s : %s %.*s TXT %.*s\n", MDNS_STRING_FORMAT(from_addr_str), entry_type, MDNS_STRING_FORMAT(entry_str), MDNS_STRING_FORMAT(txt_buffer[itxt].key));
            }
        }
    }
    else
    {
        printf("%.*s : %s %.*s type %u rclass 0x%x ttl %u length %d\n", MDNS_STRING_FORMAT(from_addr_str), entry_type, MDNS_STRING_FORMAT(entry_str), rtype, rclass, ttl, (int) record_length);
    }
}
