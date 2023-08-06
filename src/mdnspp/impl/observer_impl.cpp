#include "mdnspp/impl/observer_impl.h"

#include "mdnspp/impl/message_parser.h"

using namespace mdnspp;

observer::impl::impl()
    : m_running{false}
{
}

void observer::impl::observe()
{
    m_running = true;
    open_service_sockets();
    listen_while<mdns_socket_listen>(
        [this]() -> bool
        {
            return m_running;
        });
    close_sockets();
}

void observer::impl::stop()
{
    m_running = false;
}

void observer::impl::callback(socket_t socket, std::shared_ptr<message_buffer> buffer)
{
    char addr_buffer[64];
    char name_buffer[256];

    message_parser parser(buffer);

    auto name_offset = buffer->name_offset();
    auto ttl = buffer->ttl();
    auto rtype = buffer->rtype();
    auto entry = buffer->entry();
    auto rclass = buffer->rclass();
    mdns_string_t from_addr_str = ip_address_to_string(addr_buffer, sizeof(addr_buffer), &buffer->sender(), buffer->address_length());
    mdns_string_t name = mdns_string_extract(buffer->data().get(), buffer->size(), &name_offset, name_buffer, sizeof(name_buffer));

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

    printf("%.*s: %s %s %.*s rclass 0x%x ttl %u\n", MDNS_STRING_FORMAT(from_addr_str), entry_type, record_name, MDNS_STRING_FORMAT(name), (unsigned int) rclass, ttl);
}