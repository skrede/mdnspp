#include "mdnspp/impl/service_impl.h"

#include "mdnspp/log.h"
#include "mdnspp/services.h"

#include "mdnspp/impl/message_buffer.h"

using namespace mdnspp;

service::impl::impl(const std::string &hostname, const std::string &service_name, uint16_t port)
    : m_port(port)
    , m_hostname(hostname)
    , m_service_name(service_name)
    , m_records{0}
{
}

bool service::impl::isServing() const
{
    return m_running;
}

void service::impl::serve()
{
    start(m_hostname, m_service_name);
    announceService();
    listen();
}

void service::impl::start(std::string hostname, std::string service_name)
{
    std::lock_guard<std::mutex> l(m_mutex);
    open_service_sockets();

    if(service_name.empty())
        mdnspp::exception() << "Service name can not be empty";
    else if(service_name.back() != '.')
        service_name += '.';

    mdns_string_t service_string = (mdns_string_t) {service_name.c_str(), service_name.length()};
    mdns_string_t hostname_string = (mdns_string_t) {hostname.c_str(), hostname.length()};

    mdnspp::info() << "mDNS service " << hostname << " running on " << service_name << ":" << m_port << " with " << socket_count() << " socket" << (socket_count() == 1 ? "" : "s");;

    // Build the service instance "<hostname>.<_service-name>._tcp.local." string
    std::string service_instance = hostname + "." + service_name;
    std::string hostname_qualified = hostname + ".local";

    service.name = service_string;
    service.hostname = hostname_string;
    service.service_instance = service_string;
    service.hostname_qualified = hostname_string;
    service.address_ipv4 = address_ipv4();
    service.address_ipv6 = address_ipv6();
    service.port = m_port;
    mdnspp::default_records(service, m_records);

    m_running = true;
}

void service::impl::listen()
{
    listen_while<mdns_socket_listen>(
        [this]() -> bool
        {
            return m_running;
        }
    );
}

void service::impl::stop()
{
    std::lock_guard<std::mutex> l(m_mutex);
    if(!m_running)
        return;
    announceGoodbye();
    close_sockets();
}

void service::impl::announceService()
{
    mdns_record_t additional[5] = {0};
    size_t idx = 0;
    additional[idx++] = m_records.record_srv;
    if(has_address_ipv4())
        additional[idx++] = m_records.record_a;
    if(has_address_ipv6())
        additional[idx++] = m_records.record_aaaa;
    additional[idx++] = m_records.txt_record[0];
    additional[idx++] = m_records.txt_record[1];

    send([&](index_t soc_idx, socket_t socket, void *buffer, size_t capacity)
         {
             mdns_announce_multicast(socket, buffer, capacity, m_records.record_ptr, 0, 0, additional, idx);
         }
    );
}

void service::impl::announceGoodbye()
{
    mdns_record_t additional[5] = {0};
    size_t additional_count = 0;
    additional[additional_count++] = m_records.record_srv;
    if(has_address_ipv4())
        additional[additional_count++] = m_records.record_a;
    if(has_address_ipv6())
        additional[additional_count++] = m_records.record_aaaa;
    additional[additional_count++] = m_records.txt_record[0];
    additional[additional_count++] = m_records.txt_record[1];

    send([&](index_t soc_idx, socket_t socket, void *buffer, size_t capacity)
         {
             mdns_goodbye_multicast(socket, buffer, capacity, m_records.record_ptr, 0, 0, additional, additional_count);
         }
    );
}

void service::impl::callback(socket_t socket, const message_buffer &buffer)
{
    char addr_buffer[64];
    char entry_buffer[256];
    char name_buffer[256];
    char send_buffer[1024];

    if(entry != MDNS_ENTRYTYPE_QUESTION)
        return;

    const char dns_sd[] = "_services._dns-sd._udp.local.";

    mdns_string_t from_addr_str = ip_address_to_string(addr_buffer, sizeof(addr_buffer), from, addrlen);

    mdns_string_t name = mdns_string_extract(data, size, &name_offset, name_buffer, sizeof(name_buffer));

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
        return;
    printf("Query %s %.*s\n", record_name, MDNS_STRING_FORMAT(name));

    if((name.length == (sizeof(dns_sd) - 1)) && (strncmp(name.str, dns_sd, sizeof(dns_sd) - 1) == 0))
    {
        if((rtype == MDNS_RECORDTYPE_PTR) || (rtype == MDNS_RECORDTYPE_ANY))
        {
            // The PTR query was for the DNS-SD domain, send answer with a PTR record for the
            // service name we advertise, typically on the "<_service-name>._tcp.local." format

            // Answer PTR record reverse mapping "<_service-name>._tcp.local." to
            // "<hostname>.<_service-name>._tcp.local."
            mdns_record_t answer;
            answer.name = name;
            answer.type = MDNS_RECORDTYPE_PTR;
            answer.data.ptr.name = service.name;

            // Send the answer, unicast or multicast depending on flag in query
            uint16_t unicast = (rclass & MDNS_UNICAST_RESPONSE);
            printf("  --> answer %.*s (%s)\n", MDNS_STRING_FORMAT(answer.data.ptr.name), (unicast ? "unicast" : "multicast"));

            if(unicast)
                mdns_query_answer_unicast(socket, from, addrlen, send_buffer, sizeof(send_buffer), query_id, rtype, name.str, name.length, answer, nullptr, 0, nullptr, 0);
            else
                mdns_query_answer_multicast(socket, send_buffer, sizeof(send_buffer), answer, 0, 0, 0, 0);
        }
    }
    else if((name.length == service.name.length) && (strncmp(name.str, service.name.str, name.length) == 0))
    {
        if((rtype == MDNS_RECORDTYPE_PTR) || (rtype == MDNS_RECORDTYPE_ANY))
        {
            // The PTR query was for our service (usually "<_service-name._tcp.local"), answer a PTR
            // record reverse mapping the queried service name to our service instance name
            // (typically on the "<hostname>.<_service-name>._tcp.local." format), and add
            // additional records containing the SRV record mapping the service instance name to our
            // qualified hostname (typically "<hostname>.local.") and port, as well as any IPv4/IPv6
            // address for the hostname as A/AAAA records, and two test TXT records

            // Answer PTR record reverse mapping "<_service-name>._tcp.local." to
            // "<hostname>.<_service-name>._tcp.local."
            mdns_record_t answer = m_records.record_ptr;

            mdns_record_t additional[5] = {0};
            size_t additional_count = 0;

            // SRV record mapping "<hostname>.<_service-name>._tcp.local." to
            // "<hostname>.local." with port. Set weight & priority to 0.
            additional[additional_count++] = m_records.record_srv;

            // A/AAAA records mapping "<hostname>.local." to IPv4/IPv6 addresses
            if(service.address_ipv4.sin_family == AF_INET)
                additional[additional_count++] = m_records.record_a;
            if(service.address_ipv6.sin6_family == AF_INET6)
                additional[additional_count++] = m_records.record_aaaa;

            // Add two test TXT records for our service instance name, will be coalesced into
            // one record with both key-value pair strings by the library
            additional[additional_count++] = m_records.txt_record[0];
            additional[additional_count++] = m_records.txt_record[1];

            // Send the answer, unicast or multicast depending on flag in query
            uint16_t unicast = (rclass & MDNS_UNICAST_RESPONSE);
            printf("  --> answer %.*s (%s)\n", MDNS_STRING_FORMAT(m_records.record_ptr.data.ptr.name), (unicast ? "unicast" : "multicast"));

            if(unicast)
                mdns_query_answer_unicast(socket, from, addrlen, send_buffer, sizeof(send_buffer), query_id, rtype, name.str, name.length, answer, 0, 0, additional, additional_count);
            else
                mdns_query_answer_multicast(socket, send_buffer, sizeof(send_buffer), answer, 0, 0, additional, additional_count);
        }
    }
    else if((name.length == service.service_instance.length) && (strncmp(name.str, service.service_instance.str, name.length) == 0))
    {
        if((rtype == MDNS_RECORDTYPE_SRV) || (rtype == MDNS_RECORDTYPE_ANY))
        {
            // The SRV query was for our service instance (usually
            // "<hostname>.<_service-name._tcp.local"), answer a SRV record mapping the service
            // instance name to our qualified hostname (typically "<hostname>.local.") and port, as
            // well as any IPv4/IPv6 address for the hostname as A/AAAA records, and two test TXT
            // records

            // Answer PTR record reverse mapping "<_service-name>._tcp.local." to
            // "<hostname>.<_service-name>._tcp.local."
            mdns_record_t answer = m_records.record_srv;

            mdns_record_t additional[5] = {0};
            size_t additional_count = 0;

            // A/AAAA records mapping "<hostname>.local." to IPv4/IPv6 addresses
            if(service.address_ipv4.sin_family == AF_INET)
                additional[additional_count++] = m_records.record_a;
            if(service.address_ipv6.sin6_family == AF_INET6)
                additional[additional_count++] = m_records.record_aaaa;

            // Add two test TXT records for our service instance name, will be coalesced into
            // one record with both key-value pair strings by the library
            additional[additional_count++] = m_records.txt_record[0];
            additional[additional_count++] = m_records.txt_record[1];

            // Send the answer, unicast or multicast depending on flag in query
            uint16_t unicast = (rclass & MDNS_UNICAST_RESPONSE);
            printf("  --> answer %.*s port %d (%s)\n",
                   MDNS_STRING_FORMAT(m_records.record_srv.data.srv.name), service.port,
                   (unicast ? "unicast" : "multicast"));

            if(unicast)
                mdns_query_answer_unicast(socket, from, addrlen, send_buffer, sizeof(send_buffer), query_id, rtype, name.str, name.length, answer, 0, 0, additional, additional_count);
            else
                mdns_query_answer_multicast(socket, send_buffer, sizeof(send_buffer), answer, 0, 0, additional, additional_count);
        }
    }
    else if((name.length == service.hostname_qualified.length) && (strncmp(name.str, service.hostname_qualified.str, name.length) == 0))
    {
        if(((rtype == MDNS_RECORDTYPE_A) || (rtype == MDNS_RECORDTYPE_ANY)) && (service.address_ipv4.sin_family == AF_INET))
        {
            // The A query was for our qualified hostname (typically "<hostname>.local.") and we
            // have an IPv4 address, answer with an A record mappiing the hostname to an IPv4
            // address, as well as any IPv6 address for the hostname, and two test TXT records

            // Answer A records mapping "<hostname>.local." to IPv4 address
            mdns_record_t answer = m_records.record_a;

            mdns_record_t additional[5] = {0};
            size_t additional_count = 0;

            // AAAA record mapping "<hostname>.local." to IPv6 addresses
            if(service.address_ipv6.sin6_family == AF_INET6)
                additional[additional_count++] = m_records.record_aaaa;

            // Add two test TXT records for our service instance name, will be coalesced into
            // one record with both key-value pair strings by the library
            additional[additional_count++] = m_records.txt_record[0];
            additional[additional_count++] = m_records.txt_record[1];

            // Send the answer, unicast or multicast depending on flag in query
            uint16_t unicast = (rclass & MDNS_UNICAST_RESPONSE);
            mdns_string_t addrstr = ip_address_to_string(
                addr_buffer, sizeof(addr_buffer), (struct sockaddr *) &m_records.record_a.data.a.addr,
                sizeof(m_records.record_a.data.a.addr));
            printf("  --> answer %.*s IPv4 %.*s (%s)\n", MDNS_STRING_FORMAT(m_records.record_a.name),
                   MDNS_STRING_FORMAT(addrstr), (unicast ? "unicast" : "multicast"));

            if(unicast)
                mdns_query_answer_unicast(socket, from, addrlen, send_buffer, sizeof(send_buffer), query_id, rtype, name.str, name.length, answer, 0, 0, additional, additional_count);
            else
                mdns_query_answer_multicast(socket, send_buffer, sizeof(send_buffer), answer, 0, 0, additional, additional_count);
        }
        else if(((rtype == MDNS_RECORDTYPE_AAAA) || (rtype == MDNS_RECORDTYPE_ANY)) && (service.address_ipv6.sin6_family == AF_INET6))
        {
            // The AAAA query was for our qualified hostname (typically "<hostname>.local.") and we
            // have an IPv6 address, answer with an AAAA record mappiing the hostname to an IPv6
            // address, as well as any IPv4 address for the hostname, and two test TXT records

            // Answer AAAA records mapping "<hostname>.local." to IPv6 address
            mdns_record_t answer = m_records.record_aaaa;

            mdns_record_t additional[5] = {0};
            size_t additional_count = 0;

            // A record mapping "<hostname>.local." to IPv4 addresses
            if(service.address_ipv4.sin_family == AF_INET)
                additional[additional_count++] = m_records.record_a;

            // Add two test TXT records for our service instance name, will be coalesced into
            // one record with both key-value pair strings by the library
            additional[additional_count++] = m_records.txt_record[0];
            additional[additional_count++] = m_records.txt_record[1];

            // Send the answer, unicast or multicast depending on flag in query
            uint16_t unicast = (rclass & MDNS_UNICAST_RESPONSE);
            mdns_string_t addrstr = ip_address_to_string(addr_buffer, sizeof(addr_buffer), (struct sockaddr *) &m_records.record_aaaa.data.aaaa.addr, sizeof(m_records.record_aaaa.data.aaaa.addr));
            printf("  --> answer %.*s IPv6 %.*s (%s)\n", MDNS_STRING_FORMAT(m_records.record_aaaa.name), MDNS_STRING_FORMAT(addrstr), (unicast ? "unicast" : "multicast"));

            if(unicast)
                mdns_query_answer_unicast(socket, from, addrlen, send_buffer, sizeof(send_buffer), query_id, rtype, name.str, name.length, answer, 0, 0, additional, additional_count);
            else
                mdns_query_answer_multicast(socket, send_buffer, sizeof(send_buffer), answer, 0, 0, additional, additional_count);
        }
    }
}
