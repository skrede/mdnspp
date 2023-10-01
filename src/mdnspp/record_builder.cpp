#include "mdnspp/record_builder.h"

#include "mdnspp/log.h"
#include "mdnspp/mdns_util.h"

using namespace mdnspp;

void initialize_record(record_t &record, mdns_record_type type)
{
    record.ttl = 0u;
    record.rclass = 0u;
    record.rtype = type;
}

record_builder::record_builder(std::string hostname, std::string service_name, const std::vector<service_txt> &txt_records, std::optional<sockaddr_in> ip_v4, std::optional<sockaddr_in6> ip_v6)
    : m_name(service_name)
    , m_hostname(hostname)
    , m_address_ipv4(ip_v4)
    , m_address_ipv6(ip_v6)
    , m_record_ptr(mdns_entry_type::MDNS_ENTRYTYPE_ANSWER)
    , m_record_srv(mdns_entry_type::MDNS_ENTRYTYPE_ANSWER)
{

    if(service_name.empty())
        throw std::runtime_error("Service name can not be empty");
    else if(service_name.back() != '.')
        service_name += '.';

    // Build the service instance "<hostname>.<_service-name>._tcp.local." string
    std::string service_instance = hostname + "." + service_name;
    std::string hostname_qualified = hostname + ".local.";

    m_name = service_name;
    m_hostname = hostname;
    m_service_instance = service_instance;
    m_hostname_qualified = hostname_qualified;

    // Setup our mDNS records
    // PTR record reverse mapping "<_service-name>._tcp.local." to
    // "<hostname>.<_service-name>._tcp.local."
    initialize_record(m_record_ptr, MDNS_RECORDTYPE_PTR);
    m_record_ptr.name = m_name;
    m_record_ptr.ptr_name = service_instance;

    // SRV record mapping "<hostname>.<_service-name>._tcp.local." to
    // "<hostname>.local." with port. Set weight & priority to 0.
    initialize_record(m_record_srv, MDNS_RECORDTYPE_SRV);
    m_record_srv.weight = 0;
    m_record_srv.priority = 0;
    m_record_srv.name = service_instance;
    m_record_srv.srv_name = hostname_qualified;

    // A/AAAA records mapping "<hostname>.local." to IPv4/IPv6 addresses
    if(has_address_ipv4())
    {
        record_a_t record_a(mdns_entry_type::MDNS_ENTRYTYPE_ANSWER);
        initialize_record(record_a, MDNS_RECORDTYPE_A);
        record_a.name = hostname_qualified;
        auto sockaddr = m_address_ipv4.value();
        record_a.addr = m_address_ipv4.value();
        record_a.address_string = ip_address_to_string(sockaddr);
        m_record_a.emplace(record_a);
    }

    if(has_address_ipv6())
    {
        record_aaaa_t record_aaaa(mdns_entry_type::MDNS_ENTRYTYPE_ANSWER);
        initialize_record(record_aaaa, MDNS_RECORDTYPE_AAAA);
        record_aaaa.name = hostname_qualified;
        record_aaaa.addr = m_address_ipv6.value();
        auto sockaddr = m_address_ipv6.value();
        record_aaaa.address_string = ip_address_to_string(sockaddr);
        m_record_aaaa.emplace(record_aaaa);
    }

    for(const auto &txt : txt_records)
    {
        record_txt_t record_txt(mdns_entry_type::MDNS_ENTRYTYPE_ANSWER);
        initialize_record(record_txt, MDNS_RECORDTYPE_TXT);
        record_txt.key = txt.key;
        record_txt.value = txt.value;
        m_txt_records.push_back(record_txt);
    }
}

bool record_builder::hostname_match(const std::string &name) const
{
    return name == m_hostname_qualified;
}

bool record_builder::service_name_match(const std::string &name) const
{
    return name == m_service_instance;
}

bool record_builder::has_address_ipv4() const
{
    return m_address_ipv4.has_value();
}

uint16_t record_builder::ipv4_port() const
{
    return m_address_ipv4->sin_port;
}

std::string record_builder::address_ipv4() const
{
    return m_record_a->address_string;
}

bool record_builder::has_address_ipv6() const
{
    return m_address_ipv6.has_value();
}

uint16_t record_builder::ipv6_port() const
{
    return m_address_ipv6->sin6_port;
}

std::string record_builder::address_ipv6() const
{
    return m_record_aaaa->address_string;
}

record_ptr_t record_builder::record_ptr() const
{
    return m_record_ptr;
}

record_srv_t record_builder::record_srv() const
{
    return m_record_srv;
}

std::optional<record_a_t> record_builder::record_a() const
{
    return m_record_a;
}

std::optional<record_aaaa_t> record_builder::record_aaaa() const
{
    return m_record_aaaa;
}

std::vector<record_txt_t> record_builder::record_txts() const
{
    return m_txt_records;
}

record_ptr_t record_builder::record_dns_sd(const std::string &name) const
{
    record_ptr_t ret(mdns_entry_type::MDNS_ENTRYTYPE_ANSWER);
    ret.name = name;
    ret.ptr_name = m_name;
    return ret;
}

mdns_record_t record_builder::mdns_record_ptr() const
{
    mdns_record_t ret;
    ret.ttl = m_record_ptr.ttl;
    ret.rclass = m_record_ptr.rclass;
    ret.type = static_cast<mdns_record_type_t>(m_record_ptr.rtype);
    ret.name.str = m_record_ptr.name.c_str();
    ret.name.length = m_record_ptr.name.length();
    ret.data.ptr.name.str = m_record_ptr.ptr_name.c_str();
    ret.data.ptr.name.length = m_record_ptr.ptr_name.length();
    return ret;
}

mdns_record_t record_builder::mdns_record_srv() const
{
    mdns_record_t ret;
    ret.ttl = m_record_srv.ttl;
    ret.rclass = m_record_srv.rclass;
    ret.type = static_cast<mdns_record_type_t>(m_record_srv.rtype);
    ret.name.str = m_record_srv.name.c_str();
    ret.name.length = m_record_srv.name.length();
    ret.data.srv.port = 0u;
    ret.data.srv.weight = m_record_srv.weight;
    ret.data.srv.priority = m_record_srv.priority;
    ret.data.srv.name.str = m_record_srv.srv_name.c_str();
    ret.data.srv.name.length = m_record_srv.srv_name.length();
    return ret;
}

mdns_record_t record_builder::mdns_record_a() const
{
    mdns_record_t ret;
    if(m_record_a)
    {
        ret.ttl = m_record_a->ttl;
        ret.rclass = m_record_a->rclass;
        ret.type = static_cast<mdns_record_type_t>(m_record_a->rtype);
        ret.name.str = m_record_a->name.c_str();
        ret.name.length = m_record_a->name.length();
        ret.data.a.addr = m_record_a->addr;
    }
    return ret;
}

mdns_record_t record_builder::mdns_record_aaaa() const
{
    mdns_record_t ret;
    if(m_record_aaaa)
    {
        ret.ttl = m_record_aaaa->ttl;
        ret.rclass = m_record_aaaa->rclass;
        ret.type = static_cast<mdns_record_type_t>(m_record_aaaa->rtype);
        ret.name.str = m_record_aaaa->name.c_str();
        ret.name.length = m_record_aaaa->name.length();
        ret.data.aaaa.addr = m_record_aaaa->addr;
    }
    return ret;
}

std::vector<mdns_record_t> record_builder::mdns_record_txts() const
{
    std::vector<mdns_record_t> ret(m_txt_records.size());
    size_t idx = 0;
    for(const auto &txt : m_txt_records)
    {
        mdns_record_t txt_record;
        txt_record.ttl = txt.ttl;
        txt_record.rclass = txt.rclass;
        txt_record.type = static_cast<mdns_record_type_t>(txt.rtype);
        txt_record.name.str = txt.name.c_str();
        txt_record.name.length = txt.name.length();
        txt_record.data.txt.key.str = txt.key.c_str();
        txt_record.data.txt.key.length = txt.key.length();
        if(txt.value.has_value())
        {
            txt_record.data.txt.value.str = txt.value->c_str();
            txt_record.data.txt.value.length = txt.value->length();
        }
        else
            txt_record.data.txt.value.length = 0;
        ret[idx++] = txt_record;
    }
    return ret;
}

mdns_record_t record_builder::mdns_record_dns_sd(const std::string &name) const
{
    mdns_record_t dns_sd;
    dns_sd.name.str = name.c_str();
    dns_sd.name.length = name.length();
    dns_sd.type = MDNS_RECORDTYPE_PTR;
    dns_sd.data.ptr.name.str = m_name.c_str();
    dns_sd.data.ptr.name.length = m_name.length();
    return dns_sd;
}

std::vector<mdns_record_t> record_builder::additionals_for(mdns_record_type_t type) const
{
    std::vector<mdns_record_t> additional = mdns_record_txts();
    if(type == MDNS_RECORDTYPE_PTR)
        additional.push_back(mdns_record_srv());
    if(type != MDNS_RECORDTYPE_A && has_address_ipv4())
        additional.push_back(mdns_record_a());
    if(type != MDNS_RECORDTYPE_AAAA && has_address_ipv6())
        additional.push_back(mdns_record_aaaa());
    return additional;
}