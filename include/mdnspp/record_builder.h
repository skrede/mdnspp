#ifndef MDNSPP_RECORD_BUILDER_H
#define MDNSPP_RECORD_BUILDER_H

#include "mdnspp/records.h"

#include <string>
#include <vector>
#include <cstdint>
#include <optional>

#include <mdns.h>

namespace mdnspp {

class record_builder
{
public:
    record_builder(std::string hostname, std::string service_name, std::vector<service_txt> txt_records, std::optional<sockaddr_in> ip_v4, std::optional<sockaddr_in6> ip_v6);

    void initialize_record(record_t &record, mdns_record_type type) const;

    void update_txt_records(std::vector<service_txt> txt_records);

    bool hostname_match(const std::string &name) const;
    bool service_name_match(const std::string &name) const;

    const std::string &service_instance() const;

    bool has_address_ipv4() const;
    uint16_t ipv4_port() const;
    std::string address_ipv4() const;

    bool has_address_ipv6() const;
    uint16_t ipv6_port() const;
    std::string address_ipv6() const;

    record_ptr_t record_ptr() const;
    record_srv_t record_srv() const;
    std::optional<record_a_t> record_a() const;
    std::optional<record_aaaa_t> record_aaaa() const;
    std::vector<record_txt_t> record_txts() const;
    record_ptr_t record_dns_sd(const std::string &name) const;

    mdns_record_t mdns_record_ptr() const;
    mdns_record_t mdns_record_srv() const;
    mdns_record_t mdns_record_a() const;
    mdns_record_t mdns_record_aaaa() const;
    std::vector<mdns_record_t> mdns_record_txts() const;
    mdns_record_t mdns_record_dns_sd(const std::string &name) const;

    std::vector<mdns_record_t> additionals_for(mdns_record_type_t type) const;

private:
    std::string m_name;
    std::string m_hostname;
    std::string m_service_instance;
    std::string m_hostname_qualified;
    std::optional<sockaddr_in> m_address_ipv4;
    std::optional<sockaddr_in6> m_address_ipv6;

    record_ptr_t m_record_ptr;
    record_srv_t m_record_srv;
    std::optional<record_a_t> m_record_a;
    std::vector<record_txt_t> m_txt_records;
    std::optional<record_aaaa_t> m_record_aaaa;
    std::vector<mdns_record_t> m_mdns_txt_records;
};

}

#endif
