#ifndef HPP_GUARD_MDNSPP_SERVICE_AGGREGATION_HELPERS_H
#define HPP_GUARD_MDNSPP_SERVICE_AGGREGATION_HELPERS_H

#include "mdnspp/records.h"

#include <string>
#include <vector>
#include <cstdint>
#include <utility>

inline mdnspp::record_ptr make_ptr(std::string ptr_name)
{
    mdnspp::record_ptr r;
    r.name = "_http._tcp.local";
    r.ptr_name = std::move(ptr_name);
    return r;
}

inline mdnspp::record_srv make_srv(std::string name, std::string srv_name, uint16_t port)
{
    mdnspp::record_srv r;
    r.name = std::move(name);
    r.srv_name = std::move(srv_name);
    r.port = port;
    return r;
}

inline mdnspp::record_a make_a(std::string name, std::string address)
{
    mdnspp::record_a r;
    r.name = std::move(name);
    r.address_string = std::move(address);
    return r;
}

inline mdnspp::record_aaaa make_aaaa(std::string name, std::string address)
{
    mdnspp::record_aaaa r;
    r.name = std::move(name);
    r.address_string = std::move(address);
    return r;
}

inline mdnspp::record_txt make_txt(std::string name, std::vector<mdnspp::service_txt> entries)
{
    mdnspp::record_txt r;
    r.name = std::move(name);
    r.entries = std::move(entries);
    return r;
}

#endif
