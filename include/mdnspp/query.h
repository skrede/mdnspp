#ifndef MDNSPP_QUERY_H
#define MDNSPP_QUERY_H

#include <mdns.h>

#include <memory>
#include <string>
#include <vector>

namespace mdnspp {

struct query_t
{
    std::string name;
    mdns_record_type_t type;
};

class query
{
    class impl;
public:
    query();
    query(query &&) = delete;
    query(const query &) = delete;
    ~query();

    void send(const query_t &request);
    void send(const std::vector<query_t> &request);

private:
    std::unique_ptr<query::impl> m_impl;
};

}

#endif
