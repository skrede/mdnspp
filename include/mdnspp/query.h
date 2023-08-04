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

class QueryPrivate;

class Query
{
public:
    Query();
    Query(Query &&) = delete;
    Query(const Query &) = delete;
    ~Query();

    void send(const query_t &request);
    void send(const std::vector<query_t> &request);

private:
    std::unique_ptr<QueryPrivate> m_query;
};

}

#endif
