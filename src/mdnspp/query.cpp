#include "mdnspp/query.h"
#include "mdnspp/mdns_util.h"

#include "mdnspp/impl/query_impl.h"

mdnspp::Query::Query()
{
    // Each query is either a service name, or a pair of record type and a service name
    // For example:
    //  mdns --query _foo._tcp.local.
    //  mdns --query SRV myhost._foo._tcp.local.
    //  mdns --query A myhost._tcp.local. _service._tcp.local.
//    ++iarg;
//    while ((iarg < argc) && (query_count < 16)) {
//        query[query_count].name = argv[iarg++];
//        query[query_count].type = MDNS_RECORDTYPE_PTR;
//        if (iarg < argc) {
//            mdns_record_type_t record_type = 0;
//            if (strcmp(query[query_count].name, "PTR") == 0)
//                record_type = MDNS_RECORDTYPE_PTR;
//            else if (strcmp(query[query_count].name, "SRV") == 0)
//                record_type = MDNS_RECORDTYPE_SRV;
//            else if (strcmp(query[query_count].name, "A") == 0)
//                record_type = MDNS_RECORDTYPE_A;
//            else if (strcmp(query[query_count].name, "AAAA") == 0)
//                record_type = MDNS_RECORDTYPE_AAAA;
//            if (record_type != 0) {
//                query[query_count].type = record_type;
//                query[query_count].name = argv[iarg++];
//            }
//        }
//        query[query_count].length = strlen(query[query_count].name);
//        ++query_count;
//    }
    m_impl = std::make_unique<Query::Impl>();
}

mdnspp::Query::~Query()
{
    m_impl.reset();

}

void mdnspp::Query::send(const query_t &request)
{
    mdns_query_t query;
    query.name = request.name.c_str();
    query.type = static_cast<mdns_record_type_t>(request.type);
    query.length = request.name.length();
    m_impl->send_mdns_query(&query, 1);
}

void mdnspp::Query::send(const std::vector<query_t> &request)
{
    std::vector<mdns_query_t> queries;
    for(const auto &req : request)
    {
        mdns_query_t query;
        query.name = req.name.c_str();
        query.type = static_cast<mdns_record_type_t>(req.type);
        query.length = req.name.length();
        queries.push_back(query);
    }
    m_impl->send_mdns_query(&queries[0], queries.size());
}