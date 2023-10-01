#ifndef MDNSPP_QUERIER_H
#define MDNSPP_QUERIER_H

#include "mdnspp/records.h"
#include "mdnspp/mdns_base.h"
#include "mdnspp/message_buffer.h"

namespace mdnspp {

struct query_t
{
    std::string name;
    mdns_record_type_t type;
};

class querier : public mdns_base
{
public:
    querier() = default;
    querier(std::shared_ptr<log_sink> sink);
    querier(std::function<void(std::unique_ptr<record_t> record)> on_response);
    explicit querier(std::function<void(std::unique_ptr<record_t> record)> on_response, std::shared_ptr<log_sink> sink);

    void inquire(const query_t &query);
    void inquire(const std::vector<query_t> &query);
    void send_query(mdns_query_t *query, uint16_t count);

private:
    std::function<void(std::unique_ptr<record_t>)> m_on_response;

    void callback(socket_t socket, message_buffer &buffer) override;
};

}

#endif
