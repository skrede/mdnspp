#ifndef MDNSPP_QUERIER_H
#define MDNSPP_QUERIER_H

#include "mdnspp/records.h"
#include "mdnspp/mdns_base.h"
#include "mdnspp/record_buffer.h"

namespace mdnspp {

struct query_t
{
    std::string name;
    mdns_record_type_t type;
};

class querent : public mdns_base
{
public:
    struct params
    {
        params() : recv_buf_size(2048), send_buf_size(4096), timeout(500)
        {
        }

        uint32_t recv_buf_size;
        uint32_t send_buf_size;
        std::chrono::milliseconds timeout;
    };

    explicit querent(params p = params());
    explicit querent(std::shared_ptr<log_sink> sink, params p = params());
    explicit querent(std::function<void(std::shared_ptr<record_t> record)> on_response, params p = params());
    querent(std::function<void(std::shared_ptr<record_t> record)> on_response, std::shared_ptr<log_sink> sink, params p = params());

    void query(const query_t &inquiry);
    void query(const query_t &inquiry, std::vector<record_filter> filters);

    void query(const std::vector<query_t> &inquiry);
    void query(const std::vector<query_t> &inquiry, std::vector<record_filter> filters);

    void send_query(mdns_query_t *inquiry, uint16_t count);
    void send_query(mdns_query_t *inquiry, uint16_t count, std::vector<record_filter> filters);

private:
    uint32_t m_send_buf_size;
    std::unique_ptr<char[]> m_send_buf;
    std::chrono::milliseconds m_timeout;
    std::vector<record_filter> m_filters;
    std::function<void(std::shared_ptr<record_t>)> m_on_response;

    bool filter_ignore_record(const std::shared_ptr<record_t> &record);
    void callback(socket_t socket, record_buffer &buffer) override;
};

}

#endif
