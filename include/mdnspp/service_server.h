#ifndef MDNSPP_SERVICE_SERVER_H
#define MDNSPP_SERVICE_SERVER_H

#include "mdnspp/records.h"
#include "mdnspp/mdns_base.h"
#include "mdnspp/message_parser.h"

#include <mutex>
#include <atomic>
#include <chrono>

namespace mdnspp {

class record_builder;
class service_server : public mdns_base
{
public:
    service_server(const std::string &hostname, const std::string &service_name, uint16_t port = 0u);
    service_server(const std::string &hostname, const std::string &service_name, std::shared_ptr<log_sink> sink, uint16_t port = 0u);
    ~service_server();

    bool is_serving() const;

    void serve(const std::vector<service_txt> &txt_records, std::chrono::milliseconds timeout = std::chrono::milliseconds(5000));
    void stop() override;

private:
    uint16_t m_port;
    std::string m_hostname;
    std::string m_service_name;
    std::mutex m_mutex;
    std::atomic<bool> m_running;
    std::unique_ptr<record_builder> m_builder;

    void start(const std::vector<service_txt> &txt_records);
    void announce_service(record_builder service);
    void announce_goodbye(record_builder records);

    void listen(std::chrono::milliseconds timeout);

    void callback(socket_t socket, message_buffer &buffer) override;

    void serve_dns_sd(socket_t socket, message_parser &parser);
    void serve_ptr(socket_t socket, message_parser &parser);
    void serve_srv(socket_t socket, message_parser &parser);
    void serve_a(socket_t socket, message_parser &parser);
    void serve_aaaa(socket_t socket, message_parser &parser);
    void serve_txt(socket_t socket, message_parser &parser);
};

}

#endif
