#ifndef MDNSPP_SERVICE_SERVER_H
#define MDNSPP_SERVICE_SERVER_H

#include "mdnspp/records.h"
#include "mdnspp/mdns_base.h"
#include "mdnspp/record_parser.h"

#include <mutex>
#include <atomic>
#include <chrono>

namespace mdnspp {

class record_builder;

class service_server : public mdns_base
{
public:
    struct params
    {
        params(): recv_buf_size(2048), send_buf_size(4096), timeout(500)
        {
        }

        uint32_t recv_buf_size;
        uint32_t send_buf_size;
        std::chrono::milliseconds timeout;
    };

    service_server(const std::string &instance, const std::string &service_name, params p = params());
    service_server(const std::string &instance, const std::string &service_name, std::shared_ptr<log_sink> sink, params p = params());

    bool is_serving() const;

    void serve(const std::vector<service_txt> &txt_records);
    void serve(const std::vector<service_txt> &txt_records, const std::function<void()> &socket_open_callback);

    void announce();

    void serve_and_announce(const std::vector<service_txt> &txt_records);
    void serve_and_announce(const std::vector<service_txt> &txt_records, const std::function<void()> &socket_open_callback);

    void stop() override;

    void update_txt_records(const std::vector<service_txt> &txt_records);

    const std::string &service_instance_name() const;

private:
    std::mutex m_mutex;
    uint32_t m_send_buf_size;
    std::string m_hostname;
    std::string m_service_name;
    std::atomic<bool> m_running;
    std::function<void()> m_on_open;
    std::unique_ptr<char[]> m_buffer;
    std::chrono::milliseconds m_timeout;
    std::shared_ptr<record_builder> m_builder;

    void start(const std::vector<service_txt> &txt_records);
    void announce_goodbye();

    void listen();

    void callback(socket_t socket, record_buffer &buffer) override;

    void serve_dns_sd(socket_t socket, record_parser &parser);
    void serve_ptr(socket_t socket, record_parser &parser);
    void serve_srv(socket_t socket, record_parser &parser);
    void serve_a(socket_t socket, record_parser &parser);
    void serve_aaaa(socket_t socket, record_parser &parser);
    void serve_txt(socket_t socket, record_parser &parser);
};

}

#endif
