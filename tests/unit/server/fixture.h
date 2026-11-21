#ifndef HPP_GUARD_MDNSPP_SERVER_FIXTURE_H
#define HPP_GUARD_MDNSPP_SERVER_FIXTURE_H

#include "helpers.h"

#include "mdnspp/callback_types.h"

#include <catch2/catch_test_macros.hpp>

#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <variant>
#include <system_error>

struct completion
{
    completion()
        : fired{false}
        , ec{}
    {
    }

    bool fired;
    std::error_code ec;
};

inline server_completion_handler record_into(completion &c)
{
    return [&c](std::error_code ec)
    {
        c.fired = true;
        c.ec = ec;
    };
}

inline void check_succeeded(const completion &c)
{
    REQUIRE(c.fired);
    REQUIRE_FALSE(c.ec);
}

template <typename Code>
void check_failed_with(const completion &c, Code expected)
{
    REQUIRE(c.fired);
    REQUIRE(c.ec == expected);
}

inline service_info test_info_on_port(uint16_t port)
{
    service_info info = make_test_info();
    info.port = port;
    return info;
}

inline endpoint mdns_group()
{
    return endpoint{"224.0.0.251", 5353};
}

inline uint16_t flags_of(const sent_packet &packet)
{
    return read_u16_be(packet.data, 2);
}

template <typename Record>
bool contains_record(const std::vector<std::byte> &packet)
{
    for(const auto &rv : parse_response(packet))
    {
        if(std::holds_alternative<Record>(rv))
            return true;
    }
    return false;
}

struct server_fixture
{
    explicit server_fixture(service_info info = make_test_info(), service_options opts = {})
        : done{}
        , ready{}
        , ex{}
        , server{ex, std::move(info), std::move(opts)}
    {
    }

    void start(server_completion_handler on_ready = {}, server_completion_handler on_done = {})
    {
        server.async_start(std::move(on_ready), std::move(on_done));
    }

    void start_recording()
    {
        start(record_into(ready), record_into(done));
    }

    void go_live()
    {
        start();
        advance_to_live(server);
    }

    void fire(uint32_t times = 1)
    {
        for(uint32_t i = 0; i < times; ++i)
            server.timer().fire();
    }

    // The initial delay, probes two and three, then the conflict window.
    void finish_probing()
    {
        fire(4);
    }

    void enqueue(std::vector<std::byte> packet)
    {
        server.socket().enqueue(std::move(packet));
    }

    void inject(const endpoint &from, std::vector<std::byte> packet)
    {
        server.socket().inject_receive(from, std::move(packet));
    }

    void update(service_info info)
    {
        server.update_service_info(std::move(info));
        ex.drain_posted();
    }

    void stop()
    {
        server.stop();
        ex.drain_posted();
    }

    void clear_sent()
    {
        server.socket().clear_sent();
    }

    const std::vector<sent_packet> &sent()
    {
        return server.socket().sent_packets();
    }

    uint16_t header_u16(std::size_t index, std::size_t offset)
    {
        return read_u16_be(sent()[index].data, offset);
    }

    completion done;
    completion ready;
    mock_executor ex;
    basic_service_server<mock_policy> server;
};

#endif
