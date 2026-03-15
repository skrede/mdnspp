// Multi-service lifecycle example using LocalPolicy and local_bus.
//
// Demonstrates server, monitor, and querier working together through the
// in-process local bus -- no real network sockets. Useful for understanding
// the mDNS lifecycle without needing a real network interface.
//
// Sequence:
//   1. Server announces an HTTP service and probes/announces.
//   2. Monitor watches _http._tcp.local. and reports found/updated/lost events.
//   3. Querier performs a one-shot PTR query for the service type.
//   4. After the server comes live, the service info is updated (triggers on_updated).
//   5. The server is stopped (sends goodbye, triggers on_lost with goodbye reason).
//   6. The executor is stopped once all work is done.

#include <mdnspp/local/local_bus.h>
#include <mdnspp/local/local_timer.h>
#include <mdnspp/local/local_policy.h>
#include <mdnspp/local/local_executor.h>

#include <mdnspp/mdns_options.h>
#include <mdnspp/service_info.h>
#include <mdnspp/basic_querier.h>
#include <mdnspp/query_options.h>
#include <mdnspp/socket_options.h>
#include <mdnspp/monitor_options.h>
#include <mdnspp/service_options.h>
#include <mdnspp/basic_service_server.h>
#include <mdnspp/basic_service_monitor.h>

#include <chrono>
#include <string>
#include <vector>
#include <iostream>

using namespace std::chrono_literals;

// LocalPolicy uses steady_clock and real time. The executor drives its own
// event loop via run(), sleeping 1ms between drain iterations.
using Policy = mdnspp::LocalPolicy;

// Alias the concrete types for readability.
using Bus      = mdnspp::local::local_bus<>;
using Executor = mdnspp::local::local_executor<>;
using Timer    = mdnspp::local::local_timer<>;
using Server   = mdnspp::basic_service_server<Policy>;
using Monitor  = mdnspp::basic_service_monitor<Policy>;
using Querier  = mdnspp::basic_querier<Policy>;

int main()
{
    // Step 1: create the shared in-process bus and executor.
    // All components registered to the same executor share the bus, so every
    // packet sent by one component is visible to all others.
    Bus      bus;
    Executor executor{bus};

    // Step 2: build the service_info for the server to announce.
    mdnspp::service_info info{
        .service_name = "ExampleApp._http._tcp.local.",
        .service_type = "_http._tcp.local.",
        .hostname     = "example-host.local.",
        .port         = 8080,
        .address_ipv4 = "127.0.0.1",
        .txt_records  = {{"version", "1.0"}, {"path", "/api"}},
    };

    // Step 3: create the server. Using default service_options (probe + announce).
    Server server{
        executor,
        info,
        mdnspp::service_options{
            .on_query = [](const mdnspp::endpoint &sender,
                           mdnspp::dns_type        qtype,
                           mdnspp::response_mode   mode)
            {
                std::cout << "[server] query from " << sender
                          << " type=" << to_string(qtype)
                          << " (" << to_string(mode) << ")\n";
            },
        }
    };

    // Step 4: create the monitor. It watches _http._tcp.local. and fires
    // on_found/on_updated/on_lost callbacks as the service lifecycle progresses.
    Monitor monitor{
        executor,
        mdnspp::monitor_options{
            .on_found = [](const mdnspp::resolved_service &svc)
            {
                std::cout << "[monitor] found: " << svc.instance_name.str()
                          << " at " << svc.hostname.str()
                          << ":" << svc.port << "\n";
                if(!svc.ipv4_addresses.empty())
                    std::cout << "          ipv4: " << svc.ipv4_addresses.front() << "\n";
                for(const auto &txt : svc.txt_entries)
                    std::cout << "          txt: " << txt.key << "=" << txt.value.value_or("") << "\n";
            },
            .on_updated = [](const mdnspp::resolved_service &svc,
                             mdnspp::update_event            ev,
                             mdnspp::dns_type                changed_type)
            {
                const char *direction = (ev == mdnspp::update_event::added) ? "added" : "removed";
                std::cout << "[monitor] updated: " << svc.instance_name.str()
                          << " (" << direction << " " << to_string(changed_type) << ")\n";
            },
            .on_lost = [](const mdnspp::resolved_service &svc,
                          mdnspp::loss_reason              reason)
            {
                const char *why = [reason]
                {
                    switch(reason)
                    {
                        case mdnspp::loss_reason::goodbye:   return "goodbye";
                        case mdnspp::loss_reason::timeout:   return "timeout";
                        case mdnspp::loss_reason::unwatched: return "unwatched";
                    }
                    return "unknown";
                }();
                std::cout << "[monitor] lost: " << svc.instance_name.str()
                          << " (reason: " << why << ")\n";
            },
        }
    };
    monitor.watch("_http._tcp.local.");

    // Step 5: create the querier for a one-shot PTR query.
    // It reports each record as it arrives and completes after the silence timeout.
    Querier querier{
        executor,
        mdnspp::query_options{
            .on_record = [](const mdnspp::endpoint &, const mdnspp::mdns_record_variant &rec)
            {
                std::visit([](const auto &r)
                {
                    std::cout << "[querier] record: " << r.name.str() << "\n";
                }, rec);
            },
            .silence_timeout = 3s,
        }
    };

    // Step 6: start all three components.
    // async_start() is non-blocking; the executor drives the event loop.
    std::cout << "[main] starting server, monitor, and querier\n";
    server.async_start(
        [](std::error_code ec)
        {
            if(!ec)
                std::cout << "[server] live (probe+announce complete)\n";
        });

    monitor.async_start();

    querier.async_query("_http._tcp.local.", mdnspp::dns_type::ptr,
        [](std::error_code ec, const std::vector<mdnspp::mdns_record_variant> &results)
        {
            std::cout << "[querier] done (" << results.size() << " records";
            if(ec) std::cout << ", ec=" << ec.message();
            std::cout << ")\n";
        });

    // Step 7: use a local_timer to schedule the update and shutdown sequence.
    // These timers run on the same executor as the server/monitor/querier,
    // so there is no cross-thread synchronisation required.

    // After 5 seconds, update the TXT records to demonstrate on_updated.
    Timer update_timer{executor};
    update_timer.expires_after(5s);
    update_timer.async_wait([&](std::error_code ec)
    {
        if(ec) return;
        std::cout << "[main] updating service info (version 2.0)\n";
        mdnspp::service_info updated = info;
        updated.txt_records = {{"version", "2.0"}, {"path", "/api/v2"}};
        server.update_service_info(std::move(updated));
    });

    // After 10 seconds, stop the server (sends goodbye) to trigger on_lost.
    Timer stop_timer{executor};
    stop_timer.expires_after(10s);
    stop_timer.async_wait([&](std::error_code ec)
    {
        if(ec) return;
        std::cout << "[main] stopping server (sends goodbye)\n";
        server.stop();
    });

    // After 12 seconds, stop the entire executor to end the program.
    Timer exit_timer{executor};
    exit_timer.expires_after(12s);
    exit_timer.async_wait([&](std::error_code ec)
    {
        if(ec) return;
        std::cout << "[main] shutting down\n";
        monitor.stop();
        executor.stop();
    });

    // Step 8: run the executor. Blocks until executor.stop() is called.
    executor.run();

    std::cout << "[main] done\n";
    return 0;
}
