#include "helpers.h"

#include <catch2/catch_test_macros.hpp>

SCENARIO("probing sends 3 probe queries to multicast", "[service_server][probing]")
{
    GIVEN("a service_server")
    {
        mock_executor ex;
        basic_service_server<MockPolicy> server{ex, make_test_info()};

        WHEN("async_start is called and probing completes")
        {
            server.async_start();

            // Fire initial delay
            server.timer().fire();
            size_t after_first = server.socket().sent_packets().size();
            REQUIRE(after_first == 1); // first probe sent

            // Fire for probe 2
            server.timer().fire();
            size_t after_second = server.socket().sent_packets().size();
            REQUIRE(after_second == 2);

            // Fire for probe 3
            server.timer().fire();
            size_t after_third = server.socket().sent_packets().size();
            REQUIRE(after_third == 3);

            THEN("3 probe queries were sent to 224.0.0.251:5353")
            {
                for(size_t i = 0; i < 3; ++i)
                {
                    REQUIRE(server.socket().sent_packets()[i].dest == endpoint{"224.0.0.251", 5353});

                    // Verify probe packets have flags=0x0000 (query, not response)
                    const auto &pkt = server.socket().sent_packets()[i].data;
                    REQUIRE(pkt.size() >= 4);
                    uint16_t flags = read_u16_be(pkt, 2);
                    REQUIRE(flags == 0x0000);
                }
            }
        }
    }
}

SCENARIO("probing uses 250ms intervals", "[service_server][probing][timing]")
{
    GIVEN("a service_server")
    {
        mock_executor ex;
        basic_service_server<MockPolicy> server{ex, make_test_info()};

        WHEN("async_start is called and probes are sent")
        {
            server.async_start();

            // Initial delay is random 0-250ms, fire it
            server.timer().fire();

            THEN("subsequent probe timers are armed at 250ms intervals")
            {
                // After first probe, timer should be 250ms for next probe
                REQUIRE(server.timer().last_duration() == std::chrono::milliseconds(250));

                server.timer().fire(); // probe 2
                REQUIRE(server.timer().last_duration() == std::chrono::milliseconds(250));

                server.timer().fire(); // probe 3
                // After last probe, wait 250ms for conflict window
                REQUIRE(server.timer().last_duration() == std::chrono::milliseconds(250));
            }
        }
    }
}

SCENARIO("server enters live state after probe+announce sequence", "[service_server][probing][lifecycle]")
{
    GIVEN("a service_server with on_ready callback")
    {
        mock_executor ex;
        bool ready_fired = false;
        std::error_code ready_ec;

        basic_service_server<MockPolicy> server{ex, make_test_info()};

        WHEN("async_start is called and probe+announce completes")
        {
            server.async_start([&](std::error_code ec)
            {
                ready_fired = true;
                ready_ec = ec;
            });
            advance_to_live(server);

            THEN("on_ready fires with success")
            {
                REQUIRE(ready_fired);
                REQUIRE_FALSE(ready_ec);
            }
        }
    }
}

SCENARIO("queries dropped during probing", "[service_server][probing][drop]")
{
    GIVEN("a service_server with a PTR query enqueued before start")
    {
        mock_executor ex;
        endpoint sender{"192.168.1.50", 5353};

        basic_service_server<MockPolicy> server{ex, make_test_info()};
        server.socket().enqueue(make_ptr_query("_http._tcp.local."), sender);

        WHEN("async_start is called (query is received during probing)")
        {
            server.async_start();
            advance_to_live(server);

            THEN("no response was sent to the querier (query was dropped during probing)")
            {
                bool has_response_to_sender = false;
                for(const auto &pkt : server.socket().sent_packets())
                {
                    if(pkt.dest == sender)
                        has_response_to_sender = true;
                }
                REQUIRE_FALSE(has_response_to_sender);
            }
        }
    }
}

SCENARIO("conflict detected from incoming response during probing", "[service_server][conflict]")
{
    GIVEN("a service_server with on_ready but no on_conflict callback, and a conflict response enqueued")
    {
        mock_executor ex;
        bool ready_fired = false;
        std::error_code ready_ec;

        basic_service_server<MockPolicy> server{ex, make_test_info()};

        // Enqueue a conflict response that will be received during probing.
        // The response has QR=1 (flags=0x8400) and contains records matching our service name.
        auto conflict = make_conflict_response(make_test_info());
        server.socket().enqueue(std::move(conflict));

        WHEN("async_start is called")
        {
            server.async_start([&](std::error_code ec)
            {
                ready_fired = true;
                ready_ec = ec;
            });

            THEN("on_ready fires with probe_conflict error")
            {
                REQUIRE(ready_fired);
                REQUIRE(ready_ec == mdns_error::probe_conflict);
            }
        }
    }
}

SCENARIO("conflict callback can rename and retry probing", "[service_server][conflict][retry]")
{
    GIVEN("a service_server with on_conflict that renames")
    {
        mock_executor ex;
        bool conflict_called = false;
        unsigned conflict_attempt = 99;
        bool ready_fired = false;
        std::error_code ready_ec;

        service_options opts;
        opts.on_conflict = [&](const std::string &, std::string &new_name, unsigned attempt, conflict_type) -> bool
        {
            conflict_called = true;
            conflict_attempt = attempt;
            new_name = "Renamed._http._tcp.local.";
            return true;
        };

        basic_service_server<MockPolicy> server{ex, make_test_info(), std::move(opts)};

        // Enqueue conflict response
        server.socket().enqueue(make_conflict_response(make_test_info()));

        WHEN("async_start is called and conflict is detected")
        {
            server.async_start([&](std::error_code ec)
            {
                ready_fired = true;
                ready_ec = ec;
            });

            THEN("on_conflict was called with attempt=0")
            {
                REQUIRE(conflict_called);
                REQUIRE(conflict_attempt == 0);
            }

            AND_THEN("server restarts probing and eventually reaches live state")
            {
                // Server restarted probing after rename. Advance to live again.
                advance_to_live(server);

                REQUIRE(ready_fired);
                REQUIRE_FALSE(ready_ec);
            }
        }
    }
}

SCENARIO("conflict callback returning false stops server", "[service_server][conflict][give-up]")
{
    GIVEN("a service_server with on_conflict returning false")
    {
        mock_executor ex;
        bool ready_fired = false;
        std::error_code ready_ec;

        service_options opts;
        opts.on_conflict = [](const std::string &, std::string &, unsigned, conflict_type) -> bool
        {
            return false;
        };

        basic_service_server<MockPolicy> server{ex, make_test_info(), std::move(opts)};
        server.socket().enqueue(make_conflict_response(make_test_info()));

        WHEN("async_start is called and conflict fires")
        {
            server.async_start([&](std::error_code ec)
            {
                ready_fired = true;
                ready_ec = ec;
            });

            THEN("on_ready fires with probe_conflict")
            {
                REQUIRE(ready_fired);
                REQUIRE(ready_ec == mdns_error::probe_conflict);
            }
        }
    }
}

SCENARIO("stop during probing fires on_ready with operation_canceled", "[service_server][probing][stop]")
{
    GIVEN("a service_server with on_ready and on_done callbacks")
    {
        mock_executor ex;
        bool ready_fired = false;
        std::error_code ready_ec;
        bool done_fired = false;
        std::error_code done_ec;

        basic_service_server<MockPolicy> server{ex, make_test_info()};

        WHEN("async_start is called then stop() is called while probing")
        {
            server.async_start(
                [&](std::error_code ec) { ready_fired = true; ready_ec = ec; },
                [&](std::error_code ec) { done_fired = true; done_ec = ec; }
            );
            server.stop();
            ex.drain_posted();

            THEN("on_ready fired with operation_canceled")
            {
                REQUIRE(ready_fired);
                REQUIRE(ready_ec == std::errc::operation_canceled);
            }

            AND_THEN("on_done fired with success")
            {
                REQUIRE(done_fired);
                REQUIRE_FALSE(done_ec);
            }
        }
    }
}

// Helper: build a conflicting probe packet from another host.
// The probe has a SRV record in the authority section with different rdata.
static std::vector<std::byte> make_conflicting_probe(const service_info &our_info,
                                                      uint16_t other_probe_id,
                                                      uint8_t rdata_filler)
{
    // Build a probe for the same service name but with a different SRV rdata.
    // We manipulate the rdata by using a different priority to force a tiebreak.
    service_info other = our_info;
    other.priority = static_cast<uint16_t>(rdata_filler); // different priority byte
    auto probe = build_probe_query(other);
    // Override transaction ID with other_probe_id
    probe[0] = static_cast<std::byte>(other_probe_id >> 8);
    probe[1] = static_cast<std::byte>(other_probe_id & 0xFF);
    return probe;
}

SCENARIO("Probe tiebreaking: loser defers and conflict_type is tiebreak_deferred", "[service_server][probe][tiebreaking]")
{
    GIVEN("a server probing with priority=0 and another probe arrives with priority=1 (ours < theirs -- we lose)")
    {
        mock_executor ex;
        conflict_type observed_conflict_type = conflict_type::name_conflict;
        bool conflict_called = false;

        service_options opts;
        opts.probe_initial_delay_max = std::chrono::milliseconds{0};
        opts.probe_defer_delay = std::chrono::milliseconds{100};
        opts.on_conflict = [&](const std::string &, std::string &, unsigned, conflict_type ct) -> bool
        {
            conflict_called = true;
            observed_conflict_type = ct;
            return true; // always retry
        };

        service_info info = make_test_info();
        info.priority = 0; // our priority (lower)
        basic_service_server<MockPolicy> server{ex, info, std::move(opts)};

        WHEN("async_start is called, probe begins, and a winning probe arrives from another host")
        {
            server.async_start();
            // Fire initial delay timer so probing starts
            server.timer().fire();

            // At this point we've sent our first probe. Now inject a conflicting probe
            // from another host (different transaction ID, priority=255 > our priority=0).
            // Since their priority (255) > ours (0), their rdata is lexicographically greater
            // -- they win, we lose and should defer.
            auto their_probe = make_conflicting_probe(info, 0xABCD, 255);
            server.socket().inject_receive(endpoint{"192.168.1.99", 5353}, their_probe);

            THEN("on_conflict is called with conflict_type::tiebreak_deferred")
            {
                REQUIRE(conflict_called);
                REQUIRE(observed_conflict_type == conflict_type::tiebreak_deferred);
            }

            THEN("the probe timer is rearmed for defer delay after tiebreak loss")
            {
                REQUIRE(server.timer().has_pending());
            }
        }
    }
}

SCENARIO("Probe tiebreaking: winner (ours > theirs) does NOT defer", "[service_server][probe][tiebreaking][win]")
{
    GIVEN("a server probing with priority=255 and another probe arrives with priority=0 (ours > theirs -- we win)")
    {
        mock_executor ex;
        bool conflict_called = false;

        service_options opts;
        opts.probe_initial_delay_max = std::chrono::milliseconds{0};
        opts.on_conflict = [&](const std::string &, std::string &, unsigned, conflict_type) -> bool
        {
            conflict_called = true;
            return true;
        };

        service_info info = make_test_info();
        info.priority = 255; // our priority (higher -- we win)
        basic_service_server<MockPolicy> server{ex, info, std::move(opts)};

        WHEN("async_start is called, probe begins, and a losing probe arrives from another host")
        {
            server.async_start();
            server.timer().fire(); // fire initial delay

            // Their priority=0 < ours=255, so we win the tiebreak.
            auto their_probe = make_conflicting_probe(info, 0x1234, 0);
            server.socket().inject_receive(endpoint{"192.168.1.99", 5353}, their_probe);

            THEN("on_conflict is NOT called (we won)")
            {
                REQUIRE_FALSE(conflict_called);
            }
        }
    }
}

SCENARIO("Our own probe loopback is not treated as a conflict", "[service_server][probe][loopback]")
{
    GIVEN("a server currently probing")
    {
        mock_executor ex;
        bool conflict_called = false;

        service_options opts;
        opts.probe_initial_delay_max = std::chrono::milliseconds{0};
        opts.on_conflict = [&](const std::string &, std::string &, unsigned, conflict_type) -> bool
        {
            conflict_called = true;
            return true;
        };

        basic_service_server<MockPolicy> server{ex, make_test_info(), std::move(opts)};

        WHEN("async_start is called and probe fires")
        {
            server.async_start();
            server.timer().fire();

            // The server sent at least one probe -- find its transaction ID
            const auto &sent = server.socket().sent_packets();
            REQUIRE_FALSE(sent.empty());
            const auto &probe_pkt = sent.back().data;
            REQUIRE(probe_pkt.size() >= 2);
            uint16_t our_id = read_u16_be(probe_pkt, 0);

            // Build a probe with our OWN transaction ID (loopback simulation)
            auto loopback_probe = build_probe_query(make_test_info());
            loopback_probe[0] = probe_pkt[0];
            loopback_probe[1] = probe_pkt[1];
            server.socket().inject_receive(endpoint{"192.168.1.10", 5353}, loopback_probe);

            THEN("on_conflict is NOT called (loopback filtered)")
            {
                REQUIRE_FALSE(conflict_called);
            }
            (void)our_id;
        }
    }
}
