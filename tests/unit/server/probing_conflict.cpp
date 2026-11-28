#include "probing_fixture.h"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <cstdint>
#include <utility>
#include <optional>
#include <string_view>

namespace {

void give_up_sections(server_fixture &f)
{
    THEN("on_ready fires with probe_conflict")
    {
        check_failed_with(f.ready, mdns_error::probe_conflict);
    }

    AND_THEN("the full teardown runs and on_done fires with success")
    {
        check_succeeded(f.done);
    }

    AND_THEN("a later stop() does not fire on_done a second time")
    {
        REQUIRE_NOTHROW(f.server.stop());
        f.ex.drain_posted();
        REQUIRE(f.done.fired);
    }
}

void respond_from_peer(server_fixture &f, const service_info &info)
{
    auto response = build_dns_response(info, dns_type::srv, service_options{});
    f.inject(endpoint{"192.168.1.99", 5353}, response);
}

void post_probe_sections(server_fixture &f, const conflict_log &log)
{
    WHEN("a response claims our service name with a DIFFERENT port")
    {
        // Different rdata under the same unique name.
        respond_from_peer(f, test_info_on_port(9999));

        THEN("on_conflict fires and the server re-enters probing")
        {
            REQUIRE(log.called);
            // The probe initial-delay timer is armed again.
            REQUIRE(f.server.timer().has_pending());
        }
    }

    WHEN("a response carries our records with IDENTICAL rdata (RFC 6762 section 7.4 duplicate)")
    {
        respond_from_peer(f, make_test_info());

        THEN("no conflict is raised")
        {
            REQUIRE_FALSE(log.called);
        }
    }
}

void renamed_update_sections(server_fixture &f)
{
    WHEN("update_service_info changes the service name")
    {
        auto renamed = make_test_info();
        renamed.service_name = "Renamed._http._tcp.local.";
        f.update(std::move(renamed));

        THEN("no immediate announcement is sent (probing first, RFC 6762 section 8.1)")
        {
            REQUIRE(f.sent().empty());

            AND_WHEN("the probe sequence completes")
            {
                advance_to_live(f.server);

                THEN("probes for the new name were sent before announcements")
                {
                    REQUIRE_FALSE(f.sent().empty());
                    REQUIRE(flags_of(f.sent().front()) == 0x0000);
                    REQUIRE(flags_of(f.sent().back()) == 0x8400);
                }
            }
        }
    }
}

}

SCENARIO("conflict detected from incoming response during probing", "[service_server][conflict]")
{
    GIVEN("a service_server with on_ready but no on_conflict callback, and a conflict response enqueued")
    {
        server_fixture f;
        f.enqueue(make_conflict_response(make_test_info()));

        WHEN("async_start is called")
        {
            f.start(record_into(f.ready));

            THEN("on_ready fires with probe_conflict error")
            {
                check_failed_with(f.ready, mdns_error::probe_conflict);
            }
        }
    }
}

SCENARIO("conflict callback can rename and retry probing", "[service_server][conflict][retry]")
{
    GIVEN("a service_server with on_conflict that renames")
    {
        conflict_log log;
        server_fixture f{make_test_info(), on_conflict_into(log, "Renamed._http._tcp.local.")};
        f.enqueue(make_conflict_response(make_test_info()));

        WHEN("async_start is called and conflict is detected")
        {
            f.start(record_into(f.ready));

            THEN("on_conflict was called with attempt=0")
            {
                REQUIRE(log.called);
                REQUIRE(log.attempt == 0);
            }

            AND_THEN("server restarts probing and eventually reaches live state")
            {
                advance_to_live(f.server);
                check_succeeded(f.ready);
            }
        }
    }
}

SCENARIO("conflict callback returning nullopt tears the server down", "[service_server][conflict][give-up]")
{
    GIVEN("a service_server with on_conflict returning nullopt")
    {
        service_options opts;
        opts.on_conflict = [](std::string_view, uint32_t, conflict_type) -> std::optional<std::string>
        {
            return std::nullopt;
        };
        server_fixture f{make_test_info(), std::move(opts)};
        f.enqueue(make_conflict_response(make_test_info()));

        WHEN("async_start is called and conflict fires")
        {
            f.start_recording();
            give_up_sections(f);
        }
    }
}

SCENARIO("Post-probe conflict detection: a response asserting our name with different rdata re-probes",
         "[service_server][conflict][post-probe][rfc6762-9]")
{
    GIVEN("a live server with on_conflict that renames")
    {
        conflict_log log;
        server_fixture f{make_test_info(), on_conflict_into(log, "Renamed._http._tcp.local.")};
        f.go_live();
        post_probe_sections(f, log);
    }
}

SCENARIO("update_service_info with a changed name re-probes instead of announce-only",
         "[service_server][update][re-probe]")
{
    GIVEN("a live server")
    {
        server_fixture f;
        f.go_live();
        f.clear_sent();
        renamed_update_sections(f);

        WHEN("update_service_info keeps the names and changes only the port")
        {
            f.update(test_info_on_port(9090));

            THEN("an announcement is sent immediately (no re-probe)")
            {
                REQUIRE_FALSE(f.sent().empty());
                REQUIRE(flags_of(f.sent().back()) == 0x8400);
            }
        }
    }
}
