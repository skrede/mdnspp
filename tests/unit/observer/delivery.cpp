#include "helpers.h"

SCENARIO("observer delivers DNS records from a single packet to the callback", "[observer][packet-delivery]")
{
    GIVEN("an observer with one PTR packet enqueued")
    {
        mock_executor ex;
        endpoint sender{"192.168.1.10", 5353};

        std::vector<mdns_record_variant> received_records;
        std::vector<endpoint> received_senders;

        basic_observer<mock_policy> obs{
            ex,
            observer_options{.on_record = [&](const endpoint &ep, const mdns_record_variant &rec)
            {
                received_records.push_back(rec);
                received_senders.push_back(ep);
            }}
        };

        obs.socket().enqueue(
            make_ptr_response("_http._tcp.local.", "MyService._http._tcp.local."), sender);

        WHEN("async_observe() is called")
        {
            obs.async_observe();

            THEN("the PTR record is delivered to the callback")
            {
                REQUIRE(received_records.size() == 1);
                REQUIRE(std::holds_alternative<record_ptr>(received_records[0]));
                const auto &ptr = std::get<record_ptr>(received_records[0]);
                REQUIRE(ptr.ptr_name.find("MyService") != dns_name::npos);
            }

            AND_THEN("the sender endpoint is delivered alongside the record")
            {
                REQUIRE(received_senders.size() == 1);
                REQUIRE(received_senders[0] == sender);
            }
        }
    }
}

SCENARIO("observer delivers records from multiple packets", "[observer][multiple-packets]")
{
    GIVEN("an observer with two packets enqueued")
    {
        mock_executor ex;

        std::vector<mdns_record_variant> received_records;

        basic_observer<mock_policy> obs{
            ex,
            observer_options{.on_record = [&](const endpoint &, const mdns_record_variant &rec)
            {
                received_records.push_back(rec);
            }}
        };

        obs.socket().enqueue(make_ptr_response("_http._tcp.local.", "First._http._tcp.local."));
        obs.socket().enqueue(make_a_response("myhost.local.", 192, 168, 0, 1));

        WHEN("async_observe() is called")
        {
            obs.async_observe();

            THEN("records from all packets are delivered")
            {
                REQUIRE(received_records.size() == 2);
                REQUIRE(std::holds_alternative<record_ptr>(received_records[0]));
                REQUIRE(std::holds_alternative<record_a>(received_records[1]));
            }
        }
    }
}
