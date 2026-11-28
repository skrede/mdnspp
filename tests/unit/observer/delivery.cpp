#include "helpers.h"

static void check_ptr_and_sender_delivered(const observer_fixture &f, const endpoint &sender)
{
    THEN("the PTR record is delivered to the callback")
    {
        REQUIRE(f.records.size() == 1);
        REQUIRE(std::holds_alternative<record_ptr>(f.records[0]));
        const auto &ptr = std::get<record_ptr>(f.records[0]);
        REQUIRE(ptr.ptr_name.find("MyService") != dns_name::npos);
    }

    AND_THEN("the sender endpoint is delivered alongside the record")
    {
        REQUIRE(f.senders.size() == 1);
        REQUIRE(f.senders[0] == sender);
    }
}

SCENARIO("observer delivers DNS records from a single packet to the callback", "[observer][packet-delivery]")
{
    GIVEN("an observer with one PTR packet enqueued")
    {
        observer_fixture f;
        endpoint sender{"192.168.1.10", 5353};
        f.obs.socket().enqueue(make_ptr_response("_http._tcp.local.", "MyService._http._tcp.local."), sender);

        WHEN("async_observe() is called")
        {
            f.obs.async_observe();
            check_ptr_and_sender_delivered(f, sender);
        }
    }
}

SCENARIO("observer delivers records from multiple packets", "[observer][multiple-packets]")
{
    GIVEN("an observer with two packets enqueued")
    {
        observer_fixture f;
        f.obs.socket().enqueue(make_ptr_response("_http._tcp.local.", "First._http._tcp.local."));
        f.obs.socket().enqueue(make_a_response("myhost.local.", 192, 168, 0, 1));

        WHEN("async_observe() is called")
        {
            f.obs.async_observe();

            THEN("records from all packets are delivered")
            {
                REQUIRE(f.records.size() == 2);
                REQUIRE(std::holds_alternative<record_ptr>(f.records[0]));
                REQUIRE(std::holds_alternative<record_a>(f.records[1]));
            }
        }
    }
}
