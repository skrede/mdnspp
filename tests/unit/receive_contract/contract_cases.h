#ifndef HPP_GUARD_MDNSPP_RECEIVE_CONTRACT_CONTRACT_CASES_H
#define HPP_GUARD_MDNSPP_RECEIVE_CONTRACT_CONTRACT_CASES_H

#include "receive_contract/harness.h"

#include <catch2/catch_template_test_macros.hpp>

using namespace mdnspp::test_support;

TEMPLATE_LIST_TEST_CASE("one arm completes at most once", "[receive_contract]", receive_contract_harnesses)
{
    TestType h;
    received_list got;
    arm_recording(h.socket(), got, after_receive::none);
    deliver(h, payload(1));
    deliver(h, payload(2));
    REQUIRE(h.ledger().completions() == 1);
    arm_recording(h.socket(), got, after_receive::none);
    h.pump();
    REQUIRE(h.ledger().completions() == 2);
    REQUIRE(got[1].bytes == payload(2));
}

TEMPLATE_LIST_TEST_CASE("a handler that re-arms receives each datagram once", "[receive_contract]", receive_contract_harnesses)
{
    TestType h;
    received_list got;
    arm_recording(h.socket(), got, after_receive::rearm);
    for(uint8_t seed = 1; seed <= 3; ++seed)
        deliver(h, payload(seed));
    REQUIRE(got.size() == 3);
    REQUIRE(h.ledger().completions() == 3);
    REQUIRE(h.ledger().arms() == 4);
}

TEMPLATE_LIST_TEST_CASE("queued datagrams arrive in injection order", "[receive_contract]", receive_contract_harnesses)
{
    TestType h;
    received_list got;
    for(uint8_t seed = 1; seed <= 3; ++seed)
        deliver(h, payload(seed));
    arm_recording(h.socket(), got, after_receive::rearm);
    h.pump();
    REQUIRE(got.size() == 3);
    for(uint8_t seed = 1; seed <= 3; ++seed)
        REQUIRE(got[seed - 1].bytes == payload(seed));
}

TEMPLATE_LIST_TEST_CASE("a completion carries the datagram and its sender", "[receive_contract]", receive_contract_harnesses)
{
    TestType h;
    received_list got;
    arm_recording(h.socket(), got, after_receive::none);
    deliver(h, payload(7));
    REQUIRE(got.size() == 1);
    REQUIRE_FALSE(got[0].ec);
    REQUIRE(got[0].bytes == payload(7));
    REQUIRE_FALSE(got[0].sender.address.empty());
}

TEMPLATE_LIST_TEST_CASE("a zero-length datagram completes once with an empty span", "[receive_contract]", receive_contract_harnesses)
{
    TestType h;
    received_list got;
    arm_recording(h.socket(), got, after_receive::none);
    deliver(h, payload(0, 0));
    REQUIRE(got.size() == 1);
    REQUIRE_FALSE(got[0].ec);
    REQUIRE(got[0].bytes.empty());
    REQUIRE(h.ledger().completions() == 1);
}

TEMPLATE_LIST_TEST_CASE("close with a pending arm prevents every completion", "[receive_contract]", receive_contract_harnesses)
{
    TestType h;
    received_list got;
    arm_recording(h.socket(), got, after_receive::none);
    h.socket().close();
    deliver(h, payload(1));
    REQUIRE(got.empty());
    REQUIRE(h.ledger().completions() == 0);
}

TEMPLATE_LIST_TEST_CASE("a receive armed after close never completes", "[receive_contract]", receive_contract_harnesses)
{
    TestType h;
    received_list got;
    h.socket().close();
    arm_recording(h.socket(), got, after_receive::none);
    deliver(h, payload(1));
    REQUIRE(got.empty());
    REQUIRE(h.ledger().completions() == 0);
}

TEMPLATE_LIST_TEST_CASE("a datagram queued before close is dropped", "[receive_contract]", receive_contract_harnesses)
{
    TestType h;
    received_list got;
    deliver(h, payload(1));
    h.socket().close();
    arm_recording(h.socket(), got, after_receive::none);
    h.pump();
    REQUIRE(got.empty());
    REQUIRE(h.ledger().completions() == 0);
}

TEMPLATE_LIST_TEST_CASE("close inside the handler stops later completions", "[receive_contract]", receive_contract_harnesses)
{
    TestType h;
    received_list got;
    for(uint8_t seed = 1; seed <= 3; ++seed)
        deliver(h, payload(seed));
    arm_recording(h.socket(), got, after_receive::close_then_rearm);
    h.pump();
    REQUIRE(got.size() == 1);
    REQUIRE(h.ledger().completions() == 1);
    REQUIRE(h.ledger().completions_after_close() == 0);
}

#endif
