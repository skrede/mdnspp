#include "helpers.h"

#include "mdnspp/service_info.h"

#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/server_answer_plan.h"
#include "mdnspp/detail/server_query_match.h"

#include <catch2/catch_test_macros.hpp>

#include <vector>

namespace {

answer_plan plan_one(owned_name target, dns_type qtype, const service_info &info)
{
    std::vector<question_match> qs{{target, qtype}};
    return plan_answers(qs, info);
}

void service_type_sections(const service_info &info)
{
    SECTION("service_type PTR plans only the PTR record")
    {
        auto plan = plan_one(owned_name::service_type, dns_type::ptr, info);
        CHECK(plan.ptr);
        CHECK_FALSE(plan.srv);
        CHECK_FALSE(plan.has_nsec());
    }

    SECTION("SRV at the service type plans an NSEC, not the instance SRV (RFC 6762 section 6.1)")
    {
        auto plan = plan_one(owned_name::service_type, dns_type::srv, info);
        CHECK_FALSE(plan.srv);
        CHECK_FALSE(plan.ptr);
        CHECK(plan.nsec_service_type);
    }
}

void instance_sections(const service_info &info)
{
    SECTION("instance SRV plans the SRV record")
    {
        auto plan = plan_one(owned_name::service_name, dns_type::srv, info);
        CHECK(plan.srv);
        CHECK_FALSE(plan.ptr);
    }

    SECTION("instance ANY plans SRV and TXT")
    {
        auto plan = plan_one(owned_name::service_name, dns_type::any, info);
        CHECK(plan.srv);
        CHECK(plan.txt);
        CHECK_FALSE(plan.ptr);
    }

    SECTION("PTR at the instance name plans an NSEC for the instance")
    {
        auto plan = plan_one(owned_name::service_name, dns_type::ptr, info);
        CHECK_FALSE(plan.ptr);
        CHECK(plan.nsec_service_name);
    }
}

void hostname_sections(const service_info &info)
{
    SECTION("hostname A plans the A record when an address exists")
    {
        auto plan = plan_one(owned_name::hostname, dns_type::a, info);
        CHECK(plan.a);
        CHECK_FALSE(plan.has_nsec());
    }

    SECTION("hostname AAAA plans an NSEC when no IPv6 address exists")
    {
        auto plan = plan_one(owned_name::hostname, dns_type::aaaa, info);
        CHECK_FALSE(plan.aaaa);
        CHECK(plan.nsec_hostname);
    }
}

}

TEST_CASE("plan_answers pairs each question with its own name and qtype", "[answer_plan]")
{
    auto info = make_subtype_test_info();
    service_type_sections(info);
    instance_sections(info);
    hostname_sections(info);

    SECTION("multiple questions do not degrade to a full dump")
    {
        std::vector<question_match> qs{
            {owned_name::service_type, dns_type::ptr},
            {owned_name::service_name, dns_type::srv},
        };
        auto plan = plan_answers(qs, info);
        CHECK(plan.ptr);
        CHECK(plan.srv);
        CHECK_FALSE(plan.txt);
        CHECK_FALSE(plan.a);
    }
}
