#include <mdnspp/basic_querier.h>
#include <mdnspp/defaults.h>
#include <mdnspp/dns.h>
#include <mdnspp/endpoint.h>
#include <mdnspp/resolved_service.h>
#include <mdnspp/testing/mock_policy.h>

#include <type_traits>
#include <iostream>
#include <chrono>

// Validate ERG-02/BUILD-02: the type aliases in defaults.h name valid class types
// without requiring template arguments.
static_assert(std::is_class_v<mdnspp::querier>);
static_assert(std::is_class_v<mdnspp::observer>);
static_assert(std::is_class_v<mdnspp::service_discovery>);
static_assert(std::is_class_v<mdnspp::service_server>);
static_assert(std::is_class_v<mdnspp::context>);

int main()
{
    // Prove the installed headers compile and the template instantiates correctly.
    // No network calls — this is a compile-and-link verification.

    // Instantiate basic_querier<MockPolicy> to prove the template compiles against installed headers.
    mdnspp::basic_querier<mdnspp::testing::MockPolicy> q{
        mdnspp::testing::mock_executor{},
        std::chrono::milliseconds{300}
    };

    // Prove dns_type enum is accessible from mdnspp namespace.
    constexpr auto qtype = mdnspp::dns_type::a;
    static_assert(qtype == mdnspp::dns_type::a);

    // Prove endpoint is accessible and supports operator<=>.
    mdnspp::endpoint ep1{"192.168.1.1", 5353};
    mdnspp::endpoint ep2{"192.168.1.2", 5353};
    static_assert(std::three_way_comparable<mdnspp::endpoint>);

    // Prove resolved_service is accessible (CMAKE-04 verification).
    [[maybe_unused]] mdnspp::resolved_service svc{};

    std::cout << "mdnspp integration test PASSED\n";
    return 0;
}
