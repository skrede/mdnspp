#include <mdnspp/basic_querier.h>
#include <mdnspp/defaults.h>
#include <mdnspp/dns.h>
#include <mdnspp/endpoint.h>
#include <mdnspp/resolved_service.h>
#include <mdnspp/default/default_policy.h>
#include <mdnspp/inproc/inproc_policy.h>
#include <mdnspp/testing/test_clock.h>

#ifdef MDNSPP_HAS_ASIO
#include <mdnspp/asio/asio_policy.h>
#endif

#ifdef MDNSPP_HAS_ENCRYPT
#include <mdnspp/encrypt/aead.h>
#endif

#include <type_traits>
#include <iostream>
#include <chrono>

// Validate that the exported compile features propagate cxx_std_20 to a
// consumer that does not set CMAKE_CXX_STANDARD itself.
#if defined(_MSVC_LANG)
static_assert(_MSVC_LANG >= 202002L, "cxx_std_20 was not propagated to the consumer");
#else
static_assert(__cplusplus >= 202002L, "cxx_std_20 was not propagated to the consumer");
#endif

// Validate ERG-02/BUILD-02: the type aliases in defaults.h name valid class types
// without requiring template arguments.
static_assert(std::is_class_v<mdnspp::querier>);
static_assert(std::is_class_v<mdnspp::observer>);
static_assert(std::is_class_v<mdnspp::service_discovery>);
static_assert(std::is_class_v<mdnspp::service_server>);
static_assert(std::is_class_v<mdnspp::service_monitor>);
static_assert(std::is_class_v<mdnspp::context>);

// Validate that basic_querier<default_policy> is instantiable (template correctness check).
static_assert(std::is_class_v<mdnspp::basic_querier<mdnspp::default_policy>>);

// Validate the installed mdnspp::testing and mdnspp::inproc components: the
// inproc policy depends on mdnspp/testing/test_clock.h, so this instantiation
// catches a dangling mdnspp::testing reference in the installed export set.
static_assert(std::is_class_v<mdnspp::testing::test_clock>);
static_assert(std::is_class_v<mdnspp::inproc::inproc_policy<mdnspp::testing::test_clock>>);
static_assert(std::is_class_v<mdnspp::basic_querier<mdnspp::inproc_test_policy>>);

#ifdef MDNSPP_HAS_ASIO
// Validate that asio_policy-based template instantiation compiles against installed headers.
static_assert(std::is_class_v<mdnspp::basic_querier<mdnspp::asio_policy>>);
#endif

int main()
{
    // Prove the installed headers compile and the template instantiates correctly.
    // No network calls -- this is a compile-and-link verification.

    // Prove dns_type enum is accessible from mdnspp namespace.
    constexpr auto qtype = mdnspp::dns_type::a;
    static_assert(qtype == mdnspp::dns_type::a);

    // Prove endpoint is accessible and supports operator<=>.
    mdnspp::endpoint ep1{"192.168.1.1", 5353};
    mdnspp::endpoint ep2{"192.168.1.2", 5353};
    static_assert(std::three_way_comparable<mdnspp::endpoint>);

    // Prove resolved_service is accessible (CMAKE-04 verification).
    [[maybe_unused]] mdnspp::resolved_service svc{};

#ifdef MDNSPP_HAS_ENCRYPT
    // Prove mdnspp::encrypt links: this resolves a symbol from the installed
    // static library, which in turn requires the libsodium dependency that the
    // package config file must have provided.
    if(!mdnspp::encrypt::init_crypto())
    {
        std::cerr << "mdnspp integration test FAILED: init_crypto" << std::endl;
        return 1;
    }
#endif

    std::cout << "mdnspp integration test PASSED" << std::endl;
    return 0;
}
