// tests/defaults_compile_test.cpp
// Compile-time validation that all four type aliases in defaults.h work without
// template arguments, and that mdnspp::context names a valid class type.
//
// This test verifies ERG-02 (observer/querier/service_discovery/service_server aliases)
// and ERG-03 (context alias) from the requirements.
// Also verifies POLY-03 (backward compat) and SOCK-01 (socket_options constructors).

#include <mdnspp/defaults.h>
#include <mdnspp/service_info.h>
#include <mdnspp/socket_options.h>
#include <mdnspp/default/default_policy.h>

#include <chrono>
#include <type_traits>

// --- Class type checks (existing) ---

static_assert(std::is_class_v<mdnspp::observer>,
              "mdnspp::observer must be a class type (alias for basic_observer<DefaultPolicy>)");
static_assert(std::is_class_v<mdnspp::querier>,
              "mdnspp::querier must be a class type (alias for basic_querier<DefaultPolicy>)");
static_assert(std::is_class_v<mdnspp::service_discovery>,
              "mdnspp::service_discovery must be a class type (alias for basic_service_discovery<DefaultPolicy>)");
static_assert(std::is_class_v<mdnspp::service_server>,
              "mdnspp::service_server must be a class type (alias for basic_service_server<DefaultPolicy>)");
static_assert(std::is_class_v<mdnspp::context>,
              "mdnspp::context must be a class type (alias for DefaultContext)");

// --- POLY-03: Existing constructors without socket_options still compile ---

static_assert(std::is_constructible_v<mdnspp::observer, mdnspp::DefaultContext &>,
              "observer must remain constructible without socket_options");
static_assert(std::is_constructible_v<mdnspp::querier, mdnspp::DefaultContext &, std::chrono::milliseconds>,
              "querier must remain constructible without socket_options");
static_assert(std::is_constructible_v<mdnspp::service_discovery, mdnspp::DefaultContext &, std::chrono::milliseconds>,
              "service_discovery must remain constructible without socket_options");
static_assert(std::is_constructible_v<mdnspp::service_server, mdnspp::DefaultContext &, mdnspp::service_info>,
              "service_server must remain constructible without socket_options");

// --- SOCK-01: New socket_options constructors exist ---

static_assert(std::is_constructible_v<mdnspp::observer, mdnspp::DefaultContext &, const mdnspp::socket_options &>,
              "observer must be constructible with socket_options");
static_assert(std::is_constructible_v<mdnspp::querier, mdnspp::DefaultContext &, const mdnspp::socket_options &, std::chrono::milliseconds>,
              "querier must be constructible with socket_options");
static_assert(std::is_constructible_v<mdnspp::service_discovery, mdnspp::DefaultContext &, const mdnspp::socket_options &, std::chrono::milliseconds>,
              "service_discovery must be constructible with socket_options");
static_assert(std::is_constructible_v<mdnspp::service_server, mdnspp::DefaultContext &, const mdnspp::socket_options &, mdnspp::service_info>,
              "service_server must be constructible with socket_options");

int main()
{
    return 0;
}
