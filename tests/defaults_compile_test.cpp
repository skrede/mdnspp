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
static_assert(std::is_class_v<mdnspp::service_monitor>,
              "mdnspp::service_monitor must be a class type (alias for basic_service_monitor<DefaultPolicy>)");

// --- POLY-03: Existing constructors without socket_options still compile ---

static_assert(std::is_constructible_v<mdnspp::observer, mdnspp::DefaultContext &>,
              "observer must remain constructible without options");
static_assert(std::is_constructible_v<mdnspp::querier, mdnspp::DefaultContext &>,
              "querier must remain constructible without options");
static_assert(std::is_constructible_v<mdnspp::service_discovery, mdnspp::DefaultContext &>,
              "service_discovery must remain constructible without options");
static_assert(std::is_constructible_v<mdnspp::service_server, mdnspp::DefaultContext &, mdnspp::service_info>,
              "service_server must remain constructible without socket_options");

// --- SOCK-01: New options struct constructors exist ---

static_assert(std::is_constructible_v<mdnspp::observer, mdnspp::DefaultContext &, mdnspp::observer_options>,
              "observer must be constructible with observer_options");
static_assert(std::is_constructible_v<mdnspp::observer, mdnspp::DefaultContext &, mdnspp::observer_options, mdnspp::socket_options>,
              "observer must be constructible with observer_options + socket_options");
static_assert(std::is_constructible_v<mdnspp::querier, mdnspp::DefaultContext &, mdnspp::query_options>,
              "querier must be constructible with query_options");
static_assert(std::is_constructible_v<mdnspp::querier, mdnspp::DefaultContext &, mdnspp::query_options, mdnspp::socket_options>,
              "querier must be constructible with query_options + socket_options");
static_assert(std::is_constructible_v<mdnspp::service_discovery, mdnspp::DefaultContext &, mdnspp::query_options>,
              "service_discovery must be constructible with query_options");
static_assert(std::is_constructible_v<mdnspp::service_discovery, mdnspp::DefaultContext &, mdnspp::query_options, mdnspp::socket_options>,
              "service_discovery must be constructible with query_options + socket_options");
static_assert(std::is_constructible_v<mdnspp::service_server, mdnspp::DefaultContext &, mdnspp::service_info, mdnspp::service_options, mdnspp::socket_options>,
              "service_server must be constructible with socket_options");

int main()
{
    return 0;
}
