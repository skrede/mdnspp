// tests/defaults_compile_test.cpp
// Compile-time validation that all four type aliases in defaults.h work without
// template arguments, and that mdnspp::context names a valid class type.
//
// This test verifies ERG-02 (observer/querier/service_discovery/service_server aliases)
// and ERG-03 (context alias) from the requirements.

#include <mdnspp/defaults.h>
#include <mdnspp/default/default_policy.h>

#include <type_traits>

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

int main()
{
    return 0;
}
