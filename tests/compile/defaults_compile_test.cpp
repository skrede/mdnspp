#include <mdnspp/defaults.h>
#include <mdnspp/service_info.h>
#include <mdnspp/default/default_policy.h>
#include <mdnspp/socket_options.h>

#include <chrono>
#include <type_traits>

static_assert(std::is_class_v<mdnspp::observer>,
              "mdnspp::observer must be a class type (alias for basic_observer<default_policy>)");
static_assert(std::is_class_v<mdnspp::querier>,
              "mdnspp::querier must be a class type (alias for basic_querier<default_policy>)");
static_assert(std::is_class_v<mdnspp::service_discovery>,
              "mdnspp::service_discovery must be a class type (alias for basic_service_discovery<default_policy>)");
static_assert(std::is_class_v<mdnspp::service_server>,
              "mdnspp::service_server must be a class type (alias for basic_service_server<default_policy>)");
static_assert(std::is_class_v<mdnspp::context>,
              "mdnspp::context must be a class type (alias for default_context)");
static_assert(std::is_class_v<mdnspp::service_monitor>,
              "mdnspp::service_monitor must be a class type (alias for basic_service_monitor<default_policy>)");

static_assert(std::is_constructible_v<mdnspp::observer, mdnspp::default_context &>,
              "observer must remain constructible without options");
static_assert(std::is_constructible_v<mdnspp::querier, mdnspp::default_context &>,
              "querier must remain constructible without options");
static_assert(std::is_constructible_v<mdnspp::service_discovery, mdnspp::default_context &>,
              "service_discovery must remain constructible without options");
static_assert(std::is_constructible_v<mdnspp::service_server, mdnspp::default_context &, mdnspp::service_info>,
              "service_server must remain constructible without socket_options");

static_assert(std::is_constructible_v<mdnspp::observer, mdnspp::default_context &, mdnspp::observer_options>,
              "observer must be constructible with observer_options");
static_assert(std::is_constructible_v<mdnspp::observer, mdnspp::default_context &, mdnspp::observer_options, mdnspp::socket_options>,
              "observer must be constructible with observer_options + socket_options");
static_assert(std::is_constructible_v<mdnspp::querier, mdnspp::default_context &, mdnspp::query_options>,
              "querier must be constructible with query_options");
static_assert(std::is_constructible_v<mdnspp::querier, mdnspp::default_context &, mdnspp::query_options, mdnspp::socket_options>,
              "querier must be constructible with query_options + socket_options");
static_assert(std::is_constructible_v<mdnspp::service_discovery, mdnspp::default_context &, mdnspp::query_options>,
              "service_discovery must be constructible with query_options");
static_assert(std::is_constructible_v<mdnspp::service_discovery, mdnspp::default_context &, mdnspp::query_options, mdnspp::socket_options>,
              "service_discovery must be constructible with query_options + socket_options");
static_assert(std::is_constructible_v<mdnspp::service_server, mdnspp::default_context &, mdnspp::service_info, mdnspp::service_options, mdnspp::socket_options>,
              "service_server must be constructible with socket_options");

int main()
{
    return 0;
}
