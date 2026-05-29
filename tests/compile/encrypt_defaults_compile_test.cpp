#include "mdnspp/encrypt/defaults.h"

#include <type_traits>

static_assert(std::is_class_v<mdnspp::encrypted_observer>,
              "BLDP-04: encrypted_observer must be a class type");
static_assert(std::is_class_v<mdnspp::encrypted_querier>,
              "BLDP-04: encrypted_querier must be a class type");
static_assert(std::is_class_v<mdnspp::encrypted_service_discovery>,
              "BLDP-04: encrypted_service_discovery must be a class type");
static_assert(std::is_class_v<mdnspp::encrypted_service_server>,
              "BLDP-04: encrypted_service_server must be a class type");
static_assert(std::is_class_v<mdnspp::encrypted_service_monitor>,
              "BLDP-04: encrypted_service_monitor must be a class type");
static_assert(std::is_class_v<mdnspp::encrypted_nic_monitor>,
              "BLDP-04: encrypted_nic_monitor must be a class type");
static_assert(std::is_class_v<mdnspp::encrypted_nic_group_options>,
              "BLDP-04: encrypted_nic_group_options must be a class type");
static_assert(std::is_class_v<mdnspp::encrypted_dynamic_nic_group>,
              "BLDP-04: encrypted_dynamic_nic_group must be a class type");
static_assert(std::is_class_v<mdnspp::encrypted_nic_group<mdnspp::basic_observer>>,
              "BLDP-04: encrypted_nic_group must be instantiable with Peers");

int main()
{
    return 0;
}
