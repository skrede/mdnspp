#include "mdnspp/encrypt/defaults.h"

#include <type_traits>

static_assert(std::is_class_v<mdnspp::encrypt::encrypted_observer>,
              "encrypted_observer must be a class type");
static_assert(std::is_class_v<mdnspp::encrypt::encrypted_querier>,
              "encrypted_querier must be a class type");
static_assert(std::is_class_v<mdnspp::encrypt::encrypted_service_discovery>,
              "encrypted_service_discovery must be a class type");
static_assert(std::is_class_v<mdnspp::encrypt::encrypted_service_server>,
              "encrypted_service_server must be a class type");
static_assert(std::is_class_v<mdnspp::encrypt::encrypted_service_monitor>,
              "encrypted_service_monitor must be a class type");
static_assert(std::is_class_v<mdnspp::encrypt::encrypted_nic_monitor>,
              "encrypted_nic_monitor must be a class type");
static_assert(std::is_class_v<mdnspp::encrypt::encrypted_nic_group_options>,
              "encrypted_nic_group_options must be a class type");
static_assert(std::is_class_v<mdnspp::encrypt::encrypted_dynamic_nic_group>,
              "encrypted_dynamic_nic_group must be a class type");
static_assert(std::is_class_v<mdnspp::encrypt::encrypted_nic_group<mdnspp::basic_observer>>,
              "encrypted_nic_group must be instantiable with Peers");

int main()
{
    return 0;
}
