#ifndef AOS_AUTONOMOS_UNITTEST_STATE_H
#define AOS_AUTONOMOS_UNITTEST_STATE_H

#include "AutonomOS/Core/State/state.h"

namespace AOS {

static Uuid s_test_uuid;
static std::string s_local_app_name = "LocalAutonomOS";
static std::string s_external_app_name = "ExternalAutonomOS";

inline void initializeTestState(bool noexcepts = true)
{
    State::setLogger(std::make_shared<spdlog::logger>("AutonomOS"));
    State::setNoexcepts(noexcepts);
    State::setApplicationId(s_test_uuid);
    State::setApplicationName(s_local_app_name);
}

}

#endif
