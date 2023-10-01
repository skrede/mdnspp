#ifndef AOS_UNIT_TEST_RESOURCES_H
#define AOS_UNIT_TEST_RESOURCES_H

#define XMACRO_STRIFY(a) MACRO_STRIFY(a)
#define MACRO_STRIFY(a) #a

#include <string>

inline std::string resourceDir()
{
    return std::string(XMACRO_STRIFY(UNIT_TEST_RESOURCE_DIR))+"/";
}

#endif
