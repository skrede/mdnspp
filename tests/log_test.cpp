#include "mdnspp/log.h"

#include <catch2/catch_test_macros.hpp>

std::string test_output;

void set_output(const std::string &str)
{
    test_output = str;
}

mdnspp::ErrorStream<set_output> test_log()
{
    return{};
}

TEST_CASE("message log")
{
    test_log() << "This is a message";
    CHECK(test_output == "This is a message");
}