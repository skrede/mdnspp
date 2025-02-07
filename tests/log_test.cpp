#include "mdnspp/log.h"

#include <catch2/catch_test_macros.hpp>

#include <memory>

std::string test_output;

void set_output(const std::string &str)
{
    test_output = str;
}

TEST_CASE("message log")
{
    {
        mdnspp::logger<mdnspp::log_level::info> logger(std::make_shared<mdnspp::log_sink_f<set_output>>());
        logger << "This is a message";
    }
    CHECK(test_output == std::format("[{}] This is a message", log_level_string(mdnspp::log_level::info)));
}