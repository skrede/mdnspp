#include "fixture.h"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

TEST_CASE("nic_group started after a server went live finds it by querying on every NIC", "[nic_group]")
{
    group_fixture f;
    announced_service svc{f};
    f.advance(5s);

    found_list found;
    monitor_group grp{f.executor, f.recording_grp_opts(found), one_monitor()};
    f.start_watching(grp);
    f.advance_until([&] { return found.size() >= 2; }, 10ms, 200);

    REQUIRE(sorted_interfaces(found) == std::vector<std::string>{"nic1", "nic2"});
    grp.stop();
}
