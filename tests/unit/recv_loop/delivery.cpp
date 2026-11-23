#include "recv_loop/helpers.h"

#include "mdnspp/policy.h"

#include <cstdint>
#include <optional>

using namespace mdnspp;
using namespace mdnspp::test_support;

TEST_CASE("recv_loop hands packets of any TTL to the handler")
{
    loop_rig rig;
    for(std::optional<uint8_t> ttl : {std::optional<uint8_t>{}, std::optional<uint8_t>{0}, std::optional<uint8_t>{1},
                                      std::optional<uint8_t>{255}})
    {
        recv_metadata meta = rig.sock.default_metadata();
        meta.ttl = ttl;
        rig.sock.enqueue(make_packet(8), meta);
    }
    rig.loop.start();
    REQUIRE(rig.packets.size() == 4);
}
