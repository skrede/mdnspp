// tests/concept_conformance_test.cpp
// TEST-04: SocketPolicy concept conformance — Phase 1 (MockSocketPolicy only)
// AsioSocketPolicy conformance is Phase 2.
// This TU does NOT link against ASIO.

#include "mdnspp/socket_policy.h"
#include "mdnspp/testing/mock_socket_policy.h"

// If this static_assert fails, MockSocketPolicy does not satisfy SocketPolicy.
// Check: async_receive signature, send signature, close signature.
static_assert(
    mdnspp::SocketPolicy<mdnspp::testing::MockSocketPolicy>,
    "MockSocketPolicy must satisfy SocketPolicy — check method signatures"
);

// Minimal Catch2 test to satisfy make_test() linkage requirement.
// The real test is the static_assert above (compile-time).
#include <catch2/catch_test_macros.hpp>

TEST_CASE("MockSocketPolicy satisfies SocketPolicy concept", "[concept][conformance]")
{
    // Verify at runtime that MockSocketPolicy is instantiable
    mdnspp::testing::MockSocketPolicy mock;
    REQUIRE(mock.queue_empty());
    REQUIRE(mock.sent_packets().empty());
}
