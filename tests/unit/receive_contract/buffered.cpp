#include "receive_contract/harness.h"

#include <tuple>

using mdnspp::test_support::harness;

using receive_contract_harnesses = std::tuple<harness<mdnspp::testing::mock_socket>, harness<mdnspp::inproc::inproc_socket<>>>;

// contract_cases.h expands its cases against the alias above
#include "receive_contract/contract_cases.h"
