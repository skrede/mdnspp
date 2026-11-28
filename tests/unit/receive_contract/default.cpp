#include "receive_contract/harness_default.h"

#include <tuple>

using mdnspp::test_support::harness;

using receive_contract_harnesses = std::tuple<harness<mdnspp::default_socket>>;

// contract_cases.h expands its cases against the alias above
#include "receive_contract/contract_cases.h"
