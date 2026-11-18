#include "receive_contract/harness_default.h"
#include "receive_contract/harness_encrypted.h"

#include <tuple>

using mdnspp::test_support::harness;
using mdnspp::test_support::encrypted_over;

using receive_contract_harnesses = std::tuple<
    harness<encrypted_over<mdnspp::testing::mock_socket>>,
    harness<encrypted_over<mdnspp::inproc::inproc_socket<>>>,
    harness<encrypted_over<mdnspp::default_socket>>>;

// contract_cases.h expands its cases against the alias above
#include "receive_contract/contract_cases.h"
