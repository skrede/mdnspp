#include "receive_contract/harness_asio.h"

#include <tuple>

using mdnspp::test_support::harness;

using receive_contract_harnesses = std::tuple<harness<mdnspp::asio_socket>>;

// contract_cases.h expands its cases against the alias above
#include "receive_contract/contract_cases.h"
