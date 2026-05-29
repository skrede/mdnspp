// tests/unit/encrypt_policy_trait_test.cpp
// Compile-time and runtime tests for the policy_socket_options_t detection trait.

#include "mdnspp/policy.h"
#include "mdnspp/default/default_policy.h"
#include "mdnspp/socket_options.h"
#include "mdnspp/nic_group_options.h"

#include "mdnspp/inproc/inproc_policy.h"

#ifdef MDNSPP_ENABLE_ENCRYPT
#include "mdnspp/encrypt/encrypted_policy.h"
#include "mdnspp/encrypt/encrypt_socket_options.h"
#endif

#include <catch2/catch_test_macros.hpp>

// ---------------------------------------------------------------------------
// Mock extended socket options
// ---------------------------------------------------------------------------

struct extended_socket_options : mdnspp::socket_options
{
    int extra_field{42};
};

// ---------------------------------------------------------------------------
// Mock policy with socket_options_type
// ---------------------------------------------------------------------------

// A minimal mock policy that carries extended_socket_options.
// It reuses DefaultPolicy's socket and timer types, but specifies
// socket_options_type to activate the detection trait.
struct MockExtendedPolicy
{
    using executor_type = mdnspp::DefaultPolicy::executor_type;
    using socket_type   = mdnspp::DefaultPolicy::socket_type;
    using timer_type    = mdnspp::DefaultPolicy::timer_type;

    using socket_options_type = extended_socket_options;

    static void post(executor_type ex, mdnspp::detail::move_only_function<void()> fn)
    {
        mdnspp::DefaultPolicy::post(ex, std::move(fn));
    }
};

// ---------------------------------------------------------------------------
// Static assertions (compile-time tests)
// ---------------------------------------------------------------------------

// POLX-01: DefaultPolicy has no socket_options_type => resolves to socket_options
static_assert(std::same_as<mdnspp::policy_socket_options_t<mdnspp::DefaultPolicy>, mdnspp::socket_options>,
    "policy_socket_options_t<DefaultPolicy> must resolve to socket_options");

// POLX-02: MockExtendedPolicy defines socket_options_type derived from socket_options
static_assert(std::same_as<mdnspp::policy_socket_options_t<MockExtendedPolicy>, extended_socket_options>,
    "policy_socket_options_t<MockExtendedPolicy> must resolve to extended_socket_options");

// POLX-05: Existing policies still satisfy Policy concept
static_assert(mdnspp::Policy<mdnspp::DefaultPolicy>,
    "DefaultPolicy must satisfy Policy concept");

static_assert(mdnspp::Policy<mdnspp::InProcPolicy>,
    "InProcPolicy must satisfy Policy concept");

static_assert(mdnspp::Policy<mdnspp::InProcTestPolicy>,
    "InProcTestPolicy must satisfy Policy concept");

// POLX-02 + Policy concept: mock policy with socket_options_type passes Policy concept
static_assert(mdnspp::Policy<MockExtendedPolicy>,
    "MockExtendedPolicy with socket_options_type must still satisfy Policy concept");

#ifdef MDNSPP_ENABLE_ENCRYPT
// POLX-04: basic_nic_group_options<encrypted_policy<DefaultPolicy>> factory return type
static_assert(std::same_as<
    mdnspp::policy_socket_options_t<mdnspp::encrypted_policy<mdnspp::DefaultPolicy>>,
    mdnspp::encrypt_socket_options>,
    "policy_socket_options_t<encrypted_policy<DefaultPolicy>> must resolve to encrypt_socket_options");
#endif

// ---------------------------------------------------------------------------
// Runtime test — confirms compilation with a trivial assertion
// ---------------------------------------------------------------------------

TEST_CASE("policy_socket_options_t resolves correctly at runtime", "[policy][trait]")
{
    SECTION("DefaultPolicy resolves to socket_options")
    {
        mdnspp::policy_socket_options_t<mdnspp::DefaultPolicy> opts{};
        REQUIRE(opts.interface_address.empty());
    }

    SECTION("MockExtendedPolicy resolves to extended_socket_options with extra_field")
    {
        mdnspp::policy_socket_options_t<MockExtendedPolicy> opts{};
        REQUIRE(opts.extra_field == 42);
    }
}

#ifdef MDNSPP_ENABLE_ENCRYPT
TEST_CASE("POLX-03/04: basic_nic_group_options<encrypted_policy<DefaultPolicy>> factory returns encrypt_socket_options",
          "[policy][trait][encrypt]")
{
    using EncPolicy = mdnspp::encrypted_policy<mdnspp::DefaultPolicy>;
    mdnspp::basic_nic_group_options<EncPolicy> opts;

    opts.socket_options_factory = [](const mdnspp::network_interface &) -> mdnspp::encrypt_socket_options
    {
        mdnspp::encrypt_socket_options so;
        so.encrypt.sender_id = 99;
        return so;
    };

    mdnspp::network_interface dummy{};
    auto result = opts.socket_options_factory(dummy);

    // POLX-04: factory return type is encrypt_socket_options, not just socket_options
    static_assert(std::same_as<decltype(result), mdnspp::encrypt_socket_options>,
        "socket_options_factory must return encrypt_socket_options");

    // POLX-03: the returned options carry encrypt-specific fields
    REQUIRE(result.encrypt.sender_id == 99);
}
#endif
