#include "mdnspp/policy.h"
#include "mdnspp/socket_options.h"
#include "mdnspp/nic_group_options.h"

#include "mdnspp/default/default_policy.h"

#include "mdnspp/inproc/inproc_policy.h"

#ifdef MDNSPP_ENABLE_ENCRYPT
#include "mdnspp/encrypt/encrypted_policy.h"
#include "mdnspp/encrypt/encrypt_socket_options.h"
#endif

#include <catch2/catch_test_macros.hpp>

struct extended_socket_options : mdnspp::socket_options
{
    int extra_field{42};
};

struct MockExtendedPolicy
{
    using executor_type = mdnspp::default_policy::executor_type;
    using socket_type   = mdnspp::default_policy::socket_type;
    using timer_type    = mdnspp::default_policy::timer_type;

    using socket_options_type = extended_socket_options;

    static void post(executor_type ex, mdnspp::detail::move_only_function<void()> fn)
    {
        mdnspp::default_policy::post(ex, std::move(fn));
    }
};

static_assert(std::same_as<mdnspp::policy_socket_options_t<mdnspp::default_policy>, mdnspp::socket_options>,
    "policy_socket_options_t<default_policy> must resolve to socket_options");

static_assert(std::same_as<mdnspp::policy_socket_options_t<MockExtendedPolicy>, extended_socket_options>,
    "policy_socket_options_t<MockExtendedPolicy> must resolve to extended_socket_options");

static_assert(mdnspp::policy_like<mdnspp::default_policy>,
    "default_policy must satisfy policy_like concept");

static_assert(mdnspp::policy_like<mdnspp::inproc_policy>,
    "inproc_policy must satisfy policy_like concept");

static_assert(mdnspp::policy_like<mdnspp::inproc_test_policy>,
    "inproc_test_policy must satisfy policy_like concept");

static_assert(mdnspp::policy_like<MockExtendedPolicy>,
    "MockExtendedPolicy with socket_options_type must still satisfy policy_like concept");

#ifdef MDNSPP_ENABLE_ENCRYPT
static_assert(std::same_as<
    mdnspp::policy_socket_options_t<mdnspp::encrypt::encrypted_policy<mdnspp::default_policy>>,
    mdnspp::encrypt::encrypt_socket_options>,
    "policy_socket_options_t<encrypted_policy<default_policy>> must resolve to encrypt_socket_options");
#endif

TEST_CASE("policy_socket_options_t resolves correctly at runtime", "[policy][trait]")
{
    SECTION("default_policy resolves to socket_options")
    {
        mdnspp::policy_socket_options_t<mdnspp::default_policy> opts{};
        REQUIRE(opts.interface_address.empty());
    }

    SECTION("MockExtendedPolicy resolves to extended_socket_options with extra_field")
    {
        mdnspp::policy_socket_options_t<MockExtendedPolicy> opts{};
        REQUIRE(opts.extra_field == 42);
    }
}

#ifdef MDNSPP_ENABLE_ENCRYPT
TEST_CASE("basic_nic_group_options<encrypted_policy<default_policy>> factory returns encrypt_socket_options",
          "[policy][trait][encrypt]")
{
    using EncPolicy = mdnspp::encrypt::encrypted_policy<mdnspp::default_policy>;
    mdnspp::basic_nic_group_options<EncPolicy> opts;

    opts.socket_options_factory = [](const mdnspp::network_interface &) -> mdnspp::encrypt::encrypt_socket_options
    {
        mdnspp::encrypt::encrypt_socket_options so;
        so.encrypt.sender_id = 99;
        return so;
    };

    mdnspp::network_interface dummy{};
    auto result = opts.socket_options_factory(dummy);

    static_assert(std::same_as<decltype(result), mdnspp::encrypt::encrypt_socket_options>,
        "socket_options_factory must return encrypt_socket_options");

    REQUIRE(result.encrypt.sender_id == 99);
}
#endif
