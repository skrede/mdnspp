#ifndef HPP_GUARD_MDNSPP_NIC_GROUP_FAILING_SOCKET_H
#define HPP_GUARD_MDNSPP_NIC_GROUP_FAILING_SOCKET_H

#include "mdnspp/inproc/inproc_policy.h"
#include "mdnspp/inproc/inproc_socket.h"
#include "mdnspp/inproc/inproc_executor.h"
#include "mdnspp/inproc/inproc_socket_options.h"

#include "mdnspp/testing/test_clock.h"
#include "mdnspp/testing/mock_socket.h"

#include <system_error>

// An in-process socket that fails to construct while the mock socket's construction failure is injected, so the
// failure_injection guard drives a group whose peers talk over the in-process bus.
class failing_socket : public mdnspp::inproc::inproc_socket<mdnspp::testing::test_clock>
{
    using base = mdnspp::inproc::inproc_socket<mdnspp::testing::test_clock>;
    using executor = mdnspp::inproc::inproc_executor<mdnspp::testing::test_clock>;
    using options = mdnspp::inproc::inproc_socket_options;

public:
    explicit failing_socket(executor &ex)
        : failing_socket(ex, options{})
    {
    }

    failing_socket(executor &ex, std::error_code &ec)
        : failing_socket(ex, options{}, ec)
    {
    }

    failing_socket(executor &ex, const options &opts)
        : base(ex, opts)
    {
        if(mdnspp::testing::mock_socket::fail_on_construct())
            throw std::system_error(injected(), "failing_socket");
    }

    failing_socket(executor &ex, const options &opts, std::error_code &ec)
        : base(ex, opts, ec)
    {
        if(!ec && mdnspp::testing::mock_socket::fail_on_construct())
        {
            ec = injected();
            close();
        }
    }

private:
    static std::error_code injected()
    {
        return std::make_error_code(std::errc::address_not_available);
    }
};

struct failing_policy : mdnspp::inproc::inproc_policy<mdnspp::testing::test_clock>
{
    using socket_type = failing_socket;
};

#endif
