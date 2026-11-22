#ifndef HPP_GUARD_MDNSPP_SUPPORT_FAILURE_INJECTION_H
#define HPP_GUARD_MDNSPP_SUPPORT_FAILURE_INJECTION_H

#include "mdnspp/testing/mock_socket.h"

namespace mdnspp::test_support {

class failure_injection
{
public:
    failure_injection(bool on_construct, bool on_send)
    {
        testing::mock_socket::set_fail_on_construct(on_construct);
        testing::mock_socket::set_fail_on_send(on_send);
    }

    ~failure_injection()
    {
        testing::mock_socket::set_fail_on_construct(false);
        testing::mock_socket::set_fail_on_send(false);
    }

    failure_injection(const failure_injection &) = delete;
    failure_injection &operator=(const failure_injection &) = delete;
};

}

#endif
