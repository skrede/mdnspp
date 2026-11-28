#include "helpers.h"

#include "mdnspp/testing/mock_socket.h"

#include <catch2/catch_test_macros.hpp>

#include <new>
#include <span>
#include <cstddef>
#include <utility>
#include <system_error>

namespace {

using receive_handler = mdnspp::move_only_function<void(std::error_code, const mdnspp::recv_metadata &,
                                                        std::span<std::byte>)>;

class throwing_socket : public mdnspp::testing::mock_socket
{
public:
    using mdnspp::testing::mock_socket::mock_socket;

    static void throw_on_next_arm() noexcept { s_throw_next_arm = true; }

    void async_receive(receive_handler handler)
    {
        if(std::exchange(s_throw_next_arm, false))
            throw std::bad_alloc();
        mock_socket::async_receive(std::move(handler));
    }

private:
    static inline bool s_throw_next_arm{false};
};

static_assert(mdnspp::socket_like<throwing_socket>, "throwing_socket must satisfy socket_like");

using rearm_socket = mdnspp::encrypt::encrypted_socket<throwing_socket>;

receive_handler collect_into(payloads &out)
{
    return [&out](std::error_code, const mdnspp::recv_metadata &, std::span<std::byte> data)
    {
        out.emplace_back(data.begin(), data.end());
    };
}

}

TEST_CASE("a throwing inner arm does not stop the next async_receive from arming", "[encrypted_socket][rearm]")
{
    mdnspp::testing::mock_executor ex;
    test_socket sender(ex, make_test_opts(std::byte{0x42}, 1));
    rearm_socket receiver(ex, make_test_opts(std::byte{0x42}, 2));
    payloads got;

    throwing_socket::throw_on_next_arm();
    CHECK_THROWS_AS(receiver.async_receive(collect_into(got)), std::bad_alloc);
    receiver.async_receive(collect_into(got));
    REQUIRE(receiver.inner().has_pending_receive());

    receiver.inner().inject_receive(mdnspp::endpoint{"192.0.2.1", 5353}, sealed_by(sender, probe));
    CHECK(got == payloads{probe});
}
