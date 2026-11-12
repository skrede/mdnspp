#include "helpers.h"

TEST_CASE_METHOD(loopback_socket, "default_context dispatches data on registered loopback socket",
                 "[native][context][socket]")
{
    bool handler_called = false;
    std::string received_data;
    mdnspp::endpoint received_ep;

    ctx.register_socket(fd);
    ctx.arm_receive(fd, [&](std::error_code, const mdnspp::recv_metadata &meta, std::span<std::byte> data)
    {
        handler_called = true;
        received_data.assign(reinterpret_cast<const char *>(data.data()), data.size());
        received_ep = meta.sender;
    });

    REQUIRE(send_to_self("hello"));
    poll_until([&] { return handler_called; });

    REQUIRE(handler_called);
    REQUIRE(received_data == "hello");
    REQUIRE(received_ep.address == "127.0.0.1");
    REQUIRE(received_ep.port != 0);
    ctx.deregister_socket(fd);
}

TEST_CASE_METHOD(loopback_socket, "default_context deregister_socket stops dispatch", "[native][context][socket]")
{
    int32_t call_count = 0;
    ctx.register_socket(fd);
    ctx.arm_receive(fd, [&](std::error_code, const mdnspp::recv_metadata &, std::span<std::byte>)
    {
        ++call_count;
    });

    ctx.deregister_socket(fd);
    send_to_self("nope");

    ctx.poll_one();
    std::this_thread::sleep_for(5ms);
    ctx.poll_one();

    REQUIRE(call_count == 0);
}

TEST_CASE_METHOD(loopback_socket, "default_context arming twice replaces the handler",
                 "[native][context][socket]")
{
    int32_t first_count = 0;
    int32_t second_count = 0;

    ctx.register_socket(fd);
    ctx.arm_receive(fd, [&](std::error_code, const mdnspp::recv_metadata &, std::span<std::byte>) { ++first_count; });
    ctx.arm_receive(fd, [&](std::error_code, const mdnspp::recv_metadata &, std::span<std::byte>) { ++second_count; });

    send_to_self("test");
    poll_until([&] { return second_count != 0; });

    REQUIRE(first_count == 0);
    REQUIRE(second_count == 1);
    ctx.deregister_socket(fd);
}

TEST_CASE("default_context deregister_socket for unregistered fd is a no-op", "[native][context]")
{
    mdnspp::default_context ctx;

    REQUIRE_NOTHROW(ctx.deregister_socket(42));
    REQUIRE_NOTHROW(ctx.deregister_socket(mdnspp::detail::invalid_socket));
}
