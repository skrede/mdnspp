#include "helpers.h"

#include "support/alloc_counter.h"

#include <catch2/catch_test_macros.hpp>

#include <span>
#include <cstddef>
#include <cstdint>
#include <system_error>

namespace {

struct null_executor
{
};

class fixed_socket
{
public:
    explicit fixed_socket(null_executor &, const mdnspp::socket_options &)
        : m_sends(0)
        , m_last_size(0)
    {
    }

    void send(const mdnspp::endpoint &, std::span<const std::byte> data)
    {
        ++m_sends;
        m_last_size = data.size();
    }

    void send(const mdnspp::endpoint &dest, std::span<const std::byte> data, std::error_code &)
    {
        send(dest, data);
    }

    void async_receive(mdnspp::move_only_function<void(std::error_code, const mdnspp::recv_metadata &,
                                                       std::span<std::byte>)>)
    {
    }

    void close()
    {
    }

    uint64_t sends() const noexcept { return m_sends; }

    std::size_t last_size() const noexcept { return m_last_size; }

private:
    uint64_t m_sends;
    std::size_t m_last_size;
};

struct measurement
{
    uint64_t allocations;
    uint64_t sends;
    std::size_t last_size;
};

measurement measure_sends(const mdnspp::encrypt::encrypt_socket_options &opts, std::size_t plaintext_size)
{
    null_executor ex;
    mdnspp::encrypt::encrypted_socket<fixed_socket> sock(ex, opts);
    const plain_bytes plaintext(plaintext_size, std::byte{0x5A});
    const mdnspp::endpoint dest{"192.0.2.1", 5353};
    sock.send(dest, plaintext);
    mdnspp::test_support::reset_allocation_count();
    for(int i = 0; i < 100; ++i)
        sock.send(dest, plaintext);
    const uint64_t count = mdnspp::test_support::allocation_count();
    return {count, sock.inner().sends(), sock.inner().last_size()};
}

}

TEST_CASE("steady-state encrypted send allocates nothing", "[encrypted_socket][alloc]")
{
    const auto got = measure_sends(make_test_opts(), 200);
    CHECK(got.sends == 101);
    CHECK(got.last_size == 200 + mdnspp::encrypt::encrypted_overhead);
    REQUIRE(got.allocations == 0);
}

TEST_CASE("steady-state authenticated-only send allocates nothing", "[encrypted_socket][alloc]")
{
    auto opts = make_test_opts();
    opts.encrypt.auth_only = true;
    const auto got = measure_sends(opts, 200);
    CHECK(got.sends == 101);
    REQUIRE(got.allocations == 0);
}
