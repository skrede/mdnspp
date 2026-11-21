#include <mdnspp/dns.h>
#include <mdnspp/defaults.h>
#include <mdnspp/endpoint.h>
#include <mdnspp/basic_querier.h>
#include <mdnspp/resolved_service.h>

#include <mdnspp/default/default_policy.h>

#include <mdnspp/inproc/inproc_policy.h>

#include <mdnspp/testing/test_clock.h>

#ifdef MDNSPP_HAS_ASIO
#include <mdnspp/asio/asio_policy.h>
#endif

#ifdef MDNSPP_HAS_ENCRYPT
#include <mdnspp/encrypt/aead.h>
#endif

#include <span>
#include <array>
#include <chrono>
#include <cstddef>
#include <iostream>
#include <algorithm>
#include <type_traits>
#include <system_error>

// Validate that the exported compile features propagate cxx_std_20 to a
// consumer that does not set CMAKE_CXX_STANDARD itself.
#if defined(_MSVC_LANG)
static_assert(_MSVC_LANG >= 202002L, "cxx_std_20 was not propagated to the consumer");
#else
static_assert(__cplusplus >= 202002L, "cxx_std_20 was not propagated to the consumer");
#endif

// Validate that the type aliases in defaults.h name valid class types
// without requiring template arguments.
static_assert(std::is_class_v<mdnspp::querier>);
static_assert(std::is_class_v<mdnspp::observer>);
static_assert(std::is_class_v<mdnspp::service_discovery>);
static_assert(std::is_class_v<mdnspp::service_server>);
static_assert(std::is_class_v<mdnspp::service_monitor>);
static_assert(std::is_class_v<mdnspp::context>);

// Validate that basic_querier<default_policy> is instantiable (template correctness check).
static_assert(std::is_class_v<mdnspp::basic_querier<mdnspp::default_policy>>);

// Validate the installed mdnspp::testing and mdnspp::inproc components: the
// inproc policy depends on mdnspp/testing/test_clock.h, so this instantiation
// catches a dangling mdnspp::testing reference in the installed export set.
static_assert(std::is_class_v<mdnspp::testing::test_clock>);
static_assert(std::is_class_v<mdnspp::inproc::inproc_policy<mdnspp::testing::test_clock>>);
static_assert(std::is_class_v<mdnspp::basic_querier<mdnspp::inproc_test_policy>>);

#ifdef MDNSPP_HAS_ASIO
// Validate that asio_policy-based template instantiation compiles against installed headers.
static_assert(std::is_class_v<mdnspp::basic_querier<mdnspp::asio_policy>>);
#endif

#ifdef MDNSPP_HAS_ENCRYPT
namespace {

using mdnspp::encrypt::encrypted_overhead;

constexpr std::array<std::byte, 32> consumer_key()
{
    std::array<std::byte, 32> key{};
    for(std::size_t i = 0; i < key.size(); ++i)
        key[i] = static_cast<std::byte>(i + 1);
    return key;
}

constexpr std::array<std::byte, 5> consumer_payload{
    std::byte{'m'}, std::byte{'d'}, std::byte{'n'}, std::byte{'s'}, std::byte{'!'}};

std::size_t seal(std::array<std::byte, 128> &packet)
{
    mdnspp::encrypt::encrypted_packet_header hdr;
    hdr.sender_id = 7;
    hdr.sequence = 1;
    std::size_t written = 0;
    const std::error_code ec = mdnspp::encrypt::aead_encrypt(
        consumer_key(), hdr, consumer_payload, packet, written);
    return ec ? 0 : written;
}

bool round_trip_matches(std::span<const std::byte> packet)
{
    std::array<std::byte, 128> plain{};
    std::size_t written = 0;
    const std::error_code ec = mdnspp::encrypt::aead_decrypt(consumer_key(), packet, plain, written);
    return !ec && written == consumer_payload.size()
        && std::equal(consumer_payload.begin(), consumer_payload.end(), plain.begin());
}

bool forged_packet_rejected(std::span<const std::byte> packet)
{
    std::array<std::byte, 128> forged{};
    std::copy(packet.begin(), packet.end(), forged.begin());
    forged[packet.size() - 1] ^= std::byte{0x01};
    std::array<std::byte, 128> plain{};
    std::size_t written = 1;
    const std::error_code ec = mdnspp::encrypt::aead_decrypt(
        consumer_key(), std::span<const std::byte>(forged.data(), packet.size()), plain, written);
    return ec && written == 0;
}

// The compiled library is built at C++20 and the consumer may be C++23, so only a
// runtime round trip and a forged-packet rejection prove the boundary types agree;
// init_crypto also resolves a libsodium-dependent symbol from the installed archive.
bool encrypt_boundary_holds()
{
    if(!mdnspp::encrypt::init_crypto())
        return false;
    std::array<std::byte, 128> packet{};
    const std::size_t size = seal(packet);
    if(size != consumer_payload.size() + encrypted_overhead)
        return false;
    const std::span<const std::byte> wire(packet.data(), size);
    return round_trip_matches(wire) && forged_packet_rejected(wire);
}

}
#endif

// Proves the installed headers compile and the templates instantiate correctly.
// No network calls -- this is a compile-and-link verification.
void prove_header_surface()
{
    constexpr auto qtype = mdnspp::dns_type::a;
    static_assert(qtype == mdnspp::dns_type::a);

    mdnspp::endpoint ep1{"192.168.1.1", 5353};
    mdnspp::endpoint ep2{"192.168.1.2", 5353};
    static_assert(std::three_way_comparable<mdnspp::endpoint>);

    [[maybe_unused]] mdnspp::resolved_service svc{};
}

int main()
{
    prove_header_surface();

#ifdef MDNSPP_HAS_ENCRYPT
    if(!encrypt_boundary_holds())
    {
        std::cerr << "mdnspp integration test FAILED: encrypt boundary" << std::endl;
        return 1;
    }
#endif

    std::cout << "mdnspp integration test PASSED" << std::endl;
    return 0;
}
