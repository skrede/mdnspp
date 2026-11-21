#include "seeds.h"

#include <vector>
#include <cstddef>
#include <filesystem>

namespace mdnspp::corpus {

namespace {

void valid_a_response(const std::filesystem::path &dir)
{
    write_seed(dir, "valid_a_response",
        bytes({0x12, 0x34,  // ID
               0x84, 0x00,  // FLAGS: QR=1, AA=1
               0x00, 0x00,  // QDCOUNT = 0
               0x00, 0x01,  // ANCOUNT = 1
               0x00, 0x00,  // NSCOUNT = 0
               0x00, 0x00,  // ARCOUNT = 0
               0x00,        // root label (empty name)
               0x00, 0x01,  // TYPE = A
               0x00, 0x01,  // CLASS = IN
               0x00, 0x00, 0x00, 0x78, // TTL = 120
               0x00, 0x04,  // RDLENGTH = 4
               0x01, 0x02, 0x03, 0x04})); // 1.2.3.4
}

void valid_ptr_response(const std::filesystem::path &dir)
{
    write_seed(dir, "valid_ptr_response",
        bytes({0x00, 0x00,
               0x84, 0x00,  // QR=1, AA=1
               0x00, 0x00,
               0x00, 0x01,  // ANCOUNT = 1
               0x00, 0x00,
               0x00, 0x00,
               // "_http._tcp.local."
               0x05, '_', 'h', 't', 't', 'p', 0x04, '_', 't', 'c', 'p', 0x05, 'l', 'o', 'c', 'a', 'l', 0x00,
               0x00, 0x0C,              // TYPE = PTR
               0x00, 0x01,              // CLASS = IN
               0x00, 0x00, 0x11, 0x94,  // TTL = 4500
               0x00, 0x19,              // RDLENGTH = 25
               // "MyService._http._tcp.local."
               0x09, 'M', 'y', 'S', 'e', 'r', 'v', 'i', 'c', 'e',
               0x05, '_', 'h', 't', 't', 'p', 0x04, '_', 't', 'c', 'p', 0x05, 'l', 'o', 'c', 'a', 'l', 0x00}));
}

void malformed_headers(const std::filesystem::path &dir)
{
    // a zero header followed by 100 bytes of trailing data
    write_seed(dir, "zero_header", std::vector<std::byte>(112, std::byte{0x00}));
    // QDCOUNT = 65535 in a 12-byte packet
    write_seed(dir, "max_qdcount", bytes({0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}));
    write_seed(dir, "all_ff", std::vector<std::byte>(512, std::byte{0xFF}));
    write_seed(dir, "empty", {});
    write_seed(dir, "header_only", bytes({0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}));
}

void malformed_records(const std::filesystem::path &dir)
{
    write_seed(dir, "rdlength_overrun",
        bytes({0x00, 0x00, 0x84, 0x00, 0x00, 0x00,
               0x00, 0x01,  // ANCOUNT = 1
               0x00, 0x00, 0x00, 0x00,
               0x00,        // root name
               0x00, 0x01,  // TYPE = A
               0x00, 0x01,  // CLASS = IN
               0x00, 0x00, 0x00, 0x78,
               0x03, 0xE8,  // RDLENGTH = 1000, far past the end of the packet
               0x01, 0x02}));
    write_seed(dir, "tc_bit_set",
        bytes({0x00, 0x00,
               0x82, 0x00,  // FLAGS: QR=1, TC=1
               0x00, 0x00,
               0x00, 0x01,  // ANCOUNT = 1
               0x00, 0x00, 0x00, 0x00,
               0x05, 'h', 'e', 'l', 'l', 'o'})); // truncated answer section
}

}

void gen_walk_frame(const std::filesystem::path &root)
{
    const std::filesystem::path dir = root / "walk_frame";
    valid_a_response(dir);
    valid_ptr_response(dir);
    malformed_headers(dir);
    malformed_records(dir);
}

}
