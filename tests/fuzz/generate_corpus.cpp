#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <string_view>
#include <vector>

namespace fs = std::filesystem;

static std::vector<std::byte> bytes(std::initializer_list<unsigned char> vals)
{
    std::vector<std::byte> out;
    out.reserve(vals.size());
    for(unsigned char v : vals)
        out.push_back(static_cast<std::byte>(v));
    return out;
}

static void write_seed(const fs::path &dir, std::string_view name, std::vector<std::byte> data)
{
    fs::create_directories(dir);
    std::ofstream f(dir / name, std::ios::binary);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    f.write(reinterpret_cast<const char *>(data.data()),
            static_cast<std::streamsize>(data.size()));
}

static void gen_read_dns_name(const fs::path &root)
{
    const fs::path dir = root / "read_dns_name";

    // simple: \x05hello\x00
    write_seed(dir, "simple",
        bytes({0x05, 'h', 'e', 'l', 'l', 'o', 0x00}));

    // two_labels: \x05hello\x05world\x00
    write_seed(dir, "two_labels",
        bytes({0x05, 'h', 'e', 'l', 'l', 'o', 0x05, 'w', 'o', 'r', 'l', 'd', 0x00}));

    // compression_ptr: "a.b." followed by pointer back to offset 0
    // \x01a\x01b\x00 then pointer \xC0\x00
    write_seed(dir, "compression_ptr",
        bytes({0x01, 'a', 0x01, 'b', 0x00, 0xC0, 0x00}));

    // self_ptr: compression pointer to self at offset 0
    write_seed(dir, "self_ptr",
        bytes({0xC0, 0x00}));

    // forward_ptr: pointer to offset past buffer
    write_seed(dir, "forward_ptr",
        bytes({0xC0, 0x10}));

    // deep_chain: 5 chained compression pointers (exceeds max_hops=4)
    // Each pointer jumps backward by 2 bytes, chain depth 5
    // Layout: offsets 0,2,4,6,8,10 — each \xC0 ptr points two bytes back
    // We build: at offset 0 \xC0\x02, at offset 2 \xC0\x04 ... but pointers must be backward
    // Use a flat buffer where each 2-byte slot is a pointer to the previous slot
    // offset 0: \xC0\x02 (forward — invalid but that's the point)
    // Instead: arrange pointers so each points strictly backward:
    // 10 bytes total: offsets 8,6,4,2,0 (each ptr goes to prev)
    // buf[0..1] = label "a" + null (root)
    // buf[2..3] = \xC0\x00  (hop 1: -> offset 0, which is a valid name "a.")
    // ... but we need to exceed 4 hops; the fuzzer input is the raw bytes fed to read_dns_name at offset 0
    // Build: buf[0] = \xC0\x02, buf[2] = \xC0\x04, buf[4] = \xC0\x06,
    //        buf[6] = \xC0\x08, buf[8] = \x00  — but ptrs must go backward!
    // So reverse: start at high offset
    // buf[0] = root \x00 — offset 0
    // buf[2] = \xC0\x00 — points to 0 (hop 1)
    // buf[4] = \xC0\x02 — points to 2 (hop 2)
    // buf[6] = \xC0\x04 — points to 4 (hop 3)
    // buf[8] = \xC0\x06 — points to 6 (hop 4)
    // buf[10] = \xC0\x08 — points to 8 (hop 5 — exceeds limit)
    // We start reading from offset 10
    // But read_dns_name starts from the given offset — write 12 bytes, test starts at offset 10
    write_seed(dir, "deep_chain",
        bytes({0x00, 0x00,          // offset 0: root label + pad
               0xC0, 0x00,          // offset 2: ptr -> 0 (hop 1)
               0xC0, 0x02,          // offset 4: ptr -> 2 (hop 2)
               0xC0, 0x04,          // offset 6: ptr -> 4 (hop 3)
               0xC0, 0x06,          // offset 8: ptr -> 6 (hop 4)
               0xC0, 0x08}));       // offset 10: ptr -> 8 (hop 5 — exceeds max_hops=4)

    // label_64: label length 0x40 (64 bytes > RFC 1035 max 63)
    // Build: \x40 followed by 64 bytes of 'x' + \x00
    {
        std::vector<std::byte> v;
        v.push_back(static_cast<std::byte>(0x40)); // label len = 64
        for(int i = 0; i < 64; ++i)
            v.push_back(static_cast<std::byte>('x'));
        v.push_back(static_cast<std::byte>(0x00));
        write_seed(dir, "label_64", std::move(v));
    }

    // name_256: many labels summing to > 255 bytes
    // Use 32 labels of 8 bytes each (32 * 9 = 288 wire bytes) = 288 label chars + dots > 255
    {
        std::vector<std::byte> v;
        for(int i = 0; i < 32; ++i)
        {
            v.push_back(static_cast<std::byte>(8));
            for(int j = 0; j < 8; ++j)
                v.push_back(static_cast<std::byte>('a'));
        }
        v.push_back(static_cast<std::byte>(0x00));
        write_seed(dir, "name_256", std::move(v));
    }

    // truncated_ptr: single \xC0 byte (ptr needs 2 bytes)
    write_seed(dir, "truncated_ptr",
        bytes({0xC0}));

    // empty: zero bytes
    write_seed(dir, "empty", {});

    // root_only: single \x00 (root label)
    write_seed(dir, "root_only",
        bytes({0x00}));
}

static void gen_encode_dns_name(const fs::path &root)
{
    const fs::path dir = root / "encode_dns_name";

    {
        std::string s = "hello.local.";
        std::vector<std::byte> v;
        v.reserve(s.size());
        for(char c : s) v.push_back(static_cast<std::byte>(c));
        write_seed(dir, "simple", std::move(v));
    }

    write_seed(dir, "empty", {});

    // no_trailing_dot: "a.b"
    {
        std::string s = "a.b";
        std::vector<std::byte> v;
        for(char c : s) v.push_back(static_cast<std::byte>(c));
        write_seed(dir, "no_trailing_dot", std::move(v));
    }

    // long_label: 64 'a' chars + ".local." (64-char label exceeds 63-byte limit)
    {
        std::string s(64, 'a');
        s += ".local.";
        std::vector<std::byte> v;
        for(char c : s) v.push_back(static_cast<std::byte>(c));
        write_seed(dir, "long_label", std::move(v));
    }

    // max_length: 254-char name at boundary
    {
        // 50 labels of 4 chars each = 254 chars with dots: "aaaa.aaaa. ... aaaa."
        std::string s;
        for(int i = 0; i < 50; ++i)
        {
            s += "aaaa";
            s += '.';
        }
        s.resize(254); // trim to 254
        std::vector<std::byte> v;
        for(char c : s) v.push_back(static_cast<std::byte>(c));
        write_seed(dir, "max_length", std::move(v));
    }

    // dots_only: "..."
    {
        std::string s = "...";
        std::vector<std::byte> v;
        for(char c : s) v.push_back(static_cast<std::byte>(c));
        write_seed(dir, "dots_only", std::move(v));
    }
}

static void gen_dns_name(const fs::path &root)
{
    const fs::path dir = root / "dns_name";

    auto str_to_bytes = [](std::string_view s) {
        std::vector<std::byte> v;
        v.reserve(s.size());
        for(char c : s) v.push_back(static_cast<std::byte>(c));
        return v;
    };

    write_seed(dir, "service_type", str_to_bytes("_http._tcp.local."));
    write_seed(dir, "uppercase",    str_to_bytes("HELLO.LOCAL."));
    write_seed(dir, "empty",        {});
    write_seed(dir, "no_trailing_dot", str_to_bytes("a.b"));

    // huge: 1000 random characters (deterministic — use repeating pattern)
    {
        std::vector<std::byte> v;
        v.reserve(1000);
        for(int i = 0; i < 1000; ++i)
            v.push_back(static_cast<std::byte>('a' + (i % 26)));
        write_seed(dir, "huge", std::move(v));
    }
}

// Build a minimal record_metadata-like seed:
// The fuzz harnesses for parse::* use FuzzedDataProvider to split input into
// (a) a raw buffer and (b) field values extracted by consuming bytes.
// These seeds are crafted as raw byte inputs that represent plausible
// combinations of metadata bytes + payload.

static void gen_parse_a(const fs::path &root)
{
    const fs::path dir = root / "parse_a";

    // valid_4: 4-byte payload (IPv4 address 192.168.1.1) preceded by a plausible buffer prefix
    write_seed(dir, "valid_4",
        bytes({192, 168, 1, 1}));

    // short_3: 3 bytes (too short for A record)
    write_seed(dir, "short_3",
        bytes({0x01, 0x02, 0x03}));

    // long_5: 5 bytes (wrong length for A record)
    write_seed(dir, "long_5",
        bytes({0x01, 0x02, 0x03, 0x04, 0x05}));

    // empty
    write_seed(dir, "empty", {});
}

static void gen_parse_aaaa(const fs::path &root)
{
    const fs::path dir = root / "parse_aaaa";

    // valid_16: 16-byte IPv6 address (::1)
    write_seed(dir, "valid_16",
        bytes({0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1}));

    // short_15
    write_seed(dir, "short_15",
        bytes({0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0}));

    // long_17
    write_seed(dir, "long_17",
        bytes({0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1, 0}));

    // empty
    write_seed(dir, "empty", {});
}

static void gen_parse_ptr(const fs::path &root)
{
    const fs::path dir = root / "parse_ptr";

    // valid_ptr: encoded name "_http._tcp.local."
    write_seed(dir, "valid_ptr",
        bytes({0x05, '_', 'h', 't', 't', 'p',
               0x04, '_', 't', 'c', 'p',
               0x05, 'l', 'o', 'c', 'a', 'l',
               0x00}));

    // truncated_name: PTR with truncated compressed name
    write_seed(dir, "truncated_name",
        bytes({0x05, 'h', 'e', 'l', 'l'})); // label says 5 bytes but only 4 follow

    // empty
    write_seed(dir, "empty", {});
}

static void gen_parse_srv(const fs::path &root)
{
    const fs::path dir = root / "parse_srv";

    // valid_srv: 6-byte header (priority=0, weight=0, port=80) + encoded hostname "host.local."
    write_seed(dir, "valid_srv",
        bytes({0x00, 0x00,  // priority
               0x00, 0x00,  // weight
               0x00, 0x50,  // port = 80
               0x04, 'h', 'o', 's', 't',
               0x05, 'l', 'o', 'c', 'a', 'l',
               0x00}));

    // no_name: exactly 6 bytes (priority+weight+port, no name field)
    write_seed(dir, "no_name",
        bytes({0x00, 0x01, 0x00, 0x00, 0x1F, 0x40}));

    // empty
    write_seed(dir, "empty", {});
}

static void gen_parse_txt(const fs::path &root)
{
    const fs::path dir = root / "parse_txt";

    // valid_txt: \x05hello\x05world
    write_seed(dir, "valid_txt",
        bytes({0x05, 'h', 'e', 'l', 'l', 'o',
               0x05, 'w', 'o', 'r', 'l', 'd'}));

    // overrun: entry_len=255 with 10 bytes remaining
    {
        std::vector<std::byte> v;
        v.push_back(static_cast<std::byte>(0xFF)); // entry_len = 255
        for(int i = 0; i < 10; ++i)
            v.push_back(static_cast<std::byte>(i));
        write_seed(dir, "overrun", std::move(v));
    }

    // empty
    write_seed(dir, "empty", {});
}

static void gen_walk_frame(const fs::path &root)
{
    const fs::path dir = root / "walk_frame";

    // valid_a_response: 12-byte header (QR=1 AA=1 ANCOUNT=1) + root name + A record rdata
    // Header: ID=0x1234, FLAGS=0x8400 (QR=1, AA=1), QDCOUNT=0, ANCOUNT=1, NSCOUNT=0, ARCOUNT=0
    // Answer: name=\x00 (root), TYPE=A(1), CLASS=IN(1), TTL=120, RDLENGTH=4, RDATA=1.2.3.4
    write_seed(dir, "valid_a_response",
        bytes({// header
               0x12, 0x34,  // ID
               0x84, 0x00,  // FLAGS: QR=1, AA=1
               0x00, 0x00,  // QDCOUNT = 0
               0x00, 0x01,  // ANCOUNT = 1
               0x00, 0x00,  // NSCOUNT = 0
               0x00, 0x00,  // ARCOUNT = 0
               // answer: name
               0x00,        // root label (empty name)
               // TYPE=A, CLASS=IN, TTL, RDLENGTH
               0x00, 0x01,  // TYPE = A
               0x00, 0x01,  // CLASS = IN
               0x00, 0x00, 0x00, 0x78, // TTL = 120
               0x00, 0x04,  // RDLENGTH = 4
               0x01, 0x02, 0x03, 0x04})); // 1.2.3.4

    // valid_ptr_response: header + PTR record for "_http._tcp.local."
    write_seed(dir, "valid_ptr_response",
        bytes({// header
               0x00, 0x00,
               0x84, 0x00,  // QR=1, AA=1
               0x00, 0x00,
               0x00, 0x01,  // ANCOUNT = 1
               0x00, 0x00,
               0x00, 0x00,
               // name: "_http._tcp.local."
               0x05, '_', 'h', 't', 't', 'p',
               0x04, '_', 't', 'c', 'p',
               0x05, 'l', 'o', 'c', 'a', 'l',
               0x00,
               // TYPE=PTR(12), CLASS=IN, TTL, RDLENGTH
               0x00, 0x0C,
               0x00, 0x01,
               0x00, 0x00, 0x11, 0x94,  // TTL = 4500
               0x00, 0x19,              // RDLENGTH = 25
               // RDATA: "MyService._http._tcp.local."
               0x09, 'M', 'y', 'S', 'e', 'r', 'v', 'i', 'c', 'e',
               0x05, '_', 'h', 't', 't', 'p',
               0x04, '_', 't', 'c', 'p',
               0x05, 'l', 'o', 'c', 'a', 'l',
               0x00}));

    // zero_header: 12 bytes all zeros + 100 bytes trailing data
    {
        std::vector<std::byte> v(112, std::byte{0x00});
        write_seed(dir, "zero_header", std::move(v));
    }

    // max_qdcount: header with QDCOUNT=0xFFFF and only 12 bytes total
    write_seed(dir, "max_qdcount",
        bytes({0x00, 0x00,
               0x00, 0x00,
               0xFF, 0xFF,  // QDCOUNT = 65535
               0x00, 0x00,
               0x00, 0x00,
               0x00, 0x00}));

    // rdlength_overrun: record with rdlength=1000 in a tiny packet
    write_seed(dir, "rdlength_overrun",
        bytes({0x00, 0x00,
               0x84, 0x00,
               0x00, 0x00,
               0x00, 0x01,  // ANCOUNT = 1
               0x00, 0x00,
               0x00, 0x00,
               0x00,        // root name
               0x00, 0x01,  // TYPE = A
               0x00, 0x01,  // CLASS = IN
               0x00, 0x00, 0x00, 0x78,
               0x03, 0xE8,  // RDLENGTH = 1000 (way past end of packet)
               0x01, 0x02}));  // only 2 bytes of rdata present

    // all_ff: 512 bytes of 0xFF
    {
        std::vector<std::byte> v(512, std::byte{0xFF});
        write_seed(dir, "all_ff", std::move(v));
    }

    // tc_bit_set: header with TC=1, partial content
    write_seed(dir, "tc_bit_set",
        bytes({0x00, 0x00,
               0x82, 0x00,  // FLAGS: QR=1, TC=1
               0x00, 0x00,
               0x00, 0x01,  // ANCOUNT = 1
               0x00, 0x00,
               0x00, 0x00,
               0x05, 'h', 'e', 'l', 'l', 'o'})); // truncated answer section

    // empty
    write_seed(dir, "empty", {});

    // header_only: exactly 12 bytes, all valid, zero counts
    write_seed(dir, "header_only",
        bytes({0x00, 0x00,
               0x84, 0x00,
               0x00, 0x00,
               0x00, 0x00,
               0x00, 0x00,
               0x00, 0x00}));
}

static void gen_roundtrip(const fs::path &root)
{
    const fs::path dir = root / "roundtrip";

    auto str_to_bytes = [](std::string_view s) {
        std::vector<std::byte> v;
        v.reserve(s.size());
        for(char c : s) v.push_back(static_cast<std::byte>(c));
        return v;
    };

    write_seed(dir, "simple_fqdn",    str_to_bytes("hello.local."));
    write_seed(dir, "multipart",      str_to_bytes("_http._tcp.local."));
    write_seed(dir, "single_label",   str_to_bytes("host."));
    write_seed(dir, "empty",          {});
}

int main(int argc, char *argv[])
{
    const fs::path root = (argc > 1) ? argv[1] : "fuzz_corpus";

    gen_read_dns_name(root);
    gen_encode_dns_name(root);
    gen_dns_name(root);
    gen_parse_a(root);
    gen_parse_aaaa(root);
    gen_parse_ptr(root);
    gen_parse_srv(root);
    gen_parse_txt(root);
    gen_walk_frame(root);
    gen_roundtrip(root);

    return 0;
}
