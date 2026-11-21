#include "seeds.h"

#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <filesystem>
#include <string_view>

namespace mdnspp::corpus {

namespace {

void append_header(std::vector<std::byte> &v, uint16_t qdcount, uint16_t ancount, uint16_t nscount)
{
    append_u16(v, 0x0000); // ID
    append_u16(v, 0x0000); // flags: query
    append_u16(v, qdcount);
    append_u16(v, ancount);
    append_u16(v, nscount);
    append_u16(v, 0x0000); // ARCOUNT
}

void append_question(std::vector<std::byte> &v, std::string_view name, uint16_t qtype, uint16_t qclass)
{
    append_name(v, name);
    append_u16(v, qtype);
    append_u16(v, qclass);
}

void append_record(std::vector<std::byte> &v, std::string_view owner, uint16_t type, uint16_t ttl,
                   const std::vector<std::byte> &rdata)
{
    append_name(v, owner);
    append_u16(v, type);
    append_u16(v, 0x0001); // CLASS = IN
    append_u16(v, 0x0000); // TTL, high half
    append_u16(v, ttl);
    append_u16(v, static_cast<uint16_t>(rdata.size())); // RDLENGTH
    v.insert(v.end(), rdata.begin(), rdata.end());
}

void question_seeds(const std::filesystem::path &dir)
{
    std::vector<std::byte> ptr;
    append_header(ptr, 1, 0, 0);
    append_question(ptr, "_fuzz._tcp.local.", 0x000C, 0x0001); // PTR, IN
    write_seed(dir, "ptr_question", std::move(ptr));

    std::vector<std::byte> meta;
    append_header(meta, 1, 0, 0);
    append_question(meta, "_services._dns-sd._udp.local.", 0x000C, 0x8001); // PTR, IN with the QU bit
    write_seed(dir, "meta_query", std::move(meta));
}

void record_seeds(const std::filesystem::path &dir)
{
    std::vector<std::byte> known;
    append_header(known, 1, 1, 0);
    append_question(known, "_fuzz._tcp.local.", 0x000C, 0x0001);
    std::vector<std::byte> instance;
    append_name(instance, "Fuzzer._fuzz._tcp.local.");
    append_record(known, "_fuzz._tcp.local.", 0x000C, 0x1194, instance); // PTR, TTL = 4500
    write_seed(dir, "known_answer", std::move(known));

    // an ANY probe with an SRV authority record (RFC 6762 section 8.2)
    std::vector<std::byte> probe;
    append_header(probe, 1, 0, 1);
    append_question(probe, "Fuzzer._fuzz._tcp.local.", 0x00FF, 0x0001);
    std::vector<std::byte> srv;
    append_u16(srv, 0x0000); // priority
    append_u16(srv, 0x0000); // weight
    append_u16(srv, 8080);   // port
    append_name(srv, "fuzzhost.local.");
    append_record(probe, "Fuzzer._fuzz._tcp.local.", 0x0021, 0x0078, srv); // SRV, TTL = 120
    write_seed(dir, "probe_authority", std::move(probe));
}

}

// The names match the fixed service_info of the server query harnesses, so their match paths are reached from the
// first iteration.
void gen_server_query(const std::filesystem::path &root)
{
    const std::filesystem::path dir = root / "server_query";
    question_seeds(dir);
    record_seeds(dir);
    write_seed(dir, "empty", {});
}

void gen_roundtrip(const std::filesystem::path &root)
{
    const std::filesystem::path dir = root / "roundtrip";
    write_seed(dir, "simple_fqdn", text("hello.local."));
    write_seed(dir, "multipart", text("_http._tcp.local."));
    write_seed(dir, "single_label", text("host."));
    write_seed(dir, "empty", {});
}

}
