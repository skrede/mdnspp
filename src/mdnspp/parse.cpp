#include "mdnspp/parse.h"
#include "mdnspp/detail/mdns_util.h"
#include "mdnspp/detail/dns_wire.h"

#include <cstring>

namespace mdnspp::parse {

// Extract the owner name from the buffer at meta.name_offset.
// Returns empty string if the name cannot be decoded (lenient, matching mjansson behaviour).
static std::string extract_owner_name(std::span<const std::byte> buffer, const record_metadata &meta)
{
    auto name = detail::read_dns_name(buffer, meta.name_offset);
    return name ? std::move(*name) : std::string{};
}

std::expected<mdns_record_variant, mdns_error>
a(std::span<const std::byte> buffer, const record_metadata &meta)
{
    if (buffer.size() < meta.record_offset + meta.record_length)
        return std::unexpected(mdns_error::parse_error);

    if (meta.record_length != 4)
        return std::unexpected(mdns_error::parse_error);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    std::memcpy(&addr.sin_addr.s_addr, buffer.data() + meta.record_offset, 4);

    record_a r;
    r.name           = extract_owner_name(buffer, meta);
    r.ttl            = meta.ttl;
    r.rclass         = meta.rclass;
    r.length         = static_cast<uint32_t>(meta.record_length);
    r.sender_address = meta.sender.address;
    r.address_string = mdnspp::ip_address_to_string(addr);

    return r;
}

std::expected<mdns_record_variant, mdns_error>
aaaa(std::span<const std::byte> buffer, const record_metadata &meta)
{
    if (buffer.size() < meta.record_offset + meta.record_length)
        return std::unexpected(mdns_error::parse_error);

    if (meta.record_length != 16)
        return std::unexpected(mdns_error::parse_error);

    sockaddr_in6 addr{};
    addr.sin6_family = AF_INET6;
    std::memcpy(&addr.sin6_addr, buffer.data() + meta.record_offset, 16);

    record_aaaa r;
    r.name           = extract_owner_name(buffer, meta);
    r.ttl            = meta.ttl;
    r.rclass         = meta.rclass;
    r.length         = static_cast<uint32_t>(meta.record_length);
    r.sender_address = meta.sender.address;
    r.address_string = mdnspp::ip_address_to_string(addr);

    return r;
}

std::expected<mdns_record_variant, mdns_error>
ptr(std::span<const std::byte> buffer, const record_metadata &meta)
{
    if (buffer.size() < meta.record_offset + meta.record_length)
        return std::unexpected(mdns_error::parse_error);

    auto ptr_name = detail::read_dns_name(buffer, meta.record_offset);
    if (!ptr_name) return std::unexpected(mdns_error::parse_error);

    record_ptr r;
    r.name           = extract_owner_name(buffer, meta);
    r.ttl            = meta.ttl;
    r.rclass         = meta.rclass;
    r.length         = static_cast<uint32_t>(meta.record_length);
    r.sender_address = meta.sender.address;
    r.ptr_name       = std::move(*ptr_name);

    return r;
}

std::expected<mdns_record_variant, mdns_error>
srv(std::span<const std::byte> buffer, const record_metadata &meta)
{
    if (buffer.size() < meta.record_offset + meta.record_length)
        return std::unexpected(mdns_error::parse_error);

    if (meta.record_length < 7)
        return std::unexpected(mdns_error::parse_error);

    const std::byte *rdata = buffer.data() + meta.record_offset;
    uint16_t priority = detail::read_u16_be(rdata + 0);
    uint16_t weight   = detail::read_u16_be(rdata + 2);
    uint16_t port     = detail::read_u16_be(rdata + 4);

    auto srv_name = detail::read_dns_name(buffer, meta.record_offset + 6);
    if (!srv_name) return std::unexpected(mdns_error::parse_error);

    record_srv r;
    r.name           = extract_owner_name(buffer, meta);
    r.ttl            = meta.ttl;
    r.rclass         = meta.rclass;
    r.length         = static_cast<uint32_t>(meta.record_length);
    r.sender_address = meta.sender.address;
    r.priority       = priority;
    r.weight         = weight;
    r.port           = port;
    r.srv_name       = std::move(*srv_name);

    return r;
}

std::expected<mdns_record_variant, mdns_error>
txt(std::span<const std::byte> buffer, const record_metadata &meta)
{
    if (buffer.size() < meta.record_offset + meta.record_length)
        return std::unexpected(mdns_error::parse_error);

    record_txt r;
    r.name           = extract_owner_name(buffer, meta);
    r.ttl            = meta.ttl;
    r.rclass         = meta.rclass;
    r.length         = static_cast<uint32_t>(meta.record_length);
    r.sender_address = meta.sender.address;

    size_t pos = meta.record_offset;
    const size_t end = meta.record_offset + meta.record_length;

    while (pos < end)
    {
        uint8_t entry_len = static_cast<uint8_t>(buffer[pos]);
        ++pos;

        if (pos + entry_len > end)
            break; // silently stop — matches mjansson behaviour

        // Entry starts with '=' means no key (separator at position 0): skip
        if (entry_len > 0 && static_cast<char>(static_cast<uint8_t>(buffer[pos])) == '=')
        {
            pos += entry_len;
            continue;
        }

        std::string_view entry_sv(
            reinterpret_cast<const char *>(buffer.data() + pos), entry_len);
        pos += entry_len;

        service_txt kv;
        if (auto sep = entry_sv.find('='); sep != std::string_view::npos)
        {
            kv.key   = std::string(entry_sv.substr(0, sep));
            kv.value = std::string(entry_sv.substr(sep + 1));
        }
        else
        {
            kv.key = std::string(entry_sv);
            // value remains std::nullopt
        }

        r.entries.push_back(std::move(kv));
    }

    return r;
}

std::expected<mdns_record_variant, mdns_error>
record(std::span<const std::byte> buffer, const record_metadata &meta)
{
    switch (meta.rtype)
    {
    case dns_type::a:    return a(buffer, meta);
    case dns_type::ptr:  return ptr(buffer, meta);
    case dns_type::txt:  return txt(buffer, meta);
    case dns_type::aaaa: return aaaa(buffer, meta);
    case dns_type::srv:  return srv(buffer, meta);
    default:             return std::unexpected(mdns_error::parse_error);
    }
}

} // namespace mdnspp::parse
