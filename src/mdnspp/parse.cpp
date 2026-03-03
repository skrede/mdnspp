#include "mdnspp/parse.h"
#include "mdnspp/mdns_util.h"
#include <mdns.h>

namespace mdnspp::parse {

std::expected<mdns_record_variant, mdns_error>
a(std::span<const std::byte> buffer, const record_metadata &meta)
{
    if (buffer.size() < meta.record_offset + meta.record_length)
        return std::unexpected(mdns_error::parse_error);

    if (meta.record_length != 4)
        return std::unexpected(mdns_error::parse_error);

    const void *raw = static_cast<const void *>(buffer.data());

    // Extract owner name
    char name_buf[256];
    size_t name_offset_copy = meta.name_offset;
    mdns_string_t name_str = mdns_string_extract(
        raw, buffer.size(), &name_offset_copy, name_buf, sizeof(name_buf));

    sockaddr_in addr{};
    mdns_record_parse_a(raw, buffer.size(),
                        meta.record_offset, meta.record_length, &addr);

    record_a r;
    r.name           = std::string(name_str.str, name_str.length);
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

    const void *raw = static_cast<const void *>(buffer.data());

    // Extract owner name
    char name_buf[256];
    size_t name_offset_copy = meta.name_offset;
    mdns_string_t name_str = mdns_string_extract(
        raw, buffer.size(), &name_offset_copy, name_buf, sizeof(name_buf));

    sockaddr_in6 addr{};
    mdns_record_parse_aaaa(raw, buffer.size(),
                           meta.record_offset, meta.record_length, &addr);

    record_aaaa r;
    r.name           = std::string(name_str.str, name_str.length);
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

    const void *raw = static_cast<const void *>(buffer.data());

    // Extract owner name
    char name_buf[256];
    size_t name_offset_copy = meta.name_offset;
    mdns_string_t name_str = mdns_string_extract(
        raw, buffer.size(), &name_offset_copy, name_buf, sizeof(name_buf));

    // Extract PTR target name
    char ptr_buf[256];
    mdns_string_t ptr_str = mdns_record_parse_ptr(
        raw, buffer.size(),
        meta.record_offset, meta.record_length,
        ptr_buf, sizeof(ptr_buf));

    record_ptr r;
    r.name           = std::string(name_str.str, name_str.length);
    r.ttl            = meta.ttl;
    r.rclass         = meta.rclass;
    r.length         = static_cast<uint32_t>(meta.record_length);
    r.sender_address = meta.sender.address;
    r.ptr_name       = std::string(ptr_str.str, ptr_str.length);

    return r;
}

std::expected<mdns_record_variant, mdns_error>
srv(std::span<const std::byte> buffer, const record_metadata &meta)
{
    if (buffer.size() < meta.record_offset + meta.record_length)
        return std::unexpected(mdns_error::parse_error);

    const void *raw = static_cast<const void *>(buffer.data());

    // Extract owner name
    char name_buf[256];
    size_t name_offset_copy = meta.name_offset;
    mdns_string_t name_str = mdns_string_extract(
        raw, buffer.size(), &name_offset_copy, name_buf, sizeof(name_buf));

    // Extract SRV fields
    char srv_buf[256];
    mdns_record_srv_t srv_data = mdns_record_parse_srv(
        raw, buffer.size(),
        meta.record_offset, meta.record_length,
        srv_buf, sizeof(srv_buf));

    record_srv r;
    r.name           = std::string(name_str.str, name_str.length);
    r.ttl            = meta.ttl;
    r.rclass         = meta.rclass;
    r.length         = static_cast<uint32_t>(meta.record_length);
    r.sender_address = meta.sender.address;
    r.port           = srv_data.port;
    r.weight         = srv_data.weight;
    r.priority       = srv_data.priority;
    r.srv_name       = std::string(srv_data.name.str, srv_data.name.length);

    return r;
}

std::expected<mdns_record_variant, mdns_error>
txt(std::span<const std::byte> buffer, const record_metadata &meta)
{
    if (buffer.size() < meta.record_offset + meta.record_length)
        return std::unexpected(mdns_error::parse_error);

    const void *raw = static_cast<const void *>(buffer.data());

    // Extract owner name
    char name_buf[256];
    size_t name_offset_copy = meta.name_offset;
    mdns_string_t name_str = mdns_string_extract(
        raw, buffer.size(), &name_offset_copy, name_buf, sizeof(name_buf));

    // Parse TXT entries
    mdns_record_txt_t txt_buf[128];
    size_t count = mdns_record_parse_txt(
        raw, buffer.size(),
        meta.record_offset, meta.record_length,
        txt_buf, sizeof(txt_buf) / sizeof(mdns_record_txt_t));

    record_txt r;
    r.name           = std::string(name_str.str, name_str.length);
    r.ttl            = meta.ttl;
    r.rclass         = meta.rclass;
    r.length         = static_cast<uint32_t>(meta.record_length);
    r.sender_address = meta.sender.address;

    for (size_t i = 0; i < count; ++i)
    {
        service_txt entry;
        entry.key = std::string(txt_buf[i].key.str, txt_buf[i].key.length);
        if (txt_buf[i].value.length > 0)
            entry.value = std::string(txt_buf[i].value.str, txt_buf[i].value.length);
        r.entries.push_back(std::move(entry));
    }

    return r;
}

std::expected<mdns_record_variant, mdns_error>
record(std::span<const std::byte> buffer, const record_metadata &meta)
{
    switch (meta.rtype)
    {
    case 1:   return a(buffer, meta);
    case 12:  return ptr(buffer, meta);
    case 16:  return txt(buffer, meta);
    case 28:  return aaaa(buffer, meta);
    case 33:  return srv(buffer, meta);
    default:  return std::unexpected(mdns_error::parse_error);
    }
}

} // namespace mdnspp::parse
