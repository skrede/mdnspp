# dns_name

A fully-qualified DNS name in canonical presentation form. Every name-carrying
field of the public types (`service_info`, the record structs, `resolved_service`,
`record_cache` lookups) is a `dns_name`.

## Header

```cpp
#include <mdnspp/dns_name.h>
```

Included transitively by `<mdnspp/records.h>` and every `basic_*` header.

## Class

```cpp
namespace mdnspp {

class dns_name
{
public:
    dns_name(std::string_view name);
    dns_name(const char *name);
    dns_name(const std::string &name);
    dns_name(std::string &&name);
    dns_name() = default;

    dns_name &operator=(std::string_view name);
    dns_name &operator=(const char *name);
    dns_name &operator=(const std::string &name);
    dns_name &operator=(std::string &&name);

    static expected<dns_name, mdns_error> parse(std::string_view name);

    operator std::string_view() const noexcept;
    const std::string &str() const noexcept;

    bool empty() const noexcept;
    std::size_t find(std::string_view sv, std::size_t pos = 0) const noexcept;
    static constexpr std::size_t npos = std::string::npos;

    static constexpr char ascii_fold(char c) noexcept;
    std::string comparison_key() const;

    bool operator==(const dns_name &other) const noexcept;
    std::weak_ordering operator<=>(const dns_name &other) const noexcept;
};

std::ostream &operator<<(std::ostream &os, const dns_name &n);

}

template <>
struct std::hash<mdnspp::dns_name>;
```

## Stored value

The stored value is the RFC 1035 §5.1 escaped presentation form with a trailing
dot and the original byte case, or empty. Within a label:

| Byte | Stored as |
|------|-----------|
| `.` | `\.` |
| `\` | `\\` |
| below `0x20`, and `0x7F` | `\DDD` (three decimal digits) |
| any other byte, including UTF-8 sequences at and above `0x80` | verbatim, original case |

Case is preserved end to end for transmission (RFC 6763 §4.1: instance names are
user-facing UTF-8), and an escaped dot inside a label (`"Dr\. Smith._http._tcp.local."`)
never collides with a label separator. The empty value is the DNS root name; the
implicit constructors also produce it for invalid input.

## Construction

The constructors and assignment operators are implicit, in the manner of
`std::filesystem::path`: a string-like value converts to `dns_name` wherever one
is expected, and is normalized on entry. Input that fails validation becomes the
empty name; use `parse()` to detect it.

`parse()` is the checked path. It returns `mdns_error::invalid_name` for:

- a dangling escape, or a `\DDD` escape without exactly three decimal digits or with a value above 255;
- an empty label (`"a..b"`);
- a label over 63 octets or a name over 255 octets in wire form (length prefixes plus
  root terminator), measured on the unescaped bytes (RFC 1035 §2.3.4).

The trailing dot of the input is optional. `""` and `"."` both denote the root name
and yield the empty `dns_name` without an error.

## Access

| Member | Description |
|--------|-------------|
| `operator std::string_view` | Non-explicit view of the canonical value; a `dns_name` is accepted wherever `std::string_view` is expected. |
| `str()` | The canonical value as `const std::string &`, for APIs that need a `std::string` (for example map keys without heterogeneous lookup). |
| `empty()` | `true` for the root name and for normalized invalid input. |
| `find()`, `npos` | Substring search over the canonical value, as `std::string::find`. |
| `operator<<` | Writes the canonical value. |

## Comparison and hashing

`operator==`, `operator<=>` and `std::hash<dns_name>` are case-insensitive over
ASCII `'A'`-`'Z'` only (RFC 6762 §16); bytes at and above `0x80` are never folded.
Because both operands hold the canonical escaped form, the byte-wise folded
comparison is a label-aware name comparison. `operator<=>` returns
`std::weak_ordering`: names that differ only in ASCII case compare equivalent, yet
`str()` and `operator<<` tell them apart, so equivalent names are not substitutable
and the ordering is not strong. The hash is FNV-1a over the folded
bytes, so names that compare equal hash equal.

| Member | Description |
|--------|-------------|
| `ascii_fold(c)` | Maps `'A'`-`'Z'` to `'a'`-`'z'` and returns every other byte unchanged. |
| `comparison_key()` | The canonical value with ASCII letters lowercased: the normalization to use where a `std::string` key must match `dns_name` equality. |

## Example

```cpp
mdnspp::dns_name a = "MyApp._http._tcp.local";
mdnspp::dns_name b = "myapp._HTTP._tcp.local.";
// a == b; a.str() == "MyApp._http._tcp.local."

auto checked = mdnspp::dns_name::parse("bad..name");
// !checked.has_value(); checked.error() == mdnspp::mdns_error::invalid_name
```

## See Also

- [service_info](service_info.md) &mdash; `make()` builds escaped instance names from unescaped labels
- [records](records.md) &mdash; the record structs carrying `dns_name` fields
- [Errors](errors.md) &mdash; `mdns_error::invalid_name`
