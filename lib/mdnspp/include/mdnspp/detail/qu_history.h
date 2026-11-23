#ifndef HPP_GUARD_MDNSPP_DETAIL_QU_HISTORY_H
#define HPP_GUARD_MDNSPP_DETAIL_QU_HISTORY_H

#include "mdnspp/detail/dns_read.h"
#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/dns_frame.h"
#include "mdnspp/detail/server_question_section.h"

#include "mdnspp/records.h"
#include "mdnspp/dns_name.h"
#include "mdnspp/endpoint.h"

#include <span>
#include <deque>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <optional>
#include <algorithm>

namespace mdnspp::detail {

// RFC 6762 section 6: "A Multicast DNS querier MUST only accept unicast responses if they answer a recently sent
// query (e.g., sent within the last two seconds) that explicitly requested unicast responses."
template <typename Clock>
class qu_history
{
    struct sent_question
    {
        dns_name name;
        dns_type qtype;
        uint16_t qclass;
        typename Clock::time_point sent;
    };

public:
    explicit qu_history(std::chrono::milliseconds window)
        : m_window(window)
        , m_questions()
    {
    }

    void record_sent(std::span<const std::byte> packet)
    {
        if(packet.size() < dns_frame_header_size)
            return;
        const typename Clock::time_point now = Clock::now();
        prune(now);
        const uint16_t qdcount = read_frame_header(packet).qdcount;
        std::size_t offset = dns_frame_header_size;
        for(uint16_t i = 0; i < qdcount; ++i)
        {
            const std::optional<parsed_question> question = read_question(packet, offset);
            if(!question)
                return;
            if((question->qclass & qu_bit) != 0)
                remember(packet, *question, now);
        }
    }

    bool answers(std::span<const std::byte> response) const
    {
        if(response.size() < dns_frame_header_size)
            return false;
        const dns_frame_header header = read_frame_header(response);
        std::size_t offset = dns_frame_header_size;
        if(!skip_questions(response, offset, header.qdcount))
            return false;
        const typename Clock::time_point now = Clock::now();
        for(uint16_t i = 0; i < header.ancount; ++i)
        {
            const std::optional<record_metadata> record = read_record_metadata(response, offset, endpoint{});
            if(!record)
                return false;
            if(answered(response, *record, now))
                return true;
            offset = record->record_offset + record->record_length;
        }
        return false;
    }

private:
    std::chrono::milliseconds m_window;
    std::deque<sent_question> m_questions;
    static constexpr uint16_t cname_type = 5;
    static constexpr uint16_t qu_bit = 0x8000;
    static constexpr std::size_t capacity = 64;

    void remember(std::span<const std::byte> packet, const parsed_question &question, typename Clock::time_point now)
    {
        auto name = read_dns_name(packet, question.name_start);
        if(!name)
            return;
        if(m_questions.size() == capacity)
            m_questions.pop_front();
        const auto qclass = static_cast<uint16_t>(question.qclass & ~qu_bit);
        m_questions.push_back(sent_question{dns_name(std::move(*name)), question.qtype, qclass, now});
    }

    void prune(typename Clock::time_point now)
    {
        while(!m_questions.empty() && now - m_questions.front().sent > m_window)
            m_questions.pop_front();
    }

    bool answered(std::span<const std::byte> response, const record_metadata &record,
                  typename Clock::time_point now) const
    {
        auto name = read_dns_name(response, record.name_offset);
        if(!name)
            return false;
        const dns_name owner(std::move(*name));
        return std::ranges::any_of(m_questions, [&](const sent_question &question)
        {
            return now - question.sent <= m_window && matches(question, owner, record);
        });
    }

    // RFC 6762 section 6: "the record name must match the question name, the record rrtype must match the question
    // qtype unless the qtype is "ANY" (255) or the rrtype is "CNAME" (5), and the record rrclass must match the
    // question qclass unless the qclass is "ANY" (255)."
    static bool matches(const sent_question &question, const dns_name &owner, const record_metadata &record) noexcept
    {
        const auto rtype = static_cast<uint16_t>(record.rtype);
        const bool type_ok = question.qtype == dns_type::any || question.qtype == record.rtype || rtype == cname_type;
        const auto any_class = static_cast<uint16_t>(dns_class::any);
        const bool class_ok = question.qclass == any_class || question.qclass == static_cast<uint16_t>(record.rclass);
        return type_ok && class_ok && question.name == owner;
    }
};

}

#endif
