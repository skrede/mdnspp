#include <mdnspp/querier.h>

namespace mdnspp {

class example_sink : public log_sink
{
public:
    ~example_sink() override = default;

    void log(log_level level, const std::string &string) noexcept override
    {
        std::cout << string << std::endl;
    }
};

}

int main(int, char **)
{
    mdnspp::querier d(std::make_shared<mdnspp::example_sink>());
    d.inquire(
        {
            "preferably_unique_name._mdnspp-service._udp.local.",
            MDNS_RECORDTYPE_TXT
        });
}
